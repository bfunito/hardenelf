"""Pipeline step that zeroes stack frames at function entry."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

import lief

from binary_hardening.elf import (
    copy_if_needed,
    ensure_section_absent,
    make_section,
    parse_elf,
    require_section,
    round_up_to_page,
    validate_positive_size,
    write_elf,
)
from binary_hardening.x86 import (
    SkipFunction,
    ensure_x86_64,
    make_assembler,
    make_disassembler,
    pad_to_alignment,
)
from initialize_frames.analysis import (
    FrameInitializationSite,
    collect_initialization_site,
    iter_function_symbols,
)
from initialize_frames.trampoline import (
    build_frame_initializer_trampoline,
    make_patch_jump,
)


INITIALIZE_FRAMES_STEP = "initialize-frames"
INITIALIZE_FRAMES_DESCRIPTION = (
    "Zero stack-frame storage after each function's frame setup."
)
INIT_FRAMES_SECTION = ".init_frames"


@dataclass(frozen=True)
class InitializedFrame:
    """One function patched to zero its stack frame after setup."""

    function_name: str
    function_address: int
    patch_address: int
    trampoline_address: int
    frame_size: int
    overwritten_size: int
    original_bytes: bytes


@dataclass(frozen=True)
class SkippedFrame:
    """One function that could not be patched safely."""

    function_name: str
    function_address: int
    reason: str


@dataclass(frozen=True)
class FrameInitializationResult:
    """Summary returned after injecting stack-frame initializers."""

    output_path: Path
    initialized_frames: tuple[InitializedFrame, ...]
    skipped: tuple[SkippedFrame, ...]
    section_name: str
    section_address: int | None
    section_size: int


@dataclass(frozen=True)
class _PlannedFrameInitialization:
    site: FrameInitializationSite
    trampoline_address: int
    body: bytes
    patch_jump: bytes


@dataclass(frozen=True)
class _FrameInitializationPlan:
    patches: tuple[_PlannedFrameInitialization, ...]
    skipped: tuple[SkippedFrame, ...]
    required_trampoline_size: int


@dataclass(frozen=True)
class InitializeFramesStepOptions:
    """Configuration for the stack-frame initialization step."""

    trampoline_size: int | None = None


def initialize_stack_frames(
    input_path: Path | str,
    output_path: Path | str,
    *,
    trampoline_size: int | None = None,
) -> FrameInitializationResult:
    """Patch canonical frame-pointer functions to zero their local stack area."""

    if trampoline_size is not None:
        validate_positive_size("trampoline_size", trampoline_size)
    input_file = Path(input_path)
    output_file = Path(output_path)

    binary = parse_elf(input_file)
    ensure_x86_64(binary)
    ensure_section_absent(binary, INIT_FRAMES_SECTION)

    disassembler = make_disassembler()
    assembler = make_assembler()
    sites, skipped = _collect_sites(binary, disassembler)

    if not sites:
        copy_if_needed(input_file, output_file)
        return FrameInitializationResult(
            output_path=output_file,
            initialized_frames=(),
            skipped=tuple(skipped),
            section_name=INIT_FRAMES_SECTION,
            section_address=None,
            section_size=0,
        )

    resolved_trampoline_size = _resolve_trampoline_size(
        input_file,
        trampoline_size=trampoline_size,
        disassembler=disassembler,
        assembler=assembler,
    )
    section = make_section(
        name=INIT_FRAMES_SECTION,
        size=resolved_trampoline_size,
        flags=lief.ELF.Section.FLAGS.ALLOC | lief.ELF.Section.FLAGS.EXECINSTR,
        fill=0x90,
    )
    binary.add(section, loaded=True)

    write_elf(binary, output_file, mode_source=input_file)

    binary = parse_elf(output_file)
    ensure_x86_64(binary)
    section = require_section(binary, INIT_FRAMES_SECTION)
    sites, skipped = _collect_sites(binary, disassembler)

    plan = _build_frame_initialization_plan(
        sites,
        skipped=skipped,
        assembler=assembler,
        section=section,
        enforce_trampoline_limit=True,
    )
    initialized_frames: list[InitializedFrame] = []
    for patch in plan.patches:
        binary.patch_address(patch.trampoline_address, list(patch.body))
        binary.patch_address(patch.site.patch_address, list(patch.patch_jump))
        initialized_frames.append(
            _initialized_frame_summary(patch.site, patch.trampoline_address)
        )

    if not initialized_frames:
        raise ValueError("no stack-frame initializer trampolines were written")

    write_elf(binary, output_file, mode_source=input_file)
    rewritten = parse_elf(output_file)
    section = require_section(rewritten, INIT_FRAMES_SECTION)

    return FrameInitializationResult(
        output_path=output_file,
        initialized_frames=tuple(initialized_frames),
        skipped=plan.skipped,
        section_name=INIT_FRAMES_SECTION,
        section_address=section.virtual_address,
        section_size=section.size,
    )


def _resolve_trampoline_size(
    input_file: Path,
    *,
    trampoline_size: int | None,
    disassembler: object,
    assembler: object,
) -> int:
    if trampoline_size is not None:
        return trampoline_size

    candidate_size = round_up_to_page(0)
    seen_sizes: set[int] = set()
    with TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        for _ in range(8):
            if candidate_size in seen_sizes:
                raise ValueError("automatic .init_frames sizing did not converge")
            seen_sizes.add(candidate_size)

            output_file = tmpdir_path / f"init-frames-auto-{candidate_size:x}"
            binary = parse_elf(input_file)
            ensure_x86_64(binary)
            ensure_section_absent(binary, INIT_FRAMES_SECTION)
            section = make_section(
                name=INIT_FRAMES_SECTION,
                size=candidate_size,
                flags=lief.ELF.Section.FLAGS.ALLOC | lief.ELF.Section.FLAGS.EXECINSTR,
                fill=0x90,
            )
            binary.add(section, loaded=True)
            write_elf(binary, output_file, mode_source=input_file)

            binary = parse_elf(output_file)
            ensure_x86_64(binary)
            section = require_section(binary, INIT_FRAMES_SECTION)
            sites, skipped = _collect_sites(binary, disassembler)
            plan = _build_frame_initialization_plan(
                sites,
                skipped=skipped,
                assembler=assembler,
                section=section,
                enforce_trampoline_limit=False,
            )
            needed_size = round_up_to_page(plan.required_trampoline_size)
            if needed_size == candidate_size:
                return needed_size
            candidate_size = needed_size

    raise ValueError("automatic .init_frames sizing did not converge")


def _build_frame_initialization_plan(
    sites: list[FrameInitializationSite],
    *,
    skipped: list[SkippedFrame],
    assembler: object,
    section: lief.ELF.Section,
    enforce_trampoline_limit: bool,
) -> _FrameInitializationPlan:
    patches: list[_PlannedFrameInitialization] = []
    remaining_skips = list(skipped)
    cursor = section.virtual_address
    end = section.virtual_address + section.size

    for site in sites:
        try:
            body = build_frame_initializer_trampoline(
                assembler=assembler,
                site=site,
                trampoline_address=cursor,
            )
            body = pad_to_alignment(body)
            next_cursor = cursor + len(body)
            if enforce_trampoline_limit and next_cursor > end:
                remaining_skips.append(
                    SkippedFrame(
                        site.function.name,
                        site.function.address,
                        f"not enough room left in {INIT_FRAMES_SECTION}",
                    )
                )
                continue

            patches.append(
                _PlannedFrameInitialization(
                    site=site,
                    trampoline_address=cursor,
                    body=body,
                    patch_jump=make_patch_jump(site, cursor),
                )
            )
            cursor = next_cursor
        except SkipFunction as exc:
            remaining_skips.append(
                SkippedFrame(site.function.name, site.function.address, str(exc))
            )

    return _FrameInitializationPlan(
        patches=tuple(patches),
        skipped=tuple(remaining_skips),
        required_trampoline_size=cursor - section.virtual_address,
    )


def _collect_sites(
    binary: lief.ELF.Binary,
    disassembler: object,
) -> tuple[list[FrameInitializationSite], list[SkippedFrame]]:
    sites: list[FrameInitializationSite] = []
    skipped: list[SkippedFrame] = []

    for function in iter_function_symbols(binary):
        try:
            sites.append(collect_initialization_site(binary, disassembler, function))
        except SkipFunction as exc:
            skipped.append(SkippedFrame(function.name, function.address, str(exc)))

    return sites, skipped


def _initialized_frame_summary(
    site: FrameInitializationSite,
    trampoline_address: int,
) -> InitializedFrame:
    return InitializedFrame(
        function_name=site.function.name,
        function_address=site.function.address,
        patch_address=site.patch_address,
        trampoline_address=trampoline_address,
        frame_size=site.frame_size,
        overwritten_size=site.overwritten_size,
        original_bytes=site.original_bytes,
    )


__all__ = [
    "INITIALIZE_FRAMES_DESCRIPTION",
    "INITIALIZE_FRAMES_STEP",
    "INIT_FRAMES_SECTION",
    "FrameInitializationResult",
    "InitializeFramesStepOptions",
    "InitializedFrame",
    "SkippedFrame",
    "initialize_stack_frames",
]
