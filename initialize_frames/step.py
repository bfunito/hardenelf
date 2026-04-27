"""Pipeline step that zeroes stack frames at function entry."""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from stat import S_IMODE
from typing import ClassVar

import lief

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
class InitializeFramesStepOptions:
    """Configuration for the stack-frame initialization step."""

    trampoline_size: int = 0x4000


@dataclass(frozen=True)
class InitializeFramesStep:
    """Pipeline step that zeroes conventional x86-64 stack frames."""

    options: InitializeFramesStepOptions = field(
        default_factory=InitializeFramesStepOptions
    )

    name: ClassVar[str] = INITIALIZE_FRAMES_STEP
    description: ClassVar[str] = (
        "Zero stack-frame storage after each function's frame setup."
    )

    def run(
        self,
        input_path: Path | str,
        output_path: Path | str,
    ) -> FrameInitializationResult:
        return initialize_stack_frames(
            input_path,
            output_path,
            trampoline_size=self.options.trampoline_size,
        )


def initialize_stack_frames(
    input_path: Path | str,
    output_path: Path | str,
    *,
    trampoline_size: int = 0x4000,
) -> FrameInitializationResult:
    """Patch canonical frame-pointer functions to zero their local stack area."""

    _validate_size("trampoline_size", trampoline_size)
    input_file = Path(input_path)
    output_file = Path(output_path)

    binary = lief.parse(input_file)
    if binary is None:
        raise ValueError(f"LIEF could not parse {input_file}")
    if not isinstance(binary, lief.ELF.Binary):
        raise ValueError(f"{input_file} is not an ELF binary")
    ensure_x86_64(binary)
    _ensure_section_absent(binary, INIT_FRAMES_SECTION)

    disassembler = make_disassembler()
    assembler = make_assembler()
    sites, skipped = _collect_sites(binary, disassembler)

    if not sites:
        _copy_if_needed(input_file, output_file)
        return FrameInitializationResult(
            output_path=output_file,
            initialized_frames=(),
            skipped=tuple(skipped),
            section_name=INIT_FRAMES_SECTION,
            section_address=None,
            section_size=0,
        )

    section = _make_section(
        name=INIT_FRAMES_SECTION,
        size=trampoline_size,
        flags=lief.ELF.Section.FLAGS.ALLOC | lief.ELF.Section.FLAGS.EXECINSTR,
        fill=0x90,
    )
    binary.add(section, loaded=True)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    binary.write(output_file)
    output_file.chmod(S_IMODE(input_file.stat().st_mode))

    binary = _parse_output(output_file)
    ensure_x86_64(binary)
    section = _require_section(binary, INIT_FRAMES_SECTION)
    sites, skipped = _collect_sites(binary, disassembler)

    initialized_frames: list[InitializedFrame] = []
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
            if next_cursor > end:
                skipped.append(
                    SkippedFrame(
                        site.function.name,
                        site.function.address,
                        f"not enough room left in {INIT_FRAMES_SECTION}",
                    )
                )
                continue

            binary.patch_address(cursor, list(body))
            binary.patch_address(site.patch_address, list(make_patch_jump(site, cursor)))
            initialized_frames.append(_initialized_frame_summary(site, cursor))
            cursor = next_cursor
        except SkipFunction as exc:
            skipped.append(
                SkippedFrame(site.function.name, site.function.address, str(exc))
            )

    if not initialized_frames:
        raise ValueError("no stack-frame initializer trampolines were written")

    binary.write(output_file)
    rewritten = _parse_output(output_file)
    section = _require_section(rewritten, INIT_FRAMES_SECTION)

    return FrameInitializationResult(
        output_path=output_file,
        initialized_frames=tuple(initialized_frames),
        skipped=tuple(skipped),
        section_name=INIT_FRAMES_SECTION,
        section_address=section.virtual_address,
        section_size=section.size,
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


def _make_section(
    *,
    name: str,
    size: int,
    flags: lief.ELF.Section.FLAGS,
    fill: int,
) -> lief.ELF.Section:
    section = lief.ELF.Section(name)
    section.type = lief.ELF.Section.TYPE.PROGBITS
    section.flags = flags
    section.alignment = 0x10
    section.content = [fill] * size
    return section


def _copy_if_needed(input_file: Path, output_file: Path) -> None:
    if input_file == output_file:
        return
    output_file.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(input_file, output_file)


def _parse_output(output_file: Path) -> lief.ELF.Binary:
    rewritten = lief.parse(output_file)
    if rewritten is None or not isinstance(rewritten, lief.ELF.Binary):
        raise ValueError(f"LIEF could not parse {output_file}")
    return rewritten


def _ensure_section_absent(binary: lief.ELF.Binary, name: str) -> None:
    if binary.has_section(name):
        raise ValueError(f"{name} already exists in the input binary")


def _require_section(binary: lief.ELF.Binary, name: str) -> lief.ELF.Section:
    section = binary.get_section(name)
    if section is None:
        raise ValueError(f"{name} was not found in the rewritten binary")
    return section


def _validate_size(name: str, size: int) -> None:
    if size <= 0:
        raise ValueError(f"{name} must be greater than zero")


__all__ = [
    "INITIALIZE_FRAMES_STEP",
    "INIT_FRAMES_SECTION",
    "FrameInitializationResult",
    "InitializeFramesStep",
    "InitializeFramesStepOptions",
    "InitializedFrame",
    "SkippedFrame",
    "initialize_stack_frames",
]
