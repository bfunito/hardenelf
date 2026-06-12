"""Shadow-stack pipeline step."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import lief

from binary_hardening.elf import parse_elf, require_section
from binary_hardening.hardenelf import HARDENELF_SECTION
from binary_hardening.entry_trampoline import (
    EntryTrampoline,
    build_entry_trampoline,
    collect_entry_instructions,
    make_entry_patch,
)
from binary_hardening.exit_trampoline import (
    ReturnAddressAction,
    ReturnPatchStrategy,
    ReturnSite,
    ReturnTrampoline,
    TrapFallbackCandidate,
    build_donor_trampoline,
    build_return_trampoline,
    collect_return_sites,
)
from binary_hardening.symbols import FunctionSymbol, iter_function_symbols
from binary_hardening.x86 import (
    NEAR_JUMP_SIZE,
    SkipFunction,
    assemble,
    ensure_x86_64,
    is_pie_binary,
    load_register_with_address,
    load_r11_with_address,
    make_assembler,
    make_disassembler,
    make_jump,
    make_short_jump,
    pad_to_alignment,
    ranges_overlap,
)
from shstk_injector.expand import (
    SAVED_ADDRS_SECTION,
    AddedSection,
    ExpansionResult,
    expand_binary,
    section_summary,
)
from initialize_frames.analysis import (
    FrameInitializationSite,
    collect_initialization_site,
)
from initialize_frames.step import (
    FrameInitializationResult,
    InitializedFrame,
    SkippedFrame,
)
from initialize_frames.trampoline import build_frame_initializer_payload


SHADOW_STACK_CURSOR_SIZE = 8
SHADOW_STACK_STEP = "shadow-stack"
SHADOW_STACK_DESCRIPTION = (
    "Add the shadow-stack sections and inject entry/return trampolines."
)
HARDENELF_SIZE_PAGE = 0x1000
_TRAP_INSTRUCTION = b"\xcc"


class TrapFallbackDecision(str, Enum):
    """User policy for costly one-byte trap return trampolines."""

    ASK = "ask"
    ALLOW = "allow"
    SKIP = "skip"


@dataclass(frozen=True)
class SkippedFunction:
    """A function symbol that could not be patched safely."""

    function_name: str
    function_address: int
    reason: str


@dataclass(frozen=True)
class InjectionResult:
    """Summary returned after adding entry and return trampolines."""

    output_path: Path
    hardenelf: AddedSection
    saved_addrs: AddedSection
    trampolines: tuple[EntryTrampoline, ...]
    skipped: tuple[SkippedFunction, ...]
    return_trampolines: tuple[ReturnTrampoline, ...] = ()
    is_pie: bool = False


@dataclass(frozen=True)
class ShadowStackStepOptions:
    """Configuration for the shadow-stack pipeline step."""

    hardenelf_size: int | None = None
    saved_addrs_size: int = 0x1000
    return_address_action: ReturnAddressAction | str = ReturnAddressAction.RESTORE
    crash_message: str | bytes | None = None
    expand_only: bool = False
    trap_fallback: TrapFallbackDecision | str = TrapFallbackDecision.ASK
    trap_fallback_callback: Callable[[str, int, str], bool] | None = None


@dataclass(frozen=True)
class _ReturnBody:
    site: ReturnSite
    trampoline_address: int
    body: bytes
    donor_trampoline_address: int | None = None
    donor_body: bytes | None = None


@dataclass(frozen=True)
class _TrapEntry:
    trapped_rip: int
    trampoline_address: int


@dataclass(frozen=True)
class _PlannedFunctionPatch:
    function: FunctionSymbol
    entry_body_address: int
    entry_instructions: list[Any]
    entry_body: bytes
    entry_overwritten_size: int
    return_bodies: list[_ReturnBody]
    frame_site: FrameInitializationSite | None = None


@dataclass(frozen=True)
class _ShadowStackPlan:
    patches: tuple[_PlannedFunctionPatch, ...]
    skipped: tuple[SkippedFunction, ...]
    skipped_frames: tuple[SkippedFrame, ...]
    trap_installer_address: int | None
    trap_installer_body: bytes | None
    required_hardenelf_size: int


def inject_shadow_stack(
    input_path: Path | str,
    output_path: Path | str,
    *,
    hardenelf_size: int | None = None,
    saved_addrs_size: int = 0x1000,
    return_address_action: ReturnAddressAction | str = ReturnAddressAction.RESTORE,
    crash_message: str | bytes | None = None,
    trap_fallback: TrapFallbackDecision | str = TrapFallbackDecision.ASK,
    trap_fallback_callback: Callable[[str, int, str], bool] | None = None,
) -> InjectionResult:
    """Expand an ELF binary and patch function entries and returns."""

    action = _normalize_return_address_action(return_address_action)
    crash_message_bytes = _normalize_crash_message(action, crash_message)
    trap_decision = _normalize_trap_fallback_decision(trap_fallback)
    trap_fallback_callback = _memoize_trap_fallback_callback(trap_fallback_callback)

    disassembler = make_disassembler()
    assembler = make_assembler()

    resolved_hardenelf_size = _resolve_hardenelf_size(
        input_path,
        hardenelf_size=hardenelf_size,
        saved_addrs_size=saved_addrs_size,
        action=action,
        crash_message=crash_message_bytes,
        trap_decision=trap_decision,
        trap_fallback_callback=trap_fallback_callback,
        disassembler=disassembler,
        assembler=assembler,
    )
    expanded = expand_binary(
        input_path,
        output_path,
        hardenelf_size=resolved_hardenelf_size,
        saved_addrs_size=saved_addrs_size,
    )
    output_file = expanded.output_path

    binary = parse_elf(output_file)
    ensure_x86_64(binary)
    is_pie = is_pie_binary(binary)

    hardenelf = require_section(binary, HARDENELF_SECTION)
    saved_addrs = require_section(binary, SAVED_ADDRS_SECTION)
    if saved_addrs.size <= SHADOW_STACK_CURSOR_SIZE:
        raise ValueError(".saved_addrs must be larger than eight bytes")

    plan = _build_shadow_stack_plan(
        binary,
        disassembler=disassembler,
        assembler=assembler,
        action=action,
        crash_message=crash_message_bytes,
        trap_decision=trap_decision,
        trap_fallback_callback=trap_fallback_callback,
        enforce_hardenelf_limit=True,
    )
    trampolines: list[EntryTrampoline] = []
    return_trampolines: list[ReturnTrampoline] = []

    for patch in plan.patches:
        _patch_entry(
            binary,
            patch.function,
            patch.entry_body_address,
            patch.entry_body,
            patch.entry_instructions,
            patch.entry_overwritten_size,
            trampolines,
        )
        _patch_returns(
            binary,
            patch.function,
            patch.return_bodies,
            return_trampolines,
        )

    if not trampolines:
        raise ValueError("no complete function trampolines were written")

    if plan.trap_installer_body is not None:
        if plan.trap_installer_address is None:
            raise ValueError("trap installer address is missing")
        binary.patch_address(
            plan.trap_installer_address,
            list(plan.trap_installer_body),
        )
        binary.header.entrypoint = plan.trap_installer_address

    binary.write(output_file)
    rewritten = parse_elf(output_file)

    return InjectionResult(
        output_path=output_file,
        hardenelf=section_summary(require_section(rewritten, HARDENELF_SECTION)),
        saved_addrs=section_summary(require_section(rewritten, SAVED_ADDRS_SECTION)),
        trampolines=tuple(trampolines),
        skipped=plan.skipped,
        return_trampolines=tuple(return_trampolines),
        is_pie=is_pie,
    )


def inject_shadow_stack_and_initialize_frames(
    input_path: Path | str,
    output_path: Path | str,
    *,
    hardenelf_size: int | None = None,
    saved_addrs_size: int = 0x1000,
    return_address_action: ReturnAddressAction | str = ReturnAddressAction.RESTORE,
    crash_message: str | bytes | None = None,
    trap_fallback: TrapFallbackDecision | str = TrapFallbackDecision.ASK,
    trap_fallback_callback: Callable[[str, int, str], bool] | None = None,
) -> tuple[InjectionResult, FrameInitializationResult]:
    """Patch shadow stack and frame initialization through shared entries."""

    action = _normalize_return_address_action(return_address_action)
    crash_message_bytes = _normalize_crash_message(action, crash_message)
    trap_decision = _normalize_trap_fallback_decision(trap_fallback)
    trap_fallback_callback = _memoize_trap_fallback_callback(trap_fallback_callback)

    disassembler = make_disassembler()
    assembler = make_assembler()

    resolved_hardenelf_size = _resolve_hardenelf_size(
        input_path,
        hardenelf_size=hardenelf_size,
        saved_addrs_size=saved_addrs_size,
        action=action,
        crash_message=crash_message_bytes,
        trap_decision=trap_decision,
        trap_fallback_callback=trap_fallback_callback,
        disassembler=disassembler,
        assembler=assembler,
        include_frame_initializers=True,
    )
    expanded = expand_binary(
        input_path,
        output_path,
        hardenelf_size=resolved_hardenelf_size,
        saved_addrs_size=saved_addrs_size,
    )
    output_file = expanded.output_path

    binary = parse_elf(output_file)
    ensure_x86_64(binary)
    is_pie = is_pie_binary(binary)

    saved_addrs = require_section(binary, SAVED_ADDRS_SECTION)
    if saved_addrs.size <= SHADOW_STACK_CURSOR_SIZE:
        raise ValueError(".saved_addrs must be larger than eight bytes")

    frame_sites, skipped_frames = _collect_frame_sites(binary, disassembler)
    plan = _build_shadow_stack_plan(
        binary,
        disassembler=disassembler,
        assembler=assembler,
        action=action,
        crash_message=crash_message_bytes,
        trap_decision=trap_decision,
        trap_fallback_callback=trap_fallback_callback,
        enforce_hardenelf_limit=True,
        frame_sites=frame_sites,
        skipped_frames=tuple(skipped_frames),
    )

    trampolines: list[EntryTrampoline] = []
    initialized_frames: list[InitializedFrame] = []
    return_trampolines: list[ReturnTrampoline] = []

    for patch in plan.patches:
        _patch_entry(
            binary,
            patch.function,
            patch.entry_body_address,
            patch.entry_body,
            patch.entry_instructions,
            patch.entry_overwritten_size,
            trampolines,
        )
        if patch.frame_site is not None:
            initialized_frames.append(
                _initialized_frame_summary(
                    patch.frame_site,
                    tuple(patch.entry_instructions),
                    patch.entry_body_address,
                )
            )
        _patch_returns(
            binary,
            patch.function,
            patch.return_bodies,
            return_trampolines,
        )

    if not trampolines and not initialized_frames:
        raise ValueError("no shared hardening trampolines were written")

    if plan.trap_installer_body is not None:
        if plan.trap_installer_address is None:
            raise ValueError("trap installer address is missing")
        binary.patch_address(
            plan.trap_installer_address,
            list(plan.trap_installer_body),
        )
        binary.header.entrypoint = plan.trap_installer_address

    binary.write(output_file)
    rewritten = parse_elf(output_file)
    hardenelf = section_summary(require_section(rewritten, HARDENELF_SECTION))
    saved = section_summary(require_section(rewritten, SAVED_ADDRS_SECTION))

    shadow_result = InjectionResult(
        output_path=output_file,
        hardenelf=hardenelf,
        saved_addrs=saved,
        trampolines=tuple(trampolines),
        skipped=plan.skipped,
        return_trampolines=tuple(return_trampolines),
        is_pie=is_pie,
    )
    frame_result = FrameInitializationResult(
        output_path=output_file,
        initialized_frames=tuple(initialized_frames),
        skipped=plan.skipped_frames,
        section_name=HARDENELF_SECTION,
        section_address=hardenelf.virtual_address,
        section_size=hardenelf.size,
    )
    return shadow_result, frame_result


def run_shadow_stack_step(
    input_path: Path | str,
    output_path: Path | str,
    *,
    options: ShadowStackStepOptions | None = None,
) -> ExpansionResult | InjectionResult:
    """Run the shadow-stack pass with CLI/pipeline options."""

    selected_options = options or ShadowStackStepOptions()
    if selected_options.expand_only:
        return expand_binary(
            input_path,
            output_path,
            hardenelf_size=_manual_or_default_hardenelf_size(
                selected_options.hardenelf_size
            ),
            saved_addrs_size=selected_options.saved_addrs_size,
        )

    return inject_shadow_stack(
        input_path,
        output_path,
        hardenelf_size=selected_options.hardenelf_size,
        saved_addrs_size=selected_options.saved_addrs_size,
        return_address_action=selected_options.return_address_action,
        crash_message=selected_options.crash_message,
        trap_fallback=selected_options.trap_fallback,
        trap_fallback_callback=selected_options.trap_fallback_callback,
    )


def _resolve_hardenelf_size(
    input_path: Path | str,
    *,
    hardenelf_size: int | None,
    saved_addrs_size: int,
    action: ReturnAddressAction,
    crash_message: bytes | None,
    trap_decision: TrapFallbackDecision,
    trap_fallback_callback: Callable[[str, int, str], bool] | None,
    disassembler: Any,
    assembler: Any,
    include_frame_initializers: bool = False,
) -> int:
    if hardenelf_size is not None:
        return hardenelf_size

    candidate_size = HARDENELF_SIZE_PAGE
    seen_sizes: set[int] = set()
    with TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        for _ in range(8):
            if candidate_size in seen_sizes:
                raise ValueError("automatic .hardenelf sizing did not converge")
            seen_sizes.add(candidate_size)

            expanded_path = tmpdir_path / f"hardenelf-auto-{candidate_size:x}"
            expand_binary(
                input_path,
                expanded_path,
                hardenelf_size=candidate_size,
                saved_addrs_size=saved_addrs_size,
            )
            binary = parse_elf(expanded_path)
            ensure_x86_64(binary)

            saved_addrs = require_section(binary, SAVED_ADDRS_SECTION)
            if saved_addrs.size <= SHADOW_STACK_CURSOR_SIZE:
                raise ValueError(".saved_addrs must be larger than eight bytes")
            frame_sites: dict[int, FrameInitializationSite] | None = None
            skipped_frames: tuple[SkippedFrame, ...] = ()
            if include_frame_initializers:
                frame_sites, frame_skips = _collect_frame_sites(
                    binary,
                    disassembler,
                )
                skipped_frames = tuple(frame_skips)

            plan = _build_shadow_stack_plan(
                binary,
                disassembler=disassembler,
                assembler=assembler,
                action=action,
                crash_message=crash_message,
                trap_decision=trap_decision,
                trap_fallback_callback=trap_fallback_callback,
                enforce_hardenelf_limit=False,
                frame_sites=frame_sites,
                skipped_frames=skipped_frames,
            )
            needed_size = _round_up_to_page(plan.required_hardenelf_size)
            if needed_size == candidate_size:
                return needed_size
            candidate_size = needed_size

    raise ValueError("automatic .hardenelf sizing did not converge")


def _build_shadow_stack_plan(
    binary: lief.ELF.Binary,
    *,
    disassembler: Any,
    assembler: Any,
    action: ReturnAddressAction,
    crash_message: bytes | None,
    trap_decision: TrapFallbackDecision,
    trap_fallback_callback: Callable[[str, int, str], bool] | None,
    enforce_hardenelf_limit: bool,
    frame_sites: dict[int, FrameInitializationSite] | None = None,
    skipped_frames: tuple[SkippedFrame, ...] = (),
) -> _ShadowStackPlan:
    is_pie = is_pie_binary(binary)
    allow_absolute_saved_addrs = not is_pie
    hardenelf = require_section(binary, HARDENELF_SECTION)
    saved_addrs = require_section(binary, SAVED_ADDRS_SECTION)
    hardenelf_cursor = hardenelf.virtual_address
    hardenelf_end = hardenelf.virtual_address + hardenelf.size
    patches: list[_PlannedFunctionPatch] = []
    trap_entries: list[_TrapEntry] = []
    skipped: list[SkippedFunction] = []
    remaining_skipped_frames = list(skipped_frames)
    frame_sites_by_address = frame_sites or {}

    for function in iter_function_symbols(binary):
        frame_site = frame_sites_by_address.get(function.address)
        try:
            entry_instructions = collect_entry_instructions(
                binary,
                disassembler,
                function,
                min_size=(
                    frame_site.prologue_size
                    if frame_site is not None
                    else NEAR_JUMP_SIZE
                ),
            )
            shadow_skip: SkipFunction | None = None
            try:
                return_sites = collect_return_sites(binary, disassembler, function)
            except TrapFallbackCandidate as exc:
                if not _allow_trap_fallback(
                    trap_decision,
                    trap_fallback_callback,
                    function,
                    str(exc),
                ):
                    shadow_skip = SkipFunction(
                        _trap_fallback_skip_reason(trap_decision, str(exc))
                    )
                    return_sites = []
                else:
                    return_sites = collect_return_sites(
                        binary,
                        disassembler,
                        function,
                        allow_trap_fallback=True,
                    )
            except SkipFunction as exc:
                shadow_skip = exc
                return_sites = []

            if shadow_skip is not None:
                skipped.append(
                    SkippedFunction(function.name, function.address, str(shadow_skip))
                )
                if frame_site is None:
                    continue

            entry_overwritten_size = sum(
                instruction.size for instruction in entry_instructions
            )
            _ensure_patch_ranges_do_not_overlap(
                function.address,
                entry_overwritten_size,
                return_sites,
            )

            entry_body_address = hardenelf_cursor
            entry_body = _build_entry_body(
                assembler=assembler,
                instructions=entry_instructions,
                trampoline_address=entry_body_address,
                return_address=function.address + entry_overwritten_size,
                saved_addrs_address=saved_addrs.virtual_address,
                allow_absolute_saved_addrs=allow_absolute_saved_addrs,
                return_sites=return_sites,
                include_shadow_entry=shadow_skip is None,
                after_relocated=_frame_entry_payloads(
                    assembler,
                    frame_site,
                ),
            )
            return_bodies: list[_ReturnBody] = []
            next_hardenelf_cursor = entry_body_address + len(entry_body)

            for return_site in return_sites:
                donor_trampoline_address = None
                donor_body = None
                if return_site.donor is not None:
                    donor_trampoline_address = next_hardenelf_cursor
                    donor_body = build_donor_trampoline(
                        assembler=assembler,
                        donor=return_site.donor,
                        trampoline_address=donor_trampoline_address,
                    )
                    donor_body = pad_to_alignment(donor_body)
                    next_hardenelf_cursor += len(donor_body)

                return_body_address = next_hardenelf_cursor
                return_body = build_return_trampoline(
                    assembler=assembler,
                    return_site=return_site,
                    trampoline_address=return_body_address,
                    saved_addrs_address=saved_addrs.virtual_address,
                    action=action,
                    crash_message=crash_message,
                    allow_absolute_saved_addrs=allow_absolute_saved_addrs,
                )
                return_body = pad_to_alignment(return_body)
                next_hardenelf_cursor += len(return_body)
                return_bodies.append(
                    _ReturnBody(
                        site=return_site,
                        trampoline_address=return_body_address,
                        body=return_body,
                        donor_trampoline_address=donor_trampoline_address,
                        donor_body=donor_body,
                    )
                )

            if enforce_hardenelf_limit and next_hardenelf_cursor > hardenelf_end:
                if frame_site is not None:
                    remaining_skipped_frames.append(
                        SkippedFrame(
                            function.name,
                            function.address,
                            "not enough room left in .hardenelf",
                        )
                    )
                skipped.append(
                    SkippedFunction(
                        function.name,
                        function.address,
                        "not enough room left in .hardenelf",
                    )
                )
                continue

            patches.append(
                _PlannedFunctionPatch(
                    function=function,
                    entry_body_address=entry_body_address,
                    entry_instructions=entry_instructions,
                    entry_body=entry_body,
                    entry_overwritten_size=entry_overwritten_size,
                    return_bodies=return_bodies,
                    frame_site=frame_site,
                )
            )
            trap_entries.extend(
                _TrapEntry(
                    trapped_rip=return_body.site.patch_address + len(_TRAP_INSTRUCTION),
                    trampoline_address=return_body.trampoline_address,
                )
                for return_body in return_bodies
                if return_body.site.strategy is ReturnPatchStrategy.TRAP
            )
            hardenelf_cursor = next_hardenelf_cursor
        except SkipFunction as exc:
            if frame_site is not None:
                remaining_skipped_frames.append(
                    SkippedFrame(function.name, function.address, str(exc))
                )
            skipped.append(SkippedFunction(function.name, function.address, str(exc)))

    trap_installer_address = None
    trap_installer_body = None
    if trap_entries:
        trap_installer_address = hardenelf_cursor
        trap_installer_body = _build_trap_installer(
            assembler,
            installer_address=trap_installer_address,
            original_entrypoint=binary.entrypoint,
            trap_entries=trap_entries,
        )
        trap_installer_body = pad_to_alignment(trap_installer_body)
        hardenelf_cursor += len(trap_installer_body)
        if enforce_hardenelf_limit and hardenelf_cursor > hardenelf_end:
            raise ValueError("not enough room left in .hardenelf for SIGTRAP handler")

    return _ShadowStackPlan(
        patches=tuple(patches),
        skipped=tuple(skipped),
        skipped_frames=tuple(remaining_skipped_frames),
        trap_installer_address=trap_installer_address,
        trap_installer_body=trap_installer_body,
        required_hardenelf_size=hardenelf_cursor - hardenelf.virtual_address,
    )


def _round_up_to_page(size: int) -> int:
    size = max(size, HARDENELF_SIZE_PAGE)
    return (
        (size + HARDENELF_SIZE_PAGE - 1)
        // HARDENELF_SIZE_PAGE
    ) * HARDENELF_SIZE_PAGE


def _manual_or_default_hardenelf_size(hardenelf_size: int | None) -> int:
    return hardenelf_size if hardenelf_size is not None else HARDENELF_SIZE_PAGE


def _normalize_return_address_action(
    action: ReturnAddressAction | str,
) -> ReturnAddressAction:
    if isinstance(action, ReturnAddressAction):
        return action
    try:
        return ReturnAddressAction(action)
    except ValueError as exc:
        supported = ", ".join(item.value for item in ReturnAddressAction)
        raise ValueError(f"return address action must be one of: {supported}") from exc


def _normalize_crash_message(
    action: ReturnAddressAction,
    crash_message: str | bytes | None,
) -> bytes | None:
    if crash_message is None:
        return None
    if action is not ReturnAddressAction.COMPARE_CRASH:
        raise ValueError("crash messages are only supported with compare-crash mode")
    if isinstance(crash_message, str):
        return crash_message.encode()
    return bytes(crash_message)


def _normalize_trap_fallback_decision(
    decision: TrapFallbackDecision | str,
) -> TrapFallbackDecision:
    if isinstance(decision, TrapFallbackDecision):
        return decision
    try:
        return TrapFallbackDecision(decision)
    except ValueError as exc:
        supported = ", ".join(item.value for item in TrapFallbackDecision)
        raise ValueError(f"trap fallback must be one of: {supported}") from exc


def _memoize_trap_fallback_callback(
    callback: Callable[[str, int, str], bool] | None,
) -> Callable[[str, int, str], bool] | None:
    if callback is None:
        return None

    decisions: dict[tuple[int, str], bool] = {}

    def memoized(function_name: str, function_address: int, reason: str) -> bool:
        key = (function_address, reason)
        if key not in decisions:
            decisions[key] = bool(callback(function_name, function_address, reason))
        return decisions[key]

    return memoized


def _collect_frame_sites(
    binary: lief.ELF.Binary,
    disassembler: Any,
) -> tuple[dict[int, FrameInitializationSite], list[SkippedFrame]]:
    sites: dict[int, FrameInitializationSite] = {}
    skipped: list[SkippedFrame] = []

    for function in iter_function_symbols(binary):
        try:
            site = collect_initialization_site(binary, disassembler, function)
            sites[function.address] = site
        except SkipFunction as exc:
            skipped.append(SkippedFrame(function.name, function.address, str(exc)))

    return sites, skipped


def _initialized_frame_summary(
    site: FrameInitializationSite,
    entry_instructions: tuple[Any, ...],
    trampoline_address: int,
) -> InitializedFrame:
    return InitializedFrame(
        function_name=site.function.name,
        function_address=site.function.address,
        patch_address=site.function.address,
        trampoline_address=trampoline_address,
        frame_size=site.frame_size,
        overwritten_size=sum(instruction.size for instruction in entry_instructions),
        original_bytes=b"".join(
            bytes(instruction.bytes) for instruction in entry_instructions
        ),
    )


def _allow_trap_fallback(
    decision: TrapFallbackDecision,
    callback: Callable[[str, int, str], bool] | None,
    function: FunctionSymbol,
    reason: str,
) -> bool:
    if decision is TrapFallbackDecision.ALLOW:
        return True
    if decision is TrapFallbackDecision.SKIP:
        return False
    if callback is None:
        return False
    return bool(callback(function.name, function.address, reason))


def _trap_fallback_skip_reason(
    decision: TrapFallbackDecision,
    reason: str,
) -> str:
    if decision is TrapFallbackDecision.SKIP:
        return f"trap fallback disabled after jump strategies failed: {reason}"
    return f"trap fallback declined after jump strategies failed: {reason}"


def _ensure_patch_ranges_do_not_overlap(
    entry_address: int,
    entry_overwritten_size: int,
    return_sites: list[ReturnSite],
) -> None:
    entry_patch_range = (
        entry_address,
        entry_address + entry_overwritten_size,
    )
    for return_site in return_sites:
        for return_patch_range in return_site.patch_ranges:
            if ranges_overlap(entry_patch_range, return_patch_range):
                raise SkipFunction("entry and return patches overlap")


def _build_entry_body(
    *,
    assembler: Any,
    instructions: list[Any],
    trampoline_address: int,
    return_address: int,
    saved_addrs_address: int,
    allow_absolute_saved_addrs: bool,
    return_sites: list[ReturnSite],
    include_shadow_entry: bool = True,
    after_relocated: tuple[Callable[[int], bytes], ...] = (),
) -> bytes:
    rbx_jump_target = _rbx_jump_target(return_sites, trampoline_address)

    for _ in range(3):
        before_relocated = ()
        if include_shadow_entry:
            before_relocated = (
                lambda block_address, target=rbx_jump_target: _build_shadow_entry_block(
                    assembler=assembler,
                    block_address=block_address,
                    saved_addrs_address=saved_addrs_address,
                    allow_absolute_saved_addrs=allow_absolute_saved_addrs,
                    rbx_jump_target=target,
                ),
            )
        body = build_entry_trampoline(
            assembler=assembler,
            instructions=instructions,
            trampoline_address=trampoline_address,
            return_address=return_address,
            before_relocated=before_relocated,
            after_relocated=after_relocated,
        )
        body = pad_to_alignment(body)
        next_rbx_jump_target = _rbx_jump_target(
            return_sites,
            trampoline_address + len(body),
        )
        if next_rbx_jump_target == rbx_jump_target:
            return body
        rbx_jump_target = next_rbx_jump_target

    raise SkipFunction("could not stabilize RBX return trampoline address")


def _frame_entry_payloads(
    assembler: Any,
    frame_site: FrameInitializationSite | None,
) -> tuple[Callable[[int], bytes], ...]:
    if frame_site is None:
        return ()
    return (
        lambda block_address: build_frame_initializer_payload(
            assembler=assembler,
            site=frame_site,
            block_address=block_address,
        ),
    )


def _build_shadow_entry_block(
    *,
    assembler: Any,
    block_address: int,
    saved_addrs_address: int,
    allow_absolute_saved_addrs: bool,
    rbx_jump_target: int | None,
) -> bytes:
    register_save = assemble(
        assembler,
        """
            pushfq
            push rax
            push r10
            push r11
        """,
        block_address,
    )
    saved_addrs_load_address = block_address + len(register_save)
    saved_addrs_load = load_r11_with_address(
        assembler,
        saved_addrs_load_address,
        saved_addrs_address,
        allow_absolute=allow_absolute_saved_addrs,
    )
    tail_address = saved_addrs_load_address + len(saved_addrs_load)
    record_size = 16 if rbx_jump_target is not None else 8
    save_rbx = (
        "mov qword ptr [r10 + 8], rbx" if rbx_jump_target is not None else ""
    )
    tail = assemble(
        assembler,
        f"""
            mov r10, qword ptr [r11]
            test r10, r10
            jne cursor_ready
            lea r10, qword ptr [r11 + 8]
        cursor_ready:
            mov rax, qword ptr [rsp + 32]
            mov qword ptr [r10], rax
            {save_rbx}
            add r10, {record_size}
            mov qword ptr [r11], r10
            pop r11
            pop r10
            pop rax
            popfq
        """,
        tail_address,
    )
    block = register_save + saved_addrs_load + tail
    if rbx_jump_target is None:
        return block

    rbx_load_address = block_address + len(block)
    return block + load_register_with_address(
        assembler,
        "rbx",
        rbx_load_address,
        rbx_jump_target,
        allow_absolute=allow_absolute_saved_addrs,
    )


def _rbx_jump_target(
    return_sites: list[ReturnSite],
    first_return_trampoline_address: int,
) -> int | None:
    if any(site.strategy is ReturnPatchStrategy.RBX_JUMP for site in return_sites):
        return first_return_trampoline_address
    return None


def _patch_entry(
    binary: lief.ELF.Binary,
    function: FunctionSymbol,
    trampoline_address: int,
    body: bytes,
    instructions: list[Any],
    overwritten_size: int,
    trampolines: list[EntryTrampoline],
) -> None:
    entry_patch = make_entry_patch(
        function_address=function.address,
        trampoline_address=trampoline_address,
        overwritten_size=overwritten_size,
    )

    binary.patch_address(trampoline_address, list(body))
    binary.patch_address(function.address, list(entry_patch))

    trampolines.append(
        EntryTrampoline(
            function_name=function.name,
            function_address=function.address,
            trampoline_address=trampoline_address,
            overwritten_size=overwritten_size,
            original_bytes=b"".join(
                bytes(instruction.bytes) for instruction in instructions
            ),
        )
    )


def _patch_returns(
    binary: lief.ELF.Binary,
    function: FunctionSymbol,
    return_bodies: list[_ReturnBody],
    return_trampolines: list[ReturnTrampoline],
) -> None:
    for return_body in return_bodies:
        return_site = return_body.site
        return_trampoline_address = return_body.trampoline_address
        if return_site.strategy is ReturnPatchStrategy.RBX_JUMP:
            return_patch = b"\xff\xe3"
        elif return_site.strategy is ReturnPatchStrategy.TRAP:
            return_patch = _TRAP_INSTRUCTION
        elif return_site.strategy in (
            ReturnPatchStrategy.SHORT_CAVE,
            ReturnPatchStrategy.SHORT_DONOR,
        ):
            if return_site.bridge_address is None:
                raise SkipFunction("short return patch is missing bridge address")
            return_patch = make_short_jump(
                return_site.patch_address,
                return_site.bridge_address,
            )
        else:
            return_patch = make_jump(
                return_site.patch_address,
                return_trampoline_address,
            )
            return_patch += b"\x90" * (
                return_site.overwritten_size - NEAR_JUMP_SIZE
            )

        if return_site.strategy is ReturnPatchStrategy.SHORT_CAVE:
            if return_site.bridge_address is None:
                raise SkipFunction("short cave patch is missing bridge address")
            bridge_patch = make_jump(
                return_site.bridge_address,
                return_trampoline_address,
            )
            binary.patch_address(return_site.bridge_address, list(bridge_patch))
        elif return_site.strategy is ReturnPatchStrategy.SHORT_DONOR:
            if return_site.donor is None:
                raise SkipFunction("short donor patch is missing donor instructions")
            if return_body.donor_trampoline_address is None:
                raise SkipFunction("short donor patch is missing trampoline address")
            if return_body.donor_body is None:
                raise SkipFunction("short donor patch is missing trampoline body")

            donor_patch = make_jump(
                return_site.donor.patch_address,
                return_body.donor_trampoline_address,
            )
            donor_patch += make_jump(
                return_site.donor.patch_address + NEAR_JUMP_SIZE,
                return_trampoline_address,
            )
            donor_patch += b"\x90" * (
                return_site.donor.overwritten_size - (NEAR_JUMP_SIZE * 2)
            )
            binary.patch_address(
                return_body.donor_trampoline_address,
                list(return_body.donor_body),
            )
            binary.patch_address(return_site.donor.patch_address, list(donor_patch))

        binary.patch_address(return_trampoline_address, list(return_body.body))
        binary.patch_address(return_site.patch_address, list(return_patch))
        return_trampolines.append(
            ReturnTrampoline(
                function_name=function.name,
                function_address=function.address,
                return_address=return_site.ret_instruction.address,
                patch_address=return_site.patch_address,
                trampoline_address=return_trampoline_address,
                overwritten_size=return_site.overwritten_size,
                original_bytes=return_site.original_bytes,
                strategy=return_site.strategy,
            )
        )


def _build_trap_installer(
    assembler: Any,
    *,
    installer_address: int,
    original_entrypoint: int,
    trap_entries: list[_TrapEntry],
) -> bytes:
    table_rows = "\n".join(
        f".quad 0x{entry.trapped_rip:x}, 0x{entry.trampoline_address:x}"
        for entry in trap_entries
    )
    sa_flags = 0x04000000 | 0x00000004  # SA_RESTORER | SA_SIGINFO
    return assemble(
        assembler,
        f"""
        installer_base:
            sub rsp, 0x28
            lea rax, qword ptr [rip + trap_handler]
            mov qword ptr [rsp], rax
            mov qword ptr [rsp + 8], 0x{sa_flags:x}
            lea rax, qword ptr [rip + trap_restorer]
            mov qword ptr [rsp + 16], rax
            mov qword ptr [rsp + 24], 0
            lea rsi, qword ptr [rsp]
            xor edx, edx
            mov edi, 5
            mov r10d, 8
            mov eax, 13
            syscall
            add rsp, 0x28
            jmp original_entrypoint

        trap_handler:
            cmp edi, 5
            jne unknown_trap
            mov rax, qword ptr [rdx + 0xa8]
            lea r8, qword ptr [rip + installer_base]
            movabs r9, 0x{installer_address:x}
            sub r8, r9
            lea r10, qword ptr [rip + trap_table]
            mov ecx, {len(trap_entries)}
        trap_loop:
            test ecx, ecx
            je unknown_trap
            mov r11, qword ptr [r10]
            add r11, r8
            cmp rax, r11
            je trap_found
            add r10, 16
            dec ecx
            jmp trap_loop
        trap_found:
            mov r11, qword ptr [r10 + 8]
            add r11, r8
            mov qword ptr [rdx + 0xa8], r11
            ret
        unknown_trap:
            ud2

        trap_restorer:
            mov eax, 15
            syscall

        trap_table:
            {table_rows}

        original_entrypoint:
            jmp 0x{original_entrypoint:x}
        """,
        installer_address,
    )


__all__ = [
    "InjectionResult",
    "SHADOW_STACK_DESCRIPTION",
    "SHADOW_STACK_STEP",
    "ShadowStackStepOptions",
    "SkippedFunction",
    "TrapFallbackDecision",
    "inject_shadow_stack_and_initialize_frames",
    "inject_shadow_stack",
    "run_shadow_stack_step",
]
