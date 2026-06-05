"""Shadow-stack pipeline step."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, ClassVar, Iterable

import lief

from shstk_injector.entry_trampoline import (
    EntryTrampoline,
    build_entry_trampoline,
    collect_entry_instructions,
)
from shstk_injector.expand import (
    SAVED_ADDRS_SECTION,
    SHADOW_SECTION,
    AddedSection,
    ExpansionResult,
    _require_section,
    _section_summary,
    expand_binary,
)
from shstk_injector.return_trampoline import (
    ReturnAddressAction,
    ReturnPatchStrategy,
    ReturnSite,
    ReturnTrampoline,
    TrapFallbackCandidate,
    build_donor_trampoline,
    build_return_trampoline,
    collect_return_sites,
)
from binary_hardening.x86 import (
    NEAR_JUMP_SIZE,
    SkipFunction,
    assemble,
    ensure_x86_64,
    is_pie_binary,
    make_assembler,
    make_disassembler,
    make_jump,
    make_short_jump,
    pad_to_alignment,
    ranges_overlap,
)


SHADOW_STACK_CURSOR_SIZE = 8
SHADOW_STACK_STEP = "shadow-stack"
SHADOW_SIZE_PAGE = 0x1000
_SKIPPED_ENTRY_SYMBOLS = frozenset({"_start"})
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
    shadow: AddedSection
    saved_addrs: AddedSection
    trampolines: tuple[EntryTrampoline, ...]
    skipped: tuple[SkippedFunction, ...]
    return_trampolines: tuple[ReturnTrampoline, ...] = ()
    is_pie: bool = False


@dataclass(frozen=True)
class ShadowStackStepOptions:
    """Configuration for the shadow-stack pipeline step."""

    shadow_size: int | None = None
    saved_addrs_size: int = 0x1000
    return_address_action: ReturnAddressAction | str = ReturnAddressAction.RESTORE
    crash_message: str | bytes | None = None
    expand_only: bool = False
    trap_fallback: TrapFallbackDecision | str = TrapFallbackDecision.ASK
    trap_fallback_callback: Callable[[str, int, str], bool] | None = None


@dataclass(frozen=True)
class ShadowStackStep:
    """Pipeline step that injects the current shadow-stack protection."""

    options: ShadowStackStepOptions = field(default_factory=ShadowStackStepOptions)

    name: ClassVar[str] = SHADOW_STACK_STEP
    description: ClassVar[str] = (
        "Add the shadow-stack sections and inject entry/return trampolines."
    )

    def run(
        self,
        input_path: Path | str,
        output_path: Path | str,
    ) -> ExpansionResult | InjectionResult:
        if self.options.expand_only:
            return expand_binary(
                input_path,
                output_path,
                shadow_size=_manual_or_default_shadow_size(self.options.shadow_size),
                saved_addrs_size=self.options.saved_addrs_size,
            )

        return inject_shadow_stack(
            input_path,
            output_path,
            shadow_size=self.options.shadow_size,
            saved_addrs_size=self.options.saved_addrs_size,
            return_address_action=self.options.return_address_action,
            crash_message=self.options.crash_message,
            trap_fallback=self.options.trap_fallback,
            trap_fallback_callback=self.options.trap_fallback_callback,
        )


@dataclass(frozen=True)
class _FunctionSymbol:
    name: str
    address: int
    size: int
    section: lief.ELF.Section


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
    function: _FunctionSymbol
    entry_body_address: int
    entry_instructions: list[Any]
    entry_body: bytes
    entry_overwritten_size: int
    return_bodies: list[_ReturnBody]


@dataclass(frozen=True)
class _ShadowStackPlan:
    patches: tuple[_PlannedFunctionPatch, ...]
    skipped: tuple[SkippedFunction, ...]
    trap_entries: tuple[_TrapEntry, ...]
    trap_installer_address: int | None
    trap_installer_body: bytes | None
    required_shadow_size: int


def inject_shadow_stack(
    input_path: Path | str,
    output_path: Path | str,
    *,
    shadow_size: int | None = None,
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

    resolved_shadow_size = _resolve_shadow_size(
        input_path,
        shadow_size=shadow_size,
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
        shadow_size=resolved_shadow_size,
        saved_addrs_size=saved_addrs_size,
    )
    output_file = expanded.output_path

    binary = lief.parse(output_file)
    if binary is None or not isinstance(binary, lief.ELF.Binary):
        raise ValueError(f"LIEF could not parse expanded binary {output_file}")
    ensure_x86_64(binary)
    is_pie = is_pie_binary(binary)

    shadow = _require_section(binary, SHADOW_SECTION)
    saved_addrs = _require_section(binary, SAVED_ADDRS_SECTION)
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
        enforce_shadow_limit=True,
    )
    trampolines: list[EntryTrampoline] = []
    return_trampolines: list[ReturnTrampoline] = []
    trap_entries: list[_TrapEntry] = []

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
            trap_entries,
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
    rewritten = lief.parse(output_file)
    if rewritten is None or not isinstance(rewritten, lief.ELF.Binary):
        raise ValueError(f"LIEF wrote {output_file}, but could not parse it back")

    return InjectionResult(
        output_path=output_file,
        shadow=_section_summary(_require_section(rewritten, SHADOW_SECTION)),
        saved_addrs=_section_summary(_require_section(rewritten, SAVED_ADDRS_SECTION)),
        trampolines=tuple(trampolines),
        skipped=plan.skipped,
        return_trampolines=tuple(return_trampolines),
        is_pie=is_pie,
    )


def _resolve_shadow_size(
    input_path: Path | str,
    *,
    shadow_size: int | None,
    saved_addrs_size: int,
    action: ReturnAddressAction,
    crash_message: bytes | None,
    trap_decision: TrapFallbackDecision,
    trap_fallback_callback: Callable[[str, int, str], bool] | None,
    disassembler: Any,
    assembler: Any,
) -> int:
    if shadow_size is not None:
        return shadow_size

    candidate_size = SHADOW_SIZE_PAGE
    seen_sizes: set[int] = set()
    with TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        for _ in range(8):
            if candidate_size in seen_sizes:
                raise ValueError("automatic .shadow sizing did not converge")
            seen_sizes.add(candidate_size)

            expanded_path = tmpdir_path / f"shadow-auto-{candidate_size:x}"
            expand_binary(
                input_path,
                expanded_path,
                shadow_size=candidate_size,
                saved_addrs_size=saved_addrs_size,
            )
            binary = lief.parse(expanded_path)
            if binary is None or not isinstance(binary, lief.ELF.Binary):
                raise ValueError(
                    f"LIEF could not parse expanded binary {expanded_path}"
                )
            ensure_x86_64(binary)

            saved_addrs = _require_section(binary, SAVED_ADDRS_SECTION)
            if saved_addrs.size <= SHADOW_STACK_CURSOR_SIZE:
                raise ValueError(".saved_addrs must be larger than eight bytes")

            plan = _build_shadow_stack_plan(
                binary,
                disassembler=disassembler,
                assembler=assembler,
                action=action,
                crash_message=crash_message,
                trap_decision=trap_decision,
                trap_fallback_callback=trap_fallback_callback,
                enforce_shadow_limit=False,
            )
            needed_size = _round_up_to_page(plan.required_shadow_size)
            if needed_size == candidate_size:
                return needed_size
            candidate_size = needed_size

    raise ValueError("automatic .shadow sizing did not converge")


def _build_shadow_stack_plan(
    binary: lief.ELF.Binary,
    *,
    disassembler: Any,
    assembler: Any,
    action: ReturnAddressAction,
    crash_message: bytes | None,
    trap_decision: TrapFallbackDecision,
    trap_fallback_callback: Callable[[str, int, str], bool] | None,
    enforce_shadow_limit: bool,
) -> _ShadowStackPlan:
    is_pie = is_pie_binary(binary)
    allow_absolute_saved_addrs = not is_pie
    shadow = _require_section(binary, SHADOW_SECTION)
    saved_addrs = _require_section(binary, SAVED_ADDRS_SECTION)
    shadow_cursor = shadow.virtual_address
    shadow_end = shadow.virtual_address + shadow.size
    patches: list[_PlannedFunctionPatch] = []
    trap_entries: list[_TrapEntry] = []
    skipped: list[SkippedFunction] = []

    for function in _iter_function_symbols(binary):
        try:
            entry_instructions = collect_entry_instructions(
                binary,
                disassembler,
                function,
            )
            try:
                return_sites = collect_return_sites(binary, disassembler, function)
            except TrapFallbackCandidate as exc:
                if not _allow_trap_fallback(
                    trap_decision,
                    trap_fallback_callback,
                    function,
                    str(exc),
                ):
                    raise SkipFunction(
                        _trap_fallback_skip_reason(trap_decision, str(exc))
                    ) from exc
                return_sites = collect_return_sites(
                    binary,
                    disassembler,
                    function,
                    allow_trap_fallback=True,
                )

            entry_overwritten_size = sum(
                instruction.size for instruction in entry_instructions
            )
            _ensure_patch_ranges_do_not_overlap(
                function.address,
                entry_overwritten_size,
                return_sites,
            )

            entry_body_address = shadow_cursor
            entry_body = _build_entry_body(
                assembler=assembler,
                instructions=entry_instructions,
                trampoline_address=entry_body_address,
                return_address=function.address + entry_overwritten_size,
                saved_addrs_address=saved_addrs.virtual_address,
                allow_absolute_saved_addrs=allow_absolute_saved_addrs,
                return_sites=return_sites,
            )
            return_bodies: list[_ReturnBody] = []
            function_trap_entries: list[_TrapEntry] = []
            next_shadow_cursor = entry_body_address + len(entry_body)

            for return_site in return_sites:
                donor_trampoline_address = None
                donor_body = None
                if return_site.donor is not None:
                    donor_trampoline_address = next_shadow_cursor
                    donor_body = build_donor_trampoline(
                        assembler=assembler,
                        donor=return_site.donor,
                        trampoline_address=donor_trampoline_address,
                    )
                    donor_body = pad_to_alignment(donor_body)
                    next_shadow_cursor += len(donor_body)

                return_body_address = next_shadow_cursor
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
                return_bodies.append(
                    _ReturnBody(
                        site=return_site,
                        trampoline_address=return_body_address,
                        body=return_body,
                        donor_trampoline_address=donor_trampoline_address,
                        donor_body=donor_body,
                    )
                )
                if return_site.strategy is ReturnPatchStrategy.TRAP:
                    function_trap_entries.append(
                        _TrapEntry(
                            trapped_rip=return_site.patch_address
                            + len(_TRAP_INSTRUCTION),
                            trampoline_address=return_body_address,
                        )
                    )
                next_shadow_cursor += len(return_body)

            if enforce_shadow_limit and next_shadow_cursor > shadow_end:
                skipped.append(
                    SkippedFunction(
                        function.name,
                        function.address,
                        "not enough room left in .shadow",
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
                )
            )
            trap_entries.extend(function_trap_entries)
            shadow_cursor = next_shadow_cursor
        except SkipFunction as exc:
            skipped.append(SkippedFunction(function.name, function.address, str(exc)))

    trap_installer_address = None
    trap_installer_body = None
    if trap_entries:
        trap_installer_address = shadow_cursor
        trap_installer_body = _build_trap_installer(
            assembler,
            installer_address=trap_installer_address,
            original_entrypoint=binary.entrypoint,
            trap_entries=trap_entries,
        )
        trap_installer_body = pad_to_alignment(trap_installer_body)
        shadow_cursor += len(trap_installer_body)
        if enforce_shadow_limit and shadow_cursor > shadow_end:
            raise ValueError("not enough room left in .shadow for SIGTRAP handler")

    return _ShadowStackPlan(
        patches=tuple(patches),
        skipped=tuple(skipped),
        trap_entries=tuple(trap_entries),
        trap_installer_address=trap_installer_address,
        trap_installer_body=trap_installer_body,
        required_shadow_size=shadow_cursor - shadow.virtual_address,
    )


def _round_up_to_page(size: int) -> int:
    size = max(size, SHADOW_SIZE_PAGE)
    return ((size + SHADOW_SIZE_PAGE - 1) // SHADOW_SIZE_PAGE) * SHADOW_SIZE_PAGE


def _manual_or_default_shadow_size(shadow_size: int | None) -> int:
    return shadow_size if shadow_size is not None else SHADOW_SIZE_PAGE


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


def _allow_trap_fallback(
    decision: TrapFallbackDecision,
    callback: Callable[[str, int, str], bool] | None,
    function: _FunctionSymbol,
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


def _iter_function_symbols(binary: lief.ELF.Binary) -> Iterable[_FunctionSymbol]:
    seen_addresses: set[int] = set()
    functions: list[_FunctionSymbol] = []

    for symbol in binary.symtab_symbols:
        if symbol.type != lief.ELF.Symbol.TYPE.FUNC:
            continue
        if symbol.value == 0 or symbol.name in _SKIPPED_ENTRY_SYMBOLS:
            continue
        if symbol.value in seen_addresses:
            continue

        section = binary.section_from_virtual_address(symbol.value)
        if section is None or not section.has(lief.ELF.Section.FLAGS.EXECINSTR):
            continue
        if section.name.startswith(".plt"):
            continue

        seen_addresses.add(symbol.value)
        functions.append(
            _FunctionSymbol(
                name=symbol.name or f"sub_{symbol.value:x}",
                address=symbol.value,
                size=symbol.size,
                section=section,
            )
        )

    return sorted(functions, key=lambda function: function.address)


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
) -> bytes:
    rbx_jump_target = _rbx_jump_target(return_sites, trampoline_address)

    for _ in range(3):
        body = build_entry_trampoline(
            assembler=assembler,
            instructions=instructions,
            trampoline_address=trampoline_address,
            return_address=return_address,
            saved_addrs_address=saved_addrs_address,
            allow_absolute_saved_addrs=allow_absolute_saved_addrs,
            rbx_jump_target=rbx_jump_target,
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


def _rbx_jump_target(
    return_sites: list[ReturnSite],
    first_return_trampoline_address: int,
) -> int | None:
    if any(site.strategy is ReturnPatchStrategy.RBX_JUMP for site in return_sites):
        return first_return_trampoline_address
    return None


def _patch_entry(
    binary: lief.ELF.Binary,
    function: _FunctionSymbol,
    trampoline_address: int,
    body: bytes,
    instructions: list[Any],
    overwritten_size: int,
    trampolines: list[EntryTrampoline],
) -> None:
    entry_patch = make_jump(function.address, trampoline_address)
    entry_patch += b"\x90" * (overwritten_size - NEAR_JUMP_SIZE)

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
    function: _FunctionSymbol,
    return_bodies: list[_ReturnBody],
    return_trampolines: list[ReturnTrampoline],
    trap_entries: list[_TrapEntry],
) -> None:
    for return_body in return_bodies:
        return_site = return_body.site
        return_trampoline_address = return_body.trampoline_address
        if return_site.strategy is ReturnPatchStrategy.RBX_JUMP:
            return_patch = b"\xff\xe3"
        elif return_site.strategy is ReturnPatchStrategy.TRAP:
            return_patch = _TRAP_INSTRUCTION
            trap_entries.append(
                _TrapEntry(
                    trapped_rip=return_site.patch_address + len(_TRAP_INSTRUCTION),
                    trampoline_address=return_trampoline_address,
                )
            )
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
    "SHADOW_STACK_STEP",
    "ShadowStackStep",
    "ShadowStackStepOptions",
    "SkippedFunction",
    "TrapFallbackDecision",
    "inject_shadow_stack",
]
