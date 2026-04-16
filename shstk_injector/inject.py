"""High-level SHSTK trampoline injection pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

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
    _require_section,
    _section_summary,
    expand_binary,
)
from shstk_injector.return_trampoline import (
    ReturnSite,
    ReturnTrampoline,
    build_return_trampoline,
    collect_return_sites,
)
from shstk_injector.x86 import (
    NEAR_JUMP_SIZE,
    SkipFunction,
    ensure_x86_64,
    make_assembler,
    make_disassembler,
    make_jump,
    pad_to_alignment,
    ranges_overlap,
)


SHADOW_STACK_CURSOR_SIZE = 8
_SKIPPED_ENTRY_SYMBOLS = frozenset({"_start"})


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


EntryInjectionResult = InjectionResult


@dataclass(frozen=True)
class _FunctionSymbol:
    name: str
    address: int
    size: int
    section: lief.ELF.Section


def inject_trampolines(
    input_path: Path | str,
    output_path: Path | str,
    *,
    shadow_size: int = 0x1000,
    saved_addrs_size: int = 0x1000,
) -> InjectionResult:
    """Expand an ELF binary and patch function entries and returns.

    The first eight bytes of ``.saved_addrs`` hold a runtime cursor. Saved
    return addresses start immediately after that cursor.
    """

    disassembler = make_disassembler()
    assembler = make_assembler()

    expanded = expand_binary(
        input_path,
        output_path,
        shadow_size=shadow_size,
        saved_addrs_size=saved_addrs_size,
    )
    output_file = expanded.output_path

    binary = lief.parse(output_file)
    if binary is None or not isinstance(binary, lief.ELF.Binary):
        raise ValueError(f"LIEF could not parse expanded binary {output_file}")
    ensure_x86_64(binary)

    shadow = _require_section(binary, SHADOW_SECTION)
    saved_addrs = _require_section(binary, SAVED_ADDRS_SECTION)
    if saved_addrs.size <= SHADOW_STACK_CURSOR_SIZE:
        raise ValueError(".saved_addrs must be larger than eight bytes")

    shadow_cursor = shadow.virtual_address
    shadow_end = shadow.virtual_address + shadow.size
    trampolines: list[EntryTrampoline] = []
    return_trampolines: list[ReturnTrampoline] = []
    skipped: list[SkippedFunction] = []

    for function in _iter_function_symbols(binary):
        try:
            entry_instructions = collect_entry_instructions(
                binary,
                disassembler,
                function,
            )
            return_sites = collect_return_sites(binary, disassembler, function)

            entry_overwritten_size = sum(
                instruction.size for instruction in entry_instructions
            )
            _ensure_patch_ranges_do_not_overlap(
                function.address,
                entry_overwritten_size,
                return_sites,
            )

            entry_body = build_entry_trampoline(
                assembler=assembler,
                instructions=entry_instructions,
                trampoline_address=shadow_cursor,
                return_address=function.address + entry_overwritten_size,
                saved_addrs_address=saved_addrs.virtual_address,
            )
            entry_body = pad_to_alignment(entry_body)
            return_bodies: list[tuple[ReturnSite, int, bytes]] = []
            next_shadow_cursor = shadow_cursor + len(entry_body)

            for return_site in return_sites:
                return_body = build_return_trampoline(
                    assembler=assembler,
                    return_site=return_site,
                    trampoline_address=next_shadow_cursor,
                    saved_addrs_address=saved_addrs.virtual_address,
                )
                return_body = pad_to_alignment(return_body)
                return_bodies.append((return_site, next_shadow_cursor, return_body))
                next_shadow_cursor += len(return_body)

            if next_shadow_cursor > shadow_end:
                skipped.append(
                    SkippedFunction(
                        function.name,
                        function.address,
                        "not enough room left in .shadow",
                    )
                )
                continue

            _patch_entry(
                binary,
                function,
                shadow_cursor,
                entry_body,
                entry_instructions,
                entry_overwritten_size,
                trampolines,
            )
            _patch_returns(
                binary,
                function,
                return_bodies,
                return_trampolines,
            )

            shadow_cursor = next_shadow_cursor
        except SkipFunction as exc:
            skipped.append(SkippedFunction(function.name, function.address, str(exc)))

    if not trampolines:
        raise ValueError("no complete function trampolines were written")

    binary.write(output_file)
    rewritten = lief.parse(output_file)
    if rewritten is None or not isinstance(rewritten, lief.ELF.Binary):
        raise ValueError(f"LIEF wrote {output_file}, but could not parse it back")

    return InjectionResult(
        output_path=output_file,
        shadow=_section_summary(_require_section(rewritten, SHADOW_SECTION)),
        saved_addrs=_section_summary(_require_section(rewritten, SAVED_ADDRS_SECTION)),
        trampolines=tuple(trampolines),
        skipped=tuple(skipped),
        return_trampolines=tuple(return_trampolines),
    )


def inject_entry_trampolines(
    input_path: Path | str,
    output_path: Path | str,
    *,
    shadow_size: int = 0x1000,
    saved_addrs_size: int = 0x1000,
) -> InjectionResult:
    """Backward-compatible name for the full entry and return injector."""

    return inject_trampolines(
        input_path,
        output_path,
        shadow_size=shadow_size,
        saved_addrs_size=saved_addrs_size,
    )


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
        return_patch_range = (
            return_site.patch_address,
            return_site.patch_address + return_site.overwritten_size,
        )
        if ranges_overlap(entry_patch_range, return_patch_range):
            raise SkipFunction("entry and return patches overlap")


def _patch_entry(
    binary: lief.ELF.Binary,
    function: _FunctionSymbol,
    trampoline_address: int,
    body: bytes,
    instructions: list[object],
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
    return_bodies: list[tuple[ReturnSite, int, bytes]],
    return_trampolines: list[ReturnTrampoline],
) -> None:
    for return_site, return_trampoline_address, return_body in return_bodies:
        return_patch = make_jump(
            return_site.patch_address,
            return_trampoline_address,
        )
        return_patch += b"\x90" * (return_site.overwritten_size - NEAR_JUMP_SIZE)

        binary.patch_address(return_trampoline_address, list(return_body))
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
            )
        )
