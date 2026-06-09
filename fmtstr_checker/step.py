"""Pipeline step that injects runtime format-string argument checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import lief

from binary_hardening.elf import (
    collect_runpath,
    copy_if_needed,
    ensure_origin_runpath,
    ensure_section_absent,
    make_section,
    parse_elf,
    require_section,
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
from fmtstr_checker.analysis import (
    FormatCall,
    SkippedFormatCall,
    find_format_calls,
)
from fmtstr_checker.checkformat import (
    DEFAULT_CHECKFORMAT_LIBRARY_NAME,
    build_checkformat_library,
)
from fmtstr_checker.trampoline import (
    build_format_trampoline,
    make_call,
)


FMTSTR_CHECKER_STEP = "fmtstr-checker"
FMTSTR_CHECKER_DESCRIPTION = (
    "Inject runtime format-string argument checks before printf-like calls."
)
FMTSTR_TRAMPOLINE_SECTION = ".fmtstr_tramp"
FMTSTR_DATA_SECTION = ".fmtstr_data"
_CHECK_FORMAT_SYMBOL = "check_format"


@dataclass(frozen=True)
class PatchedFormatCall:
    """One printf-like call site routed through a format-check trampoline."""

    function_name: str
    call_address: int
    target_name: str
    trampoline_address: int
    n_variadic: int
    format_register: str


@dataclass(frozen=True)
class FmtStrPatchResult:
    """Summary returned after injecting format-string checks."""

    output_path: Path
    library_name: str
    library_path: Path | None
    patched_calls: tuple[PatchedFormatCall, ...]
    skipped_calls: tuple[SkippedFormatCall, ...]
    libraries: tuple[str, ...]
    runpath: tuple[str, ...]


@dataclass(frozen=True)
class FmtStrCheckerStepOptions:
    """Configuration for the format-string checker step."""

    trampoline_size: int = 0x4000
    library_name: str = DEFAULT_CHECKFORMAT_LIBRARY_NAME
    source_path: Path | str | None = None


def patch_format_strings(
    input_path: Path | str,
    output_path: Path | str,
    *,
    trampoline_size: int = 0x4000,
    library_name: str = DEFAULT_CHECKFORMAT_LIBRARY_NAME,
    source_path: Path | str | None = None,
) -> FmtStrPatchResult:
    """Patch direct printf-like PLT calls to validate their format strings."""

    validate_positive_size("trampoline_size", trampoline_size)
    input_file = Path(input_path)
    output_file = Path(output_path)

    binary = parse_elf(input_file)
    ensure_x86_64(binary)

    disassembler = make_disassembler()
    assembler = make_assembler()
    calls, skipped_calls = find_format_calls(binary, disassembler)

    if not calls:
        copy_if_needed(input_file, output_file)
        rewritten = parse_elf(output_file)
        return FmtStrPatchResult(
            output_path=output_file,
            library_name=library_name,
            library_path=None,
            patched_calls=(),
            skipped_calls=skipped_calls,
            libraries=tuple(rewritten.libraries),
            runpath=collect_runpath(rewritten),
        )

    ensure_section_absent(binary, FMTSTR_TRAMPOLINE_SECTION)
    ensure_section_absent(binary, FMTSTR_DATA_SECTION)

    if not binary.has_library(library_name):
        binary.add_library(library_name)
    ensure_origin_runpath(binary)

    trampoline_section = make_section(
        name=FMTSTR_TRAMPOLINE_SECTION,
        size=trampoline_size,
        flags=lief.ELF.Section.FLAGS.ALLOC | lief.ELF.Section.FLAGS.EXECINSTR,
        fill=0x90,
        alignment=0x10,
    )
    data_section = make_section(
        name=FMTSTR_DATA_SECTION,
        size=8,
        flags=lief.ELF.Section.FLAGS.ALLOC | lief.ELF.Section.FLAGS.WRITE,
        fill=0x00,
        alignment=0x8,
    )
    binary.add(trampoline_section, loaded=True)
    binary.add(data_section, loaded=True)

    trampoline_section = require_section(binary, FMTSTR_TRAMPOLINE_SECTION)
    data_section = require_section(binary, FMTSTR_DATA_SECTION)
    check_format_symbol = _add_check_format_symbol(binary)
    _add_check_format_relocation(binary, check_format_symbol, data_section.virtual_address)

    write_elf(binary, output_file, mode_source=input_file)

    binary = parse_elf(output_file)
    ensure_x86_64(binary)
    calls, skipped_calls = find_format_calls(binary, disassembler)
    trampoline_section = require_section(binary, FMTSTR_TRAMPOLINE_SECTION)
    data_section = require_section(binary, FMTSTR_DATA_SECTION)

    patched_calls: list[PatchedFormatCall] = []
    remaining_skips = list(skipped_calls)
    cursor = trampoline_section.virtual_address
    end = trampoline_section.virtual_address + trampoline_section.size

    for call in calls:
        try:
            trampoline_body = build_format_trampoline(
                assembler=assembler,
                call=call,
                trampoline_address=cursor,
                check_format_slot_address=data_section.virtual_address,
            )
            trampoline_body = pad_to_alignment(trampoline_body)
            next_cursor = cursor + len(trampoline_body)
            if next_cursor > end:
                remaining_skips.append(
                    SkippedFormatCall(
                        call.function_name,
                        call.call_address,
                        call.target_name,
                        "not enough room left in .fmtstr_tramp",
                    )
                )
                continue

            call_patch = make_call(call.call_address, cursor)
            call_patch += b"\x90" * (call.instruction_size - len(call_patch))

            binary.patch_address(cursor, list(trampoline_body))
            binary.patch_address(call.call_address, list(call_patch))
            patched_calls.append(_patched_call_summary(call, cursor))
            cursor = next_cursor
        except SkipFunction as exc:
            remaining_skips.append(
                SkippedFormatCall(
                    call.function_name,
                    call.call_address,
                    call.target_name,
                    str(exc),
                )
            )

    if not patched_calls:
        raise ValueError("no format-string call trampolines were written")

    write_elf(binary, output_file, mode_source=input_file)

    library_path = build_checkformat_library(
        output_file.parent,
        library_name=library_name,
        source_path=source_path,
    )
    rewritten = parse_elf(output_file)

    return FmtStrPatchResult(
        output_path=output_file,
        library_name=library_name,
        library_path=library_path,
        patched_calls=tuple(patched_calls),
        skipped_calls=tuple(remaining_skips),
        libraries=tuple(rewritten.libraries),
        runpath=collect_runpath(rewritten),
    )


def _patched_call_summary(call: FormatCall, trampoline_address: int) -> PatchedFormatCall:
    return PatchedFormatCall(
        function_name=call.function_name,
        call_address=call.call_address,
        target_name=call.target_name,
        trampoline_address=trampoline_address,
        n_variadic=call.n_variadic,
        format_register=call.format_register,
    )


def _add_check_format_symbol(binary: lief.ELF.Binary) -> lief.ELF.Symbol:
    if binary.has_dynamic_symbol(_CHECK_FORMAT_SYMBOL):
        return binary.get_dynamic_symbol(_CHECK_FORMAT_SYMBOL)

    symbol = lief.ELF.Symbol()
    symbol.name = _CHECK_FORMAT_SYMBOL
    symbol.type = lief.ELF.Symbol.TYPE.FUNC
    symbol.binding = lief.ELF.Symbol.BINDING.GLOBAL
    symbol.shndx = 0
    symbol.value = 0
    symbol.size = 0
    return binary.add_dynamic_symbol(symbol)


def _add_check_format_relocation(
    binary: lief.ELF.Binary,
    symbol: lief.ELF.Symbol,
    slot_address: int,
) -> None:
    relocation = lief.ELF.Relocation(
        slot_address,
        lief.ELF.Relocation.TYPE.X86_64_GLOB_DAT,
        lief.ELF.Relocation.ENCODING.RELA,
    )
    relocation.symbol = symbol
    relocation.addend = 0
    binary.add_dynamic_relocation(relocation)


__all__ = [
    "FMTSTR_CHECKER_DESCRIPTION",
    "FMTSTR_CHECKER_STEP",
    "FMTSTR_DATA_SECTION",
    "FMTSTR_TRAMPOLINE_SECTION",
    "FmtStrCheckerStepOptions",
    "FmtStrPatchResult",
    "PatchedFormatCall",
    "SkippedFormatCall",
    "patch_format_strings",
]
