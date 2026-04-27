"""Pipeline step that injects runtime format-string argument checks."""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from stat import S_IMODE
from typing import ClassVar

import lief

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
from shstk_injector.x86 import (
    SkipFunction,
    ensure_x86_64,
    make_assembler,
    make_disassembler,
    pad_to_alignment,
)


FMTSTR_CHECKER_STEP = "fmtstr-checker"
FMTSTR_TRAMPOLINE_SECTION = ".fmtstr_tramp"
FMTSTR_DATA_SECTION = ".fmtstr_data"
_ORIGIN_RUNPATH = "$ORIGIN"
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


@dataclass(frozen=True)
class FmtStrCheckerStep:
    """Pipeline step that checks printf-like calls before libc sees them."""

    options: FmtStrCheckerStepOptions = field(default_factory=FmtStrCheckerStepOptions)

    name: ClassVar[str] = FMTSTR_CHECKER_STEP
    description: ClassVar[str] = (
        "Inject runtime format-string argument checks before printf-like calls."
    )

    def run(self, input_path: Path | str, output_path: Path | str) -> FmtStrPatchResult:
        return patch_format_strings(
            input_path,
            output_path,
            trampoline_size=self.options.trampoline_size,
            library_name=self.options.library_name,
            source_path=self.options.source_path,
        )


def patch_format_strings(
    input_path: Path | str,
    output_path: Path | str,
    *,
    trampoline_size: int = 0x4000,
    library_name: str = DEFAULT_CHECKFORMAT_LIBRARY_NAME,
    source_path: Path | str | None = None,
) -> FmtStrPatchResult:
    """Patch direct printf-like PLT calls to validate their format strings."""

    _validate_size("trampoline_size", trampoline_size)
    input_file = Path(input_path)
    output_file = Path(output_path)

    binary = lief.parse(input_file)
    if binary is None:
        raise ValueError(f"LIEF could not parse {input_file}")
    if not isinstance(binary, lief.ELF.Binary):
        raise ValueError(f"{input_file} is not an ELF binary")
    ensure_x86_64(binary)

    disassembler = make_disassembler()
    assembler = make_assembler()
    calls, skipped_calls = find_format_calls(binary, disassembler)

    if not calls:
        _copy_if_needed(input_file, output_file)
        rewritten = _parse_output(output_file)
        return FmtStrPatchResult(
            output_path=output_file,
            library_name=library_name,
            library_path=None,
            patched_calls=(),
            skipped_calls=skipped_calls,
            libraries=tuple(rewritten.libraries),
            runpath=_collect_runpath(rewritten),
        )

    _ensure_section_absent(binary, FMTSTR_TRAMPOLINE_SECTION)
    _ensure_section_absent(binary, FMTSTR_DATA_SECTION)

    if not binary.has_library(library_name):
        binary.add_library(library_name)
    _ensure_origin_runpath(binary)

    trampoline_section = _make_section(
        name=FMTSTR_TRAMPOLINE_SECTION,
        size=trampoline_size,
        flags=lief.ELF.Section.FLAGS.ALLOC | lief.ELF.Section.FLAGS.EXECINSTR,
        fill=0x90,
        alignment=0x10,
    )
    data_section = _make_section(
        name=FMTSTR_DATA_SECTION,
        size=8,
        flags=lief.ELF.Section.FLAGS.ALLOC | lief.ELF.Section.FLAGS.WRITE,
        fill=0x00,
        alignment=0x8,
    )
    binary.add(trampoline_section, loaded=True)
    binary.add(data_section, loaded=True)

    trampoline_section = _require_section(binary, FMTSTR_TRAMPOLINE_SECTION)
    data_section = _require_section(binary, FMTSTR_DATA_SECTION)
    check_format_symbol = _add_check_format_symbol(binary)
    _add_check_format_relocation(binary, check_format_symbol, data_section.virtual_address)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    binary.write(output_file)
    output_file.chmod(S_IMODE(input_file.stat().st_mode))

    binary = _parse_output(output_file)
    ensure_x86_64(binary)
    calls, skipped_calls = find_format_calls(binary, disassembler)
    trampoline_section = _require_section(binary, FMTSTR_TRAMPOLINE_SECTION)
    data_section = _require_section(binary, FMTSTR_DATA_SECTION)

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

    binary.write(output_file)
    output_file.chmod(S_IMODE(input_file.stat().st_mode))

    library_path = build_checkformat_library(
        output_file.parent,
        library_name=library_name,
        source_path=source_path,
    )
    rewritten = _parse_output(output_file)

    return FmtStrPatchResult(
        output_path=output_file,
        library_name=library_name,
        library_path=library_path,
        patched_calls=tuple(patched_calls),
        skipped_calls=tuple(remaining_skips),
        libraries=tuple(rewritten.libraries),
        runpath=_collect_runpath(rewritten),
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


def _make_section(
    *,
    name: str,
    size: int,
    flags: lief.ELF.Section.FLAGS,
    fill: int,
    alignment: int,
) -> lief.ELF.Section:
    section = lief.ELF.Section(name)
    section.type = lief.ELF.Section.TYPE.PROGBITS
    section.flags = flags
    section.alignment = alignment
    section.content = [fill] * size
    return section


def _ensure_origin_runpath(binary: lief.ELF.Binary) -> None:
    for entry in binary.dynamic_entries:
        if isinstance(entry, lief.ELF.DynamicEntryRunPath):
            if _ORIGIN_RUNPATH not in entry.paths:
                entry.append(_ORIGIN_RUNPATH)
            return
    binary.add(lief.ELF.DynamicEntryRunPath(_ORIGIN_RUNPATH))


def _collect_runpath(binary: lief.ELF.Binary) -> tuple[str, ...]:
    for entry in binary.dynamic_entries:
        if isinstance(entry, lief.ELF.DynamicEntryRunPath):
            return tuple(entry.paths)
    return ()


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
    "FMTSTR_CHECKER_STEP",
    "FMTSTR_DATA_SECTION",
    "FMTSTR_TRAMPOLINE_SECTION",
    "FmtStrCheckerStep",
    "FmtStrCheckerStepOptions",
    "FmtStrPatchResult",
    "PatchedFormatCall",
    "SkippedFormatCall",
    "patch_format_strings",
]
