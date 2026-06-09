"""Function-symbol discovery shared by binary analyses."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import lief


DEFAULT_SKIPPED_SYMBOLS = frozenset({"_start"})


@dataclass(frozen=True)
class FunctionSymbol:
    """One executable function symbol from the ELF symbol table."""

    name: str
    address: int
    size: int
    section: lief.ELF.Section


def iter_function_symbols(
    binary: lief.ELF.Binary,
    *,
    infer_missing_sizes: bool = False,
    skipped_names: frozenset[str] = DEFAULT_SKIPPED_SYMBOLS,
) -> Iterable[FunctionSymbol]:
    """Yield unique non-PLT function symbols in address order."""

    functions = _raw_function_symbols(binary, skipped_names)
    if not infer_missing_sizes:
        return functions

    bounded_functions: list[FunctionSymbol] = []
    for index, function in enumerate(functions):
        size = function.size
        if size <= 0:
            section_end = function.section.virtual_address + function.section.size
            next_address = _next_function_address(functions, index, section_end)
            size = max(0, min(next_address, section_end) - function.address)
        if size > 0:
            bounded_functions.append(
                FunctionSymbol(
                    name=function.name,
                    address=function.address,
                    size=size,
                    section=function.section,
                )
            )

    return bounded_functions


def _raw_function_symbols(
    binary: lief.ELF.Binary,
    skipped_names: frozenset[str],
) -> tuple[FunctionSymbol, ...]:
    seen_addresses: set[int] = set()
    functions: list[FunctionSymbol] = []

    for symbol in binary.symtab_symbols:
        if symbol.type != lief.ELF.Symbol.TYPE.FUNC:
            continue
        if symbol.value == 0 or symbol.name in skipped_names:
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
            FunctionSymbol(
                name=symbol.name or f"sub_{symbol.value:x}",
                address=symbol.value,
                size=symbol.size,
                section=section,
            )
        )

    return tuple(sorted(functions, key=lambda function: function.address))


def _next_function_address(
    functions: tuple[FunctionSymbol, ...],
    function_index: int,
    section_end: int,
) -> int:
    function = functions[function_index]
    for next_function in functions[function_index + 1 :]:
        if next_function.section == function.section:
            return next_function.address
    return section_end
