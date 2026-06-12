"""ELF expansion primitives for hardening trampolines."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import lief

from binary_hardening.hardenelf import HARDENELF_SECTION
from binary_hardening.elf import (
    ensure_section_absent,
    make_section,
    parse_elf,
    require_section,
    validate_positive_size,
    write_elf,
)


SAVED_ADDRS_SECTION = ".saved_addrs"


@dataclass(frozen=True)
class AddedSection:
    """Summary of a section added to the rewritten binary."""

    name: str
    virtual_address: int
    file_offset: int
    size: int
    flags: tuple[str, ...]


@dataclass(frozen=True)
class ExpansionResult:
    """Summary returned after expanding an ELF binary."""

    output_path: Path
    hardenelf: AddedSection
    saved_addrs: AddedSection


def expand_binary(
    input_path: Path | str,
    output_path: Path | str,
    *,
    hardenelf_size: int = 0x1000,
    saved_addrs_size: int = 0x1000,
) -> ExpansionResult:
    """Add the sections needed by later trampoline-injection steps.

    The added sections are loaded into memory:
    - ``.hardenelf`` is executable space for trampoline bodies.
    - ``.saved_addrs`` is writable storage for return addresses.
    """

    input_file = Path(input_path)
    output_file = Path(output_path)
    validate_positive_size("hardenelf_size", hardenelf_size)
    validate_positive_size("saved_addrs_size", saved_addrs_size)

    binary = parse_elf(input_file)

    ensure_section_absent(binary, HARDENELF_SECTION)
    ensure_section_absent(binary, SAVED_ADDRS_SECTION)

    hardenelf = make_section(
        name=HARDENELF_SECTION,
        size=hardenelf_size,
        flags=lief.ELF.Section.FLAGS.ALLOC | lief.ELF.Section.FLAGS.EXECINSTR,
        fill=0x90,
    )
    saved_addrs = make_section(
        name=SAVED_ADDRS_SECTION,
        size=saved_addrs_size,
        flags=lief.ELF.Section.FLAGS.ALLOC | lief.ELF.Section.FLAGS.WRITE,
        fill=0x00,
    )

    binary.add(hardenelf, loaded=True)
    binary.add(saved_addrs, loaded=True)

    write_elf(binary, output_file, mode_source=input_file)
    rewritten = parse_elf(output_file)

    return ExpansionResult(
        output_path=output_file,
        hardenelf=section_summary(require_section(rewritten, HARDENELF_SECTION)),
        saved_addrs=section_summary(require_section(rewritten, SAVED_ADDRS_SECTION)),
    )


def section_summary(section: lief.ELF.Section) -> AddedSection:
    return AddedSection(
        name=section.name,
        virtual_address=section.virtual_address,
        file_offset=section.file_offset,
        size=section.size,
        flags=tuple(flag.name for flag in section.flags_list),
    )
