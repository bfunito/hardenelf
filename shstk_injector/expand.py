"""ELF expansion primitives for the SHSTK injector prototype."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from stat import S_IMODE

import lief


SHADOW_SECTION = ".shadow"
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
    shadow: AddedSection
    saved_addrs: AddedSection


def expand_binary(
    input_path: Path | str,
    output_path: Path | str,
    *,
    shadow_size: int = 0x1000,
    saved_addrs_size: int = 0x1000,
) -> ExpansionResult:
    """Add the sections needed by later trampoline-injection steps.

    The added sections are loaded into memory:
    - ``.shadow`` is executable space for future trampoline bodies.
    - ``.saved_addrs`` is writable storage for return addresses.
    """

    input_file = Path(input_path)
    output_file = Path(output_path)
    _validate_size("shadow_size", shadow_size)
    _validate_size("saved_addrs_size", saved_addrs_size)

    binary = lief.parse(input_file)
    if binary is None:
        raise ValueError(f"LIEF could not parse {input_file}")
    if not isinstance(binary, lief.ELF.Binary):
        raise ValueError(f"{input_file} is not an ELF binary")

    _ensure_section_absent(binary, SHADOW_SECTION)
    _ensure_section_absent(binary, SAVED_ADDRS_SECTION)

    shadow = _make_section(
        name=SHADOW_SECTION,
        size=shadow_size,
        flags=lief.ELF.Section.FLAGS.ALLOC | lief.ELF.Section.FLAGS.EXECINSTR,
        fill=0x90,
    )
    saved_addrs = _make_section(
        name=SAVED_ADDRS_SECTION,
        size=saved_addrs_size,
        flags=lief.ELF.Section.FLAGS.ALLOC | lief.ELF.Section.FLAGS.WRITE,
        fill=0x00,
    )

    binary.add(shadow, loaded=True)
    binary.add(saved_addrs, loaded=True)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    binary.write(output_file)
    output_file.chmod(S_IMODE(input_file.stat().st_mode))

    rewritten = lief.parse(output_file)
    if rewritten is None or not isinstance(rewritten, lief.ELF.Binary):
        raise ValueError(f"LIEF wrote {output_file}, but could not parse it back")

    return ExpansionResult(
        output_path=output_file,
        shadow=_section_summary(_require_section(rewritten, SHADOW_SECTION)),
        saved_addrs=_section_summary(_require_section(rewritten, SAVED_ADDRS_SECTION)),
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


def _section_summary(section: lief.ELF.Section) -> AddedSection:
    return AddedSection(
        name=section.name,
        virtual_address=section.virtual_address,
        file_offset=section.file_offset,
        size=section.size,
        flags=tuple(flag.name for flag in section.flags_list),
    )


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
