"""Small ELF file helpers shared by hardening passes."""

from __future__ import annotations

import shutil
from pathlib import Path
from stat import S_IMODE

import lief


ORIGIN_RUNPATH = "$ORIGIN"
PAGE_SIZE = 0x1000


def parse_elf(path: Path | str) -> lief.ELF.Binary:
    """Parse ``path`` and require an ELF binary."""

    file_path = Path(path)
    binary = lief.parse(file_path)
    if binary is None:
        raise ValueError(f"LIEF could not parse {file_path}")
    if not isinstance(binary, lief.ELF.Binary):
        raise ValueError(f"{file_path} is not an ELF binary")
    return binary


def write_elf(
    binary: lief.ELF.Binary,
    output_file: Path,
    *,
    mode_source: Path,
) -> None:
    """Write an ELF and preserve executable bits from ``mode_source``."""

    output_file.parent.mkdir(parents=True, exist_ok=True)
    binary.write(output_file)
    output_file.chmod(S_IMODE(mode_source.stat().st_mode))


def copy_if_needed(input_file: Path, output_file: Path) -> None:
    """Copy ``input_file`` to ``output_file`` unless both paths are identical."""

    if input_file == output_file:
        return
    output_file.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(input_file, output_file)


def make_section(
    *,
    name: str,
    size: int,
    flags: lief.ELF.Section.FLAGS,
    fill: int,
    alignment: int = 0x10,
) -> lief.ELF.Section:
    section = lief.ELF.Section(name)
    section.type = lief.ELF.Section.TYPE.PROGBITS
    section.flags = flags
    section.alignment = alignment
    section.content = [fill] * size
    return section


def ensure_section_absent(binary: lief.ELF.Binary, name: str) -> None:
    if binary.has_section(name):
        raise ValueError(f"{name} already exists in the input binary")


def require_section(binary: lief.ELF.Binary, name: str) -> lief.ELF.Section:
    section = binary.get_section(name)
    if section is None:
        raise ValueError(f"{name} was not found in the rewritten binary")
    return section


def validate_positive_size(name: str, size: int) -> None:
    if size <= 0:
        raise ValueError(f"{name} must be greater than zero")


def round_up_to_page(size: int) -> int:
    size = max(size, PAGE_SIZE)
    return ((size + PAGE_SIZE - 1) // PAGE_SIZE) * PAGE_SIZE


def ensure_origin_runpath(binary: lief.ELF.Binary) -> None:
    for entry in binary.dynamic_entries:
        if isinstance(entry, lief.ELF.DynamicEntryRunPath):
            if ORIGIN_RUNPATH not in entry.paths:
                entry.append(ORIGIN_RUNPATH)
            return
    binary.add(lief.ELF.DynamicEntryRunPath(ORIGIN_RUNPATH))


def collect_runpath(binary: lief.ELF.Binary) -> tuple[str, ...]:
    for entry in binary.dynamic_entries:
        if isinstance(entry, lief.ELF.DynamicEntryRunPath):
            return tuple(entry.paths)
    return ()
