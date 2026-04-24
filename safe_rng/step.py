"""Pipeline step that retargets unsafe RNG imports to ``libsaferand.so``."""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from stat import S_IMODE
from typing import ClassVar

import lief

from safe_rng.saferand import (
    DEFAULT_SAFERAND_LIBRARY_NAME,
    build_saferand_library,
)


RNG_PATCHER_STEP = "rng-patcher"
_ORIGIN_RUNPATH = "$ORIGIN"
_TARGET_SYMBOLS = (
    "rand",
    "rand_r",
    "random",
    "random_r",
    "lrand48",
    "nrand48",
    "mrand48",
    "jrand48",
    "drand48",
    "erand48",
    "srand",
    "srandom",
    "srand48",
    "seed48",
    "lcong48",
)
_SYMBOL_RENAMES = {name: f"saferand_{name}" for name in _TARGET_SYMBOLS}


@dataclass(frozen=True)
class PatchedImport:
    """One imported function retargeted to ``libsaferand.so``."""

    original_name: str
    patched_name: str


@dataclass(frozen=True)
class RngPatchResult:
    """Summary returned after patching RNG imports."""

    output_path: Path
    library_name: str
    library_path: Path | None
    patched_imports: tuple[PatchedImport, ...]
    libraries: tuple[str, ...]
    runpath: tuple[str, ...]


@dataclass(frozen=True)
class RngPatcherStepOptions:
    """Configuration for the RNG patcher step."""

    library_name: str = DEFAULT_SAFERAND_LIBRARY_NAME
    source_path: Path | str | None = None


@dataclass(frozen=True)
class RngPatcherStep:
    """Pipeline step that redirects libc RNG imports to ``libsaferand.so``."""

    options: RngPatcherStepOptions = field(default_factory=RngPatcherStepOptions)

    name: ClassVar[str] = RNG_PATCHER_STEP
    description: ClassVar[str] = (
        "Redirect imported RNG APIs to the bundled libsaferand shared library."
    )

    def run(self, input_path: Path | str, output_path: Path | str) -> RngPatchResult:
        return patch_rng_imports(
            input_path,
            output_path,
            library_name=self.options.library_name,
            source_path=self.options.source_path,
        )


def patch_rng_imports(
    input_path: Path | str,
    output_path: Path | str,
    *,
    library_name: str = DEFAULT_SAFERAND_LIBRARY_NAME,
    source_path: Path | str | None = None,
) -> RngPatchResult:
    """Retarget imported RNG functions to ``libsaferand.so``."""

    input_file = Path(input_path)
    output_file = Path(output_path)

    binary = lief.parse(input_file)
    if binary is None:
        raise ValueError(f"LIEF could not parse {input_file}")
    if not isinstance(binary, lief.ELF.Binary):
        raise ValueError(f"{input_file} is not an ELF binary")

    imported_by_name = {
        _base_symbol_name(symbol.name): symbol
        for symbol in binary.imported_symbols
        if _base_symbol_name(symbol.name) in _TARGET_SYMBOLS
    }
    patched_imports: list[PatchedImport] = []

    for original_name in _TARGET_SYMBOLS:
        symbol = imported_by_name.get(original_name)
        if symbol is None:
            continue
        patched_name = _SYMBOL_RENAMES[original_name]
        symbol.name = patched_name
        patched_imports.append(
            PatchedImport(
                original_name=original_name,
                patched_name=patched_name,
            )
        )

    has_saferand_imports = any(
        _base_symbol_name(symbol.name) in _SYMBOL_RENAMES.values()
        for symbol in binary.imported_symbols
    )
    if (
        not patched_imports
        and not binary.has_library(library_name)
        and not has_saferand_imports
    ):
        _copy_if_needed(input_file, output_file)
        rewritten = lief.parse(output_file)
        if rewritten is None or not isinstance(rewritten, lief.ELF.Binary):
            raise ValueError(f"LIEF could not parse {output_file}")
        return RngPatchResult(
            output_path=output_file,
            library_name=library_name,
            library_path=None,
            patched_imports=(),
            libraries=tuple(rewritten.libraries),
            runpath=_collect_runpath(rewritten),
        )

    if not binary.has_library(library_name):
        binary.add_library(library_name)
    _ensure_origin_runpath(binary)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    binary.write(output_file)
    output_file.chmod(S_IMODE(input_file.stat().st_mode))

    library_path = build_saferand_library(
        output_file.parent,
        library_name=library_name,
        source_path=source_path,
    )
    rewritten = lief.parse(output_file)
    if rewritten is None or not isinstance(rewritten, lief.ELF.Binary):
        raise ValueError(f"LIEF wrote {output_file}, but could not parse it back")

    return RngPatchResult(
        output_path=output_file,
        library_name=library_name,
        library_path=library_path,
        patched_imports=tuple(patched_imports),
        libraries=tuple(rewritten.libraries),
        runpath=_collect_runpath(rewritten),
    )


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


def _base_symbol_name(symbol_name: str) -> str:
    return symbol_name.split("@", 1)[0]


__all__ = [
    "PatchedImport",
    "RNG_PATCHER_STEP",
    "RngPatchResult",
    "RngPatcherStep",
    "RngPatcherStepOptions",
    "patch_rng_imports",
]
