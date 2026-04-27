"""Helpers for building the bundled ``libcheckformat.so`` library."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


DEFAULT_CHECKFORMAT_LIBRARY_NAME = "libcheckformat.so"
_BUNDLED_CHECKFORMAT_SOURCE = (
    Path(__file__).resolve().parent / "native" / "libcheckformat.c"
)
_CHECKFORMAT_BUILD_FLAGS = (
    "-shared",
    "-fPIC",
    "-O2",
    "-std=c11",
    "-D_GNU_SOURCE",
    "-Wall",
    "-Wextra",
    "-Werror",
)


def bundled_checkformat_source() -> Path:
    """Return the path to the bundled ``libcheckformat`` C source."""

    return _BUNDLED_CHECKFORMAT_SOURCE


def build_checkformat_library(
    output_directory: Path | str,
    *,
    library_name: str = DEFAULT_CHECKFORMAT_LIBRARY_NAME,
    source_path: Path | str | None = None,
) -> Path:
    """Build ``libcheckformat.so`` into ``output_directory``."""

    compiler = shutil.which("gcc")
    if compiler is None:
        raise RuntimeError("gcc is required to build libcheckformat.so")

    source_file = (
        Path(source_path) if source_path is not None else bundled_checkformat_source()
    )
    if not source_file.is_file():
        raise RuntimeError(f"bundled checkformat source was not found: {source_file}")

    output_dir = Path(output_directory)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / library_name

    command = [
        compiler,
        *_CHECKFORMAT_BUILD_FLAGS,
        f"-Wl,-soname,{library_name}",
        str(source_file),
        "-o",
        str(output_file),
    ]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = (
            result.stderr.strip()
            or result.stdout.strip()
            or "unknown compiler error"
        )
        raise RuntimeError(f"could not build {library_name}: {stderr}")

    return output_file


__all__ = [
    "DEFAULT_CHECKFORMAT_LIBRARY_NAME",
    "build_checkformat_library",
    "bundled_checkformat_source",
]
