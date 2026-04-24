"""Helpers for building the bundled ``libsaferand.so`` library."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


DEFAULT_SAFERAND_LIBRARY_NAME = "libsaferand.so"
_BUNDLED_SAFERAND_SOURCE = Path(__file__).resolve().parent / "native" / "libsaferand.c"
_SAFERAND_BUILD_FLAGS = (
    "-shared",
    "-fPIC",
    "-O2",
    "-std=c11",
    "-D_GNU_SOURCE",
    "-Wall",
    "-Wextra",
    "-Werror",
)


def bundled_saferand_source() -> Path:
    """Return the path to the bundled ``libsaferand`` C source."""

    return _BUNDLED_SAFERAND_SOURCE


def build_saferand_library(
    output_directory: Path | str,
    *,
    library_name: str = DEFAULT_SAFERAND_LIBRARY_NAME,
    source_path: Path | str | None = None,
) -> Path:
    """Build ``libsaferand.so`` into ``output_directory``."""

    compiler = shutil.which("gcc")
    if compiler is None:
        raise RuntimeError("gcc is required to build libsaferand.so")

    source_file = Path(source_path) if source_path is not None else bundled_saferand_source()
    if not source_file.is_file():
        raise RuntimeError(f"bundled saferand source was not found: {source_file}")

    output_dir = Path(output_directory)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / library_name

    command = [
        compiler,
        *_SAFERAND_BUILD_FLAGS,
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
        stderr = result.stderr.strip() or result.stdout.strip() or "unknown compiler error"
        raise RuntimeError(f"could not build {library_name}: {stderr}")

    return output_file


__all__ = [
    "DEFAULT_SAFERAND_LIBRARY_NAME",
    "build_saferand_library",
    "bundled_saferand_source",
]
