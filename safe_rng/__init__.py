"""Modular RNG hardening step and bundled saferand library."""

from safe_rng.saferand import (
    DEFAULT_SAFERAND_LIBRARY_NAME,
    build_saferand_library,
    bundled_saferand_source,
)
from safe_rng.step import (
    PatchedImport,
    RNG_PATCHER_STEP,
    RngPatchResult,
    RngPatcherStep,
    RngPatcherStepOptions,
    patch_rng_imports,
)

__all__ = [
    "DEFAULT_SAFERAND_LIBRARY_NAME",
    "PatchedImport",
    "RNG_PATCHER_STEP",
    "RngPatchResult",
    "RngPatcherStep",
    "RngPatcherStepOptions",
    "build_saferand_library",
    "bundled_saferand_source",
    "patch_rng_imports",
]
