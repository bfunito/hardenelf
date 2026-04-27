"""Backward-compatible access to registered pipeline steps."""

from __future__ import annotations

from collections.abc import Sequence

from fmtstr_checker.step import (
    FMTSTR_CHECKER_STEP,
    FmtStrCheckerStep,
    FmtStrCheckerStepOptions,
)
from safe_rng.step import (
    RNG_PATCHER_STEP,
    RngPatcherStep,
    RngPatcherStepOptions,
)

from .shadow_stack import (
    SHADOW_STACK_STEP,
    ShadowStackStep,
    ShadowStackStepOptions,
)


def available_steps() -> tuple[object, ...]:
    """Return registered steps from the central registry."""

    from binary_hardening.registry import available_steps as _available_steps

    return _available_steps()


def available_step_names() -> tuple[str, ...]:
    """Return registered step names from the central registry."""

    from binary_hardening.registry import (
        available_step_names as _available_step_names,
    )

    return _available_step_names()


def build_steps(
    step_names: Sequence[str] | None = None,
    **kwargs: object,
) -> tuple[object, ...]:
    """Instantiate steps through the central registry."""

    from binary_hardening.registry import build_steps as _build_steps

    return _build_steps(step_names, **kwargs)


def __getattr__(name: str) -> object:
    if name in {"PipelineOptions", "StepDefinition"}:
        from binary_hardening import registry

        return getattr(registry, name)
    raise AttributeError(name)


__all__ = [
    "FMTSTR_CHECKER_STEP",
    "FmtStrCheckerStep",
    "FmtStrCheckerStepOptions",
    "PipelineOptions",
    "RNG_PATCHER_STEP",
    "RngPatcherStep",
    "RngPatcherStepOptions",
    "SHADOW_STACK_STEP",
    "ShadowStackStep",
    "ShadowStackStepOptions",
    "StepDefinition",
    "available_step_names",
    "available_steps",
    "build_steps",
]
