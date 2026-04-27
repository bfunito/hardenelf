"""Pipeline step registry."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

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
from shstk_injector.pipeline import PipelineStep

from .shadow_stack import (
    SHADOW_STACK_STEP,
    ShadowStackStep,
    ShadowStackStepOptions,
)


@dataclass(frozen=True)
class StepDefinition:
    """Static metadata for one pipeline step."""

    name: str
    description: str


_STEP_DEFINITIONS = (
    StepDefinition(
        name=SHADOW_STACK_STEP,
        description=ShadowStackStep.description,
    ),
    StepDefinition(
        name=RNG_PATCHER_STEP,
        description=RngPatcherStep.description,
    ),
    StepDefinition(
        name=FMTSTR_CHECKER_STEP,
        description=FmtStrCheckerStep.description,
    ),
)


def available_steps() -> tuple[StepDefinition, ...]:
    """Return the implemented steps in pipeline order."""

    return _STEP_DEFINITIONS


def available_step_names() -> tuple[str, ...]:
    """Return the implemented step names in pipeline order."""

    return tuple(step.name for step in _STEP_DEFINITIONS)


def build_steps(
    step_names: Sequence[str] | None = None,
    *,
    shadow_stack_options: ShadowStackStepOptions | None = None,
    rng_patcher_options: RngPatcherStepOptions | None = None,
    fmtstr_checker_options: FmtStrCheckerStepOptions | None = None,
) -> tuple[PipelineStep, ...]:
    """Instantiate the requested step sequence."""

    normalized_names = _normalize_step_names(step_names)
    configured_shadow_stack = shadow_stack_options or ShadowStackStepOptions()
    configured_rng_patcher = rng_patcher_options or RngPatcherStepOptions()
    configured_fmtstr_checker = fmtstr_checker_options or FmtStrCheckerStepOptions()

    steps: list[PipelineStep] = []
    for step_name in normalized_names:
        if step_name == SHADOW_STACK_STEP:
            steps.append(ShadowStackStep(configured_shadow_stack))
            continue
        if step_name == RNG_PATCHER_STEP:
            steps.append(RngPatcherStep(configured_rng_patcher))
            continue
        if step_name == FMTSTR_CHECKER_STEP:
            steps.append(FmtStrCheckerStep(configured_fmtstr_checker))
            continue
        raise AssertionError(f"unhandled step definition for {step_name!r}")

    return tuple(steps)


def _normalize_step_names(step_names: Sequence[str] | None) -> tuple[str, ...]:
    if step_names is None:
        return available_step_names()

    normalized = tuple(step_names)
    duplicates = tuple(
        step_name
        for index, step_name in enumerate(normalized)
        if step_name in normalized[:index]
    )
    if duplicates:
        repeated = ", ".join(sorted(set(duplicates)))
        raise ValueError(f"pipeline steps must be unique: {repeated}")

    supported = set(available_step_names())
    unknown = tuple(step_name for step_name in normalized if step_name not in supported)
    if unknown:
        supported_list = ", ".join(available_step_names())
        unknown_list = ", ".join(unknown)
        raise ValueError(
            f"unknown pipeline step(s): {unknown_list}; supported steps: {supported_list}"
        )

    return normalized


__all__ = [
    "FMTSTR_CHECKER_STEP",
    "FmtStrCheckerStep",
    "FmtStrCheckerStepOptions",
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
