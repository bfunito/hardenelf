"""Central registry for binary hardening pipeline steps."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

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
from shstk_injector.steps.shadow_stack import (
    SHADOW_STACK_STEP,
    ShadowStackStep,
    ShadowStackStepOptions,
)

from .pipeline import PipelineStep


@dataclass(frozen=True)
class PipelineOptions:
    """Configuration for all registered pipeline steps."""

    shadow_stack: ShadowStackStepOptions = field(default_factory=ShadowStackStepOptions)
    rng_patcher: RngPatcherStepOptions = field(default_factory=RngPatcherStepOptions)
    fmtstr_checker: FmtStrCheckerStepOptions = field(
        default_factory=FmtStrCheckerStepOptions
    )


@dataclass(frozen=True)
class StepDefinition:
    """Static metadata and factory for one pipeline step."""

    name: str
    description: str
    build: Callable[[PipelineOptions], PipelineStep]


_STEP_DEFINITIONS = (
    StepDefinition(
        name=SHADOW_STACK_STEP,
        description=ShadowStackStep.description,
        build=lambda options: ShadowStackStep(options.shadow_stack),
    ),
    StepDefinition(
        name=RNG_PATCHER_STEP,
        description=RngPatcherStep.description,
        build=lambda options: RngPatcherStep(options.rng_patcher),
    ),
    StepDefinition(
        name=FMTSTR_CHECKER_STEP,
        description=FmtStrCheckerStep.description,
        build=lambda options: FmtStrCheckerStep(options.fmtstr_checker),
    ),
)
_STEP_DEFINITIONS_BY_NAME = {definition.name: definition for definition in _STEP_DEFINITIONS}


def available_steps() -> tuple[StepDefinition, ...]:
    """Return the implemented steps in default pipeline order."""

    return _STEP_DEFINITIONS


def available_step_names() -> tuple[str, ...]:
    """Return the implemented step names in default pipeline order."""

    return tuple(step.name for step in _STEP_DEFINITIONS)


def build_steps(
    step_names: Sequence[str] | None = None,
    *,
    options: PipelineOptions | None = None,
    shadow_stack_options: ShadowStackStepOptions | None = None,
    rng_patcher_options: RngPatcherStepOptions | None = None,
    fmtstr_checker_options: FmtStrCheckerStepOptions | None = None,
) -> tuple[PipelineStep, ...]:
    """Instantiate ``step_names`` in the exact order requested."""

    normalized_names = _normalize_step_names(step_names)
    configured_options = _merge_options(
        options,
        shadow_stack_options=shadow_stack_options,
        rng_patcher_options=rng_patcher_options,
        fmtstr_checker_options=fmtstr_checker_options,
    )
    return tuple(
        _STEP_DEFINITIONS_BY_NAME[step_name].build(configured_options)
        for step_name in normalized_names
    )


def _merge_options(
    options: PipelineOptions | None,
    *,
    shadow_stack_options: ShadowStackStepOptions | None,
    rng_patcher_options: RngPatcherStepOptions | None,
    fmtstr_checker_options: FmtStrCheckerStepOptions | None,
) -> PipelineOptions:
    base = options or PipelineOptions()
    return PipelineOptions(
        shadow_stack=shadow_stack_options or base.shadow_stack,
        rng_patcher=rng_patcher_options or base.rng_patcher,
        fmtstr_checker=fmtstr_checker_options or base.fmtstr_checker,
    )


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
