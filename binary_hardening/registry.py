"""Step names, default order, and option binding for the hardening pipeline."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from fmtstr_checker.step import (
    FMTSTR_CHECKER_DESCRIPTION,
    FMTSTR_CHECKER_STEP,
    FmtStrCheckerStepOptions,
    patch_format_strings,
)
from initialize_frames.step import (
    INITIALIZE_FRAMES_DESCRIPTION,
    INITIALIZE_FRAMES_STEP,
    InitializeFramesStepOptions,
    initialize_stack_frames,
)
from safe_rng.step import (
    RNG_PATCHER_DESCRIPTION,
    RNG_PATCHER_STEP,
    RngPatcherStepOptions,
    patch_rng_imports,
)
from shstk_injector.steps.shadow_stack import (
    SHADOW_STACK_DESCRIPTION,
    SHADOW_STACK_STEP,
    ShadowStackStepOptions,
    run_shadow_stack_step,
)

from .pipeline import PipelineStep, StepFunction


_STEPS = (
    (INITIALIZE_FRAMES_STEP, INITIALIZE_FRAMES_DESCRIPTION),
    (SHADOW_STACK_STEP, SHADOW_STACK_DESCRIPTION),
    (RNG_PATCHER_STEP, RNG_PATCHER_DESCRIPTION),
    (FMTSTR_CHECKER_STEP, FMTSTR_CHECKER_DESCRIPTION),
)
_STEP_DESCRIPTIONS = dict(_STEPS)
_STEP_NAMES = tuple(name for name, _ in _STEPS)


def available_steps() -> tuple[tuple[str, str], ...]:
    """Return ``(name, description)`` pairs in default pipeline order."""

    return _STEPS


def available_step_names() -> tuple[str, ...]:
    """Return implemented step names in default pipeline order."""

    return _STEP_NAMES


def build_steps(
    step_names: Sequence[str] | None = None,
    *,
    shadow_stack_options: ShadowStackStepOptions | None = None,
    initialize_frames_options: InitializeFramesStepOptions | None = None,
    rng_patcher_options: RngPatcherStepOptions | None = None,
    fmtstr_checker_options: FmtStrCheckerStepOptions | None = None,
) -> tuple[PipelineStep, ...]:
    """Bind selected step names to concrete runner functions."""

    selected_names = _normalize_step_names(step_names)
    runners = {
        INITIALIZE_FRAMES_STEP: _initialize_frames_runner(
            initialize_frames_options or InitializeFramesStepOptions()
        ),
        SHADOW_STACK_STEP: _shadow_stack_runner(
            shadow_stack_options or ShadowStackStepOptions()
        ),
        RNG_PATCHER_STEP: _rng_patcher_runner(
            rng_patcher_options or RngPatcherStepOptions()
        ),
        FMTSTR_CHECKER_STEP: _fmtstr_checker_runner(
            fmtstr_checker_options or FmtStrCheckerStepOptions()
        ),
    }
    return tuple((name, runners[name]) for name in selected_names)


def _initialize_frames_runner(options: InitializeFramesStepOptions) -> StepFunction:
    def run(input_path: Path | str, output_path: Path | str) -> object:
        return initialize_stack_frames(
            input_path,
            output_path,
            trampoline_size=options.trampoline_size,
        )

    return run


def _shadow_stack_runner(options: ShadowStackStepOptions) -> StepFunction:
    def run(input_path: Path | str, output_path: Path | str) -> object:
        return run_shadow_stack_step(input_path, output_path, options=options)

    return run


def _rng_patcher_runner(options: RngPatcherStepOptions) -> StepFunction:
    def run(input_path: Path | str, output_path: Path | str) -> object:
        return patch_rng_imports(
            input_path,
            output_path,
            library_name=options.library_name,
            source_path=options.source_path,
        )

    return run


def _fmtstr_checker_runner(options: FmtStrCheckerStepOptions) -> StepFunction:
    def run(input_path: Path | str, output_path: Path | str) -> object:
        return patch_format_strings(
            input_path,
            output_path,
            trampoline_size=options.trampoline_size,
            library_name=options.library_name,
            source_path=options.source_path,
        )

    return run


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

    unknown = tuple(
        step_name for step_name in normalized if step_name not in _STEP_DESCRIPTIONS
    )
    if unknown:
        supported_list = ", ".join(available_step_names())
        unknown_list = ", ".join(unknown)
        raise ValueError(
            f"unknown pipeline step(s): {unknown_list}; supported steps: {supported_list}"
        )

    return normalized


__all__ = [
    "FMTSTR_CHECKER_STEP",
    "FmtStrCheckerStepOptions",
    "INITIALIZE_FRAMES_STEP",
    "InitializeFramesStepOptions",
    "RNG_PATCHER_STEP",
    "RngPatcherStepOptions",
    "SHADOW_STACK_STEP",
    "ShadowStackStepOptions",
    "available_step_names",
    "available_steps",
    "build_steps",
]
