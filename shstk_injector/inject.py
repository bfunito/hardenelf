"""Public API for the binary-injection pipeline."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from shstk_injector.pipeline import PipelineResult, run_pipeline
from shstk_injector.return_trampoline import ReturnAddressAction
from shstk_injector.steps import SHADOW_STACK_STEP, build_steps
from shstk_injector.steps.shadow_stack import (
    EntryInjectionResult,
    InjectionResult,
    ShadowStackStepOptions,
    SkippedFunction,
)


def run_injection_pipeline(
    input_path: Path | str,
    output_path: Path | str,
    *,
    steps: Sequence[str] | None = None,
    shadow_stack_options: ShadowStackStepOptions | None = None,
) -> PipelineResult:
    """Run the selected pipeline steps in order."""

    configured_steps = build_steps(
        steps,
        shadow_stack_options=shadow_stack_options,
    )
    return run_pipeline(input_path, output_path, steps=configured_steps)


def inject_trampolines(
    input_path: Path | str,
    output_path: Path | str,
    *,
    shadow_size: int = 0x1000,
    saved_addrs_size: int = 0x1000,
    return_address_action: ReturnAddressAction | str = ReturnAddressAction.RESTORE,
    crash_message: str | bytes | None = None,
) -> InjectionResult:
    """Run the shadow-stack step through the generic pipeline API."""

    result = run_injection_pipeline(
        input_path,
        output_path,
        steps=(SHADOW_STACK_STEP,),
        shadow_stack_options=ShadowStackStepOptions(
            shadow_size=shadow_size,
            saved_addrs_size=saved_addrs_size,
            return_address_action=return_address_action,
            crash_message=crash_message,
        ),
    )
    shadow_stack_result = result.result_for_step(SHADOW_STACK_STEP)
    if not isinstance(shadow_stack_result, InjectionResult):
        raise TypeError("shadow-stack step returned an unexpected result type")
    return shadow_stack_result


def inject_entry_trampolines(
    input_path: Path | str,
    output_path: Path | str,
    *,
    shadow_size: int = 0x1000,
    saved_addrs_size: int = 0x1000,
    return_address_action: ReturnAddressAction | str = ReturnAddressAction.RESTORE,
    crash_message: str | bytes | None = None,
) -> InjectionResult:
    """Backward-compatible name for the full shadow-stack injector."""

    return inject_trampolines(
        input_path,
        output_path,
        shadow_size=shadow_size,
        saved_addrs_size=saved_addrs_size,
        return_address_action=return_address_action,
        crash_message=crash_message,
    )


__all__ = [
    "EntryInjectionResult",
    "InjectionResult",
    "PipelineResult",
    "SHADOW_STACK_STEP",
    "ShadowStackStepOptions",
    "SkippedFunction",
    "inject_entry_trampolines",
    "inject_trampolines",
    "run_injection_pipeline",
]
