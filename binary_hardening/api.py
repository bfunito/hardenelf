"""Public API for the binary hardening pipeline."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from fmtstr_checker.step import (
    FMTSTR_CHECKER_STEP,
    FmtStrCheckerStepOptions,
    FmtStrPatchResult,
)
from initialize_frames.step import (
    INITIALIZE_FRAMES_STEP,
    FrameInitializationResult,
    InitializeFramesStepOptions,
)
from safe_rng.step import RNG_PATCHER_STEP, RngPatchResult, RngPatcherStepOptions
from shstk_injector.return_trampoline import ReturnAddressAction
from shstk_injector.steps.shadow_stack import (
    SHADOW_STACK_STEP,
    EntryInjectionResult,
    InjectionResult,
    ShadowStackStepOptions,
    SkippedFunction,
)

from .pipeline import PipelineResult, run_pipeline
from .registry import PipelineOptions, build_steps


def run_hardening_pipeline(
    input_path: Path | str,
    output_path: Path | str,
    *,
    steps: Sequence[str] | None = None,
    options: PipelineOptions | None = None,
    shadow_stack_options: ShadowStackStepOptions | None = None,
    initialize_frames_options: InitializeFramesStepOptions | None = None,
    rng_patcher_options: RngPatcherStepOptions | None = None,
    fmtstr_checker_options: FmtStrCheckerStepOptions | None = None,
) -> PipelineResult:
    """Run selected hardening steps in the order provided by ``steps``."""

    configured_steps = build_steps(
        steps,
        options=options,
        shadow_stack_options=shadow_stack_options,
        initialize_frames_options=initialize_frames_options,
        rng_patcher_options=rng_patcher_options,
        fmtstr_checker_options=fmtstr_checker_options,
    )
    return run_pipeline(input_path, output_path, steps=configured_steps)


def run_injection_pipeline(
    input_path: Path | str,
    output_path: Path | str,
    *,
    steps: Sequence[str] | None = None,
    options: PipelineOptions | None = None,
    shadow_stack_options: ShadowStackStepOptions | None = None,
    initialize_frames_options: InitializeFramesStepOptions | None = None,
    rng_patcher_options: RngPatcherStepOptions | None = None,
    fmtstr_checker_options: FmtStrCheckerStepOptions | None = None,
) -> PipelineResult:
    """Backward-compatible alias for ``run_hardening_pipeline``."""

    return run_hardening_pipeline(
        input_path,
        output_path,
        steps=steps,
        options=options,
        shadow_stack_options=shadow_stack_options,
        initialize_frames_options=initialize_frames_options,
        rng_patcher_options=rng_patcher_options,
        fmtstr_checker_options=fmtstr_checker_options,
    )


def inject_trampolines(
    input_path: Path | str,
    output_path: Path | str,
    *,
    shadow_size: int = 0x1000,
    saved_addrs_size: int = 0x1000,
    return_address_action: ReturnAddressAction | str = ReturnAddressAction.RESTORE,
    crash_message: str | bytes | None = None,
) -> InjectionResult:
    """Run only the shadow-stack step."""

    result = run_hardening_pipeline(
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


def patch_rng_functions(
    input_path: Path | str,
    output_path: Path | str,
    *,
    library_name: str = "libsaferand.so",
    source_path: Path | str | None = None,
) -> RngPatchResult:
    """Run only the RNG patcher step."""

    result = run_hardening_pipeline(
        input_path,
        output_path,
        steps=(RNG_PATCHER_STEP,),
        rng_patcher_options=RngPatcherStepOptions(
            library_name=library_name,
            source_path=source_path,
        ),
    )
    rng_result = result.result_for_step(RNG_PATCHER_STEP)
    if not isinstance(rng_result, RngPatchResult):
        raise TypeError("rng-patcher step returned an unexpected result type")
    return rng_result


def initialize_stack_frames(
    input_path: Path | str,
    output_path: Path | str,
    *,
    trampoline_size: int = 0x4000,
) -> FrameInitializationResult:
    """Run only the stack-frame initialization step."""

    result = run_hardening_pipeline(
        input_path,
        output_path,
        steps=(INITIALIZE_FRAMES_STEP,),
        initialize_frames_options=InitializeFramesStepOptions(
            trampoline_size=trampoline_size,
        ),
    )
    frame_result = result.result_for_step(INITIALIZE_FRAMES_STEP)
    if not isinstance(frame_result, FrameInitializationResult):
        raise TypeError("initialize-frames step returned an unexpected result type")
    return frame_result


def patch_format_strings(
    input_path: Path | str,
    output_path: Path | str,
    *,
    trampoline_size: int = 0x4000,
    library_name: str = "libcheckformat.so",
    source_path: Path | str | None = None,
) -> FmtStrPatchResult:
    """Run only the format-string checker step."""

    result = run_hardening_pipeline(
        input_path,
        output_path,
        steps=(FMTSTR_CHECKER_STEP,),
        fmtstr_checker_options=FmtStrCheckerStepOptions(
            trampoline_size=trampoline_size,
            library_name=library_name,
            source_path=source_path,
        ),
    )
    fmtstr_result = result.result_for_step(FMTSTR_CHECKER_STEP)
    if not isinstance(fmtstr_result, FmtStrPatchResult):
        raise TypeError("fmtstr-checker step returned an unexpected result type")
    return fmtstr_result


__all__ = [
    "EntryInjectionResult",
    "FMTSTR_CHECKER_STEP",
    "INITIALIZE_FRAMES_STEP",
    "FrameInitializationResult",
    "FmtStrCheckerStepOptions",
    "FmtStrPatchResult",
    "InitializeFramesStepOptions",
    "InjectionResult",
    "PipelineOptions",
    "PipelineResult",
    "RNG_PATCHER_STEP",
    "RngPatchResult",
    "RngPatcherStepOptions",
    "SHADOW_STACK_STEP",
    "ShadowStackStepOptions",
    "SkippedFunction",
    "initialize_stack_frames",
    "inject_entry_trampolines",
    "inject_trampolines",
    "patch_format_strings",
    "patch_rng_functions",
    "run_hardening_pipeline",
    "run_injection_pipeline",
]
