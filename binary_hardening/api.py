"""Public API for the binary hardening pipeline."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from fmtstr_checker.step import (
    FMTSTR_CHECKER_STEP,
    FmtStrCheckerStepOptions,
    FmtStrPatchResult,
    patch_format_strings as patch_format_string_calls,
)
from initialize_frames.step import (
    INITIALIZE_FRAMES_STEP,
    FrameInitializationResult,
    InitializeFramesStepOptions,
    initialize_stack_frames as initialize_frames_in_binary,
)
from safe_rng.step import (
    RNG_PATCHER_STEP,
    RngPatchResult,
    RngPatcherStepOptions,
    patch_rng_imports,
)
from binary_hardening.exit_trampoline import ReturnAddressAction
from shstk_injector.steps.shadow_stack import (
    SHADOW_STACK_STEP,
    InjectionResult,
    ShadowStackStepOptions,
    SkippedFunction,
    TrapFallbackDecision,
    inject_shadow_stack_and_initialize_frames,
    inject_shadow_stack,
)

from .pipeline import CompletedStep, PipelineResult, run_pipeline
from .registry import build_steps


def run_hardening_pipeline(
    input_path: Path | str,
    output_path: Path | str,
    *,
    steps: Sequence[str] | None = None,
    shadow_stack_options: ShadowStackStepOptions | None = None,
    initialize_frames_options: InitializeFramesStepOptions | None = None,
    rng_patcher_options: RngPatcherStepOptions | None = None,
    fmtstr_checker_options: FmtStrCheckerStepOptions | None = None,
) -> PipelineResult:
    """Run selected hardening steps in the order provided by ``steps``."""

    configured_steps = build_steps(
        steps,
        shadow_stack_options=shadow_stack_options,
        initialize_frames_options=initialize_frames_options,
        rng_patcher_options=rng_patcher_options,
        fmtstr_checker_options=fmtstr_checker_options,
    )
    selected_names = tuple(name for name, _ in configured_steps)

    if _can_share_entry_trampolines(selected_names, shadow_stack_options):
        return _run_pipeline_with_shared_entry_trampolines(
            input_path,
            output_path,
            selected_names=selected_names,
            shadow_stack_options=shadow_stack_options or ShadowStackStepOptions(),
            initialize_frames_options=(
                initialize_frames_options or InitializeFramesStepOptions()
            ),
            rng_patcher_options=rng_patcher_options,
            fmtstr_checker_options=fmtstr_checker_options,
        )

    return run_pipeline(input_path, output_path, steps=configured_steps)


def _can_share_entry_trampolines(
    selected_names: tuple[str, ...],
    shadow_stack_options: ShadowStackStepOptions | None,
) -> bool:
    if INITIALIZE_FRAMES_STEP not in selected_names:
        return False
    if SHADOW_STACK_STEP not in selected_names:
        return False
    if shadow_stack_options is not None and shadow_stack_options.expand_only:
        return False

    left = selected_names.index(INITIALIZE_FRAMES_STEP)
    right = selected_names.index(SHADOW_STACK_STEP)
    return abs(left - right) == 1


def _run_pipeline_with_shared_entry_trampolines(
    input_path: Path | str,
    output_path: Path | str,
    *,
    selected_names: tuple[str, ...],
    shadow_stack_options: ShadowStackStepOptions,
    initialize_frames_options: InitializeFramesStepOptions,
    rng_patcher_options: RngPatcherStepOptions | None,
    fmtstr_checker_options: FmtStrCheckerStepOptions | None,
) -> PipelineResult:
    final_output = Path(output_path)
    current_input = Path(input_path)
    completed: list[CompletedStep] = []
    index = 0

    while index < len(selected_names):
        name = selected_names[index]
        next_name = (
            selected_names[index + 1]
            if index + 1 < len(selected_names)
            else None
        )
        pair = {name, next_name}
        if pair == {INITIALIZE_FRAMES_STEP, SHADOW_STACK_STEP}:
            hardenelf_size = shadow_stack_options.hardenelf_size
            if hardenelf_size is None:
                hardenelf_size = initialize_frames_options.trampoline_size
            shadow_result, frame_result = inject_shadow_stack_and_initialize_frames(
                current_input,
                final_output,
                hardenelf_size=hardenelf_size,
                saved_addrs_size=shadow_stack_options.saved_addrs_size,
                return_address_action=shadow_stack_options.return_address_action,
                crash_message=shadow_stack_options.crash_message,
                trap_fallback=shadow_stack_options.trap_fallback,
                trap_fallback_callback=shadow_stack_options.trap_fallback_callback,
            )
            results = {
                INITIALIZE_FRAMES_STEP: frame_result,
                SHADOW_STACK_STEP: shadow_result,
            }
            completed.append(CompletedStep(name, results[name]))
            assert next_name is not None
            completed.append(CompletedStep(next_name, results[next_name]))
            current_input = final_output
            index += 2
            continue

        runner = build_steps(
            (name,),
            shadow_stack_options=shadow_stack_options,
            initialize_frames_options=initialize_frames_options,
            rng_patcher_options=rng_patcher_options,
            fmtstr_checker_options=fmtstr_checker_options,
        )[0][1]
        completed.append(CompletedStep(name, runner(current_input, final_output)))
        current_input = final_output
        index += 1

    return PipelineResult(output_path=final_output, steps=tuple(completed))


def inject_trampolines(
    input_path: Path | str,
    output_path: Path | str,
    *,
    hardenelf_size: int | None = None,
    saved_addrs_size: int = 0x1000,
    return_address_action: ReturnAddressAction | str = ReturnAddressAction.RESTORE,
    crash_message: str | bytes | None = None,
    trap_fallback: TrapFallbackDecision | str = TrapFallbackDecision.ASK,
) -> InjectionResult:
    """Inject shadow-stack entry and return trampolines."""

    return inject_shadow_stack(
        input_path,
        output_path,
        hardenelf_size=hardenelf_size,
        saved_addrs_size=saved_addrs_size,
        return_address_action=return_address_action,
        crash_message=crash_message,
        trap_fallback=trap_fallback,
    )


def patch_rng_functions(
    input_path: Path | str,
    output_path: Path | str,
    *,
    library_name: str = "libsaferand.so",
    source_path: Path | str | None = None,
) -> RngPatchResult:
    """Rewrite unsafe RNG imports to the bundled saferand library."""

    return patch_rng_imports(
        input_path,
        output_path,
        library_name=library_name,
        source_path=source_path,
    )


def initialize_stack_frames(
    input_path: Path | str,
    output_path: Path | str,
    *,
    trampoline_size: int | None = None,
) -> FrameInitializationResult:
    """Zero stack-frame storage in canonical frame-pointer functions."""

    return initialize_frames_in_binary(
        input_path,
        output_path,
        trampoline_size=trampoline_size,
    )


def patch_format_strings(
    input_path: Path | str,
    output_path: Path | str,
    *,
    trampoline_size: int | None = None,
    library_name: str = "libcheckformat.so",
    source_path: Path | str | None = None,
) -> FmtStrPatchResult:
    """Patch printf-like calls through runtime format-string checks."""

    return patch_format_string_calls(
        input_path,
        output_path,
        trampoline_size=trampoline_size,
        library_name=library_name,
        source_path=source_path,
    )


__all__ = [
    "FMTSTR_CHECKER_STEP",
    "INITIALIZE_FRAMES_STEP",
    "FrameInitializationResult",
    "FmtStrCheckerStepOptions",
    "FmtStrPatchResult",
    "InitializeFramesStepOptions",
    "InjectionResult",
    "PipelineResult",
    "RNG_PATCHER_STEP",
    "RngPatchResult",
    "RngPatcherStepOptions",
    "SHADOW_STACK_STEP",
    "ShadowStackStepOptions",
    "SkippedFunction",
    "initialize_stack_frames",
    "inject_trampolines",
    "patch_format_strings",
    "patch_rng_functions",
    "run_hardening_pipeline",
]
