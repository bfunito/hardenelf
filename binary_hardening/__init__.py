"""Public API for binary hardening passes.

The root package stays lightweight so internal modules can import
``binary_hardening.elf`` without loading the whole pipeline.
"""

from binary_hardening.pipeline import (
    CompletedStep,
    PipelineResult,
    PipelineStep,
    StepFunction,
)

__all__ = [
    "CompletedStep",
    "PipelineResult",
    "PipelineStep",
    "StepFunction",
    "available_step_names",
    "available_steps",
    "build_steps",
    "initialize_stack_frames",
    "inject_trampolines",
    "patch_format_strings",
    "patch_rng_functions",
    "run_hardening_pipeline",
]


def __getattr__(name: str) -> object:
    if name in {
        "initialize_stack_frames",
        "inject_trampolines",
        "patch_format_strings",
        "patch_rng_functions",
        "run_hardening_pipeline",
    }:
        from binary_hardening import api

        return getattr(api, name)

    if name in {
        "available_step_names",
        "available_steps",
        "build_steps",
    }:
        from binary_hardening import registry

        return getattr(registry, name)

    raise AttributeError(name)
