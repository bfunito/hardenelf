"""Central pipeline API for binary hardening passes."""

from binary_hardening.api import (
    inject_entry_trampolines,
    inject_trampolines,
    patch_format_strings,
    patch_rng_functions,
    run_hardening_pipeline,
    run_injection_pipeline,
)
from binary_hardening.pipeline import CompletedStep, PipelineResult, PipelineStep
from binary_hardening.registry import (
    PipelineOptions,
    StepDefinition,
    available_step_names,
    available_steps,
    build_steps,
)

__all__ = [
    "CompletedStep",
    "PipelineOptions",
    "PipelineResult",
    "PipelineStep",
    "StepDefinition",
    "available_step_names",
    "available_steps",
    "build_steps",
    "inject_entry_trampolines",
    "inject_trampolines",
    "patch_format_strings",
    "patch_rng_functions",
    "run_hardening_pipeline",
    "run_injection_pipeline",
]
