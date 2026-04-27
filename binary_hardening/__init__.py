"""Central pipeline API for binary hardening passes."""

from binary_hardening.pipeline import CompletedStep, PipelineResult, PipelineStep

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


def __getattr__(name: str) -> object:
    if name in {
        "inject_entry_trampolines",
        "inject_trampolines",
        "patch_format_strings",
        "patch_rng_functions",
        "run_hardening_pipeline",
        "run_injection_pipeline",
    }:
        from binary_hardening import api

        return getattr(api, name)

    if name in {
        "PipelineOptions",
        "StepDefinition",
        "available_step_names",
        "available_steps",
        "build_steps",
    }:
        from binary_hardening import registry

        return getattr(registry, name)

    raise AttributeError(name)
