"""Backward-compatible imports for pipeline primitives."""

from binary_hardening.pipeline import (
    CompletedStep,
    PipelineResult,
    PipelineStep,
    run_pipeline,
)

__all__ = [
    "CompletedStep",
    "PipelineResult",
    "PipelineStep",
    "run_pipeline",
]
