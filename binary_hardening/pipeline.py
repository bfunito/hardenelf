"""Small pipeline runner for binary rewriting functions."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


StepFunction = Callable[[Path | str, Path | str], object]
PipelineStep = tuple[str, StepFunction]


@dataclass(frozen=True)
class CompletedStep:
    """One pipeline step and its execution summary."""

    name: str
    result: object


@dataclass(frozen=True)
class PipelineResult:
    """Summary returned after executing a pipeline."""

    output_path: Path
    steps: tuple[CompletedStep, ...]

    def result_for_step(self, step_name: str) -> object:
        """Return the summary produced by ``step_name``."""

        for step in self.steps:
            if step.name == step_name:
                return step.result
        raise KeyError(f"pipeline step {step_name!r} was not executed")


def run_pipeline(
    input_path: Path | str,
    output_path: Path | str,
    *,
    steps: Sequence[PipelineStep],
) -> PipelineResult:
    """Run ``steps`` in order.

    Each function writes to ``output_path``. Later functions read that same file
    so they keep patching the already rewritten binary.
    """

    selected_steps = tuple(steps)
    if not selected_steps:
        raise ValueError("pipeline must contain at least one step")

    final_output = Path(output_path)
    current_input = Path(input_path)
    completed: list[CompletedStep] = []

    for name, run_step in selected_steps:
        result = run_step(current_input, final_output)
        completed.append(
            CompletedStep(
                name=name,
                result=result,
            )
        )
        current_input = final_output

    return PipelineResult(output_path=final_output, steps=tuple(completed))


__all__ = [
    "CompletedStep",
    "PipelineResult",
    "PipelineStep",
    "StepFunction",
    "run_pipeline",
]
