"""Pipeline primitives for composing binary rewriting steps."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class PipelineStep(Protocol):
    """A single binary-rewriting pass in the hardening pipeline."""

    name: str
    description: str

    def run(self, input_path: Path | str, output_path: Path | str) -> object:
        """Rewrite ``input_path`` into ``output_path``."""


@dataclass(frozen=True)
class CompletedStep:
    """One pipeline step and its execution summary."""

    name: str
    description: str
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
    """Run the selected pipeline steps in the exact order provided.

    Each step writes to the same output path so later steps can keep patching the
    already-rewritten binary. The original input path is only used for the first
    step.
    """

    selected_steps = tuple(steps)
    if not selected_steps:
        raise ValueError("pipeline must contain at least one step")

    final_output = Path(output_path)
    current_input = Path(input_path)
    completed: list[CompletedStep] = []

    for step in selected_steps:
        result = step.run(current_input, final_output)
        completed.append(
            CompletedStep(
                name=step.name,
                description=step.description,
                result=result,
            )
        )
        current_input = final_output

    return PipelineResult(output_path=final_output, steps=tuple(completed))


__all__ = [
    "CompletedStep",
    "PipelineResult",
    "PipelineStep",
    "run_pipeline",
]
