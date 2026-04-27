from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from binary_hardening.pipeline import run_pipeline
from binary_hardening.registry import (
    FMTSTR_CHECKER_STEP,
    RNG_PATCHER_STEP,
    SHADOW_STACK_STEP,
    available_step_names,
    build_steps,
)
from fmtstr_checker.step import FmtStrCheckerStep, FmtStrCheckerStepOptions
from safe_rng.step import RngPatcherStep, RngPatcherStepOptions
from shstk_injector.steps import available_step_names as legacy_step_names
from shstk_injector.steps.shadow_stack import ShadowStackStep, ShadowStackStepOptions


@dataclass(frozen=True)
class _MarkerStep:
    name: str
    description: str
    marker: str

    def run(self, input_path: Path | str, output_path: Path | str) -> dict[str, str]:
        input_file = Path(input_path)
        output_file = Path(output_path)
        output_file.write_text(input_file.read_text() + self.marker)
        return {"marker": self.marker}


class PipelineTests(unittest.TestCase):
    def test_pipeline_runs_steps_in_order(self) -> None:
        with TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            input_path = tmpdir_path / "input.txt"
            output_path = tmpdir_path / "output.txt"
            input_path.write_text("seed")

            result = run_pipeline(
                input_path,
                output_path,
                steps=(
                    _MarkerStep("first", "append first marker", "-a"),
                    _MarkerStep("second", "append second marker", "-b"),
                ),
            )

            self.assertEqual(output_path.read_text(), "seed-a-b")
            self.assertEqual(result.output_path, output_path)
            self.assertEqual(tuple(step.name for step in result.steps), ("first", "second"))

    def test_pipeline_requires_at_least_one_step(self) -> None:
        with TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            input_path = tmpdir_path / "input.txt"
            output_path = tmpdir_path / "output.txt"
            input_path.write_text("seed")

            with self.assertRaisesRegex(ValueError, "at least one step"):
                run_pipeline(input_path, output_path, steps=())


class StepRegistryTests(unittest.TestCase):
    def test_registry_returns_all_steps_by_default(self) -> None:
        steps = build_steps()

        self.assertEqual(tuple(step.name for step in steps), available_step_names())

    def test_registry_preserves_user_defined_step_order(self) -> None:
        steps = build_steps(
            (
                FMTSTR_CHECKER_STEP,
                RNG_PATCHER_STEP,
                SHADOW_STACK_STEP,
            )
        )

        self.assertEqual(
            tuple(step.name for step in steps),
            (
                FMTSTR_CHECKER_STEP,
                RNG_PATCHER_STEP,
                SHADOW_STACK_STEP,
            ),
        )

    def test_legacy_step_registry_delegates_to_central_registry(self) -> None:
        self.assertEqual(legacy_step_names(), available_step_names())

    def test_registry_builds_configured_shadow_stack_step(self) -> None:
        step = build_steps(
            (SHADOW_STACK_STEP,),
            shadow_stack_options=ShadowStackStepOptions(expand_only=True),
        )[0]

        self.assertIsInstance(step, ShadowStackStep)
        assert isinstance(step, ShadowStackStep)
        self.assertTrue(step.options.expand_only)

    def test_registry_builds_configured_rng_patcher_step(self) -> None:
        step = build_steps(
            (RNG_PATCHER_STEP,),
            rng_patcher_options=RngPatcherStepOptions(library_name="custom.so"),
        )[0]

        self.assertIsInstance(step, RngPatcherStep)
        assert isinstance(step, RngPatcherStep)
        self.assertEqual(step.options.library_name, "custom.so")

    def test_registry_builds_configured_fmtstr_checker_step(self) -> None:
        step = build_steps(
            (FMTSTR_CHECKER_STEP,),
            fmtstr_checker_options=FmtStrCheckerStepOptions(
                trampoline_size=0x8000,
            ),
        )[0]

        self.assertIsInstance(step, FmtStrCheckerStep)
        assert isinstance(step, FmtStrCheckerStep)
        self.assertEqual(step.options.trampoline_size, 0x8000)

    def test_registry_rejects_duplicate_steps(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be unique"):
            build_steps((SHADOW_STACK_STEP, SHADOW_STACK_STEP))

    def test_registry_rejects_unknown_steps(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown pipeline step"):
            build_steps(("format-string-checker",))


if __name__ == "__main__":
    unittest.main()
