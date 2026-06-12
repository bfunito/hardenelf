from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from binary_hardening.pipeline import run_pipeline
from binary_hardening.registry import (
    FMTSTR_CHECKER_STEP,
    INITIALIZE_FRAMES_STEP,
    RNG_PATCHER_STEP,
    SHADOW_STACK_STEP,
    available_step_names,
    build_steps,
)
from fmtstr_checker.step import FmtStrCheckerStepOptions
from initialize_frames.step import InitializeFramesStepOptions
from safe_rng.step import RngPatcherStepOptions
from shstk_injector.steps.shadow_stack import ShadowStackStepOptions


def _append_marker(marker: str):
    def run(input_path: Path | str, output_path: Path | str) -> dict[str, str]:
        input_file = Path(input_path)
        output_file = Path(output_path)
        output_file.write_text(input_file.read_text() + marker)
        return {"marker": marker}

    return run


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
                    ("first", _append_marker("-a")),
                    ("second", _append_marker("-b")),
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

        self.assertEqual(tuple(step[0] for step in steps), available_step_names())

    def test_registry_preserves_user_defined_step_order(self) -> None:
        steps = build_steps(
            (
                FMTSTR_CHECKER_STEP,
                RNG_PATCHER_STEP,
                INITIALIZE_FRAMES_STEP,
                SHADOW_STACK_STEP,
            )
        )

        self.assertEqual(
            tuple(step[0] for step in steps),
            (
                FMTSTR_CHECKER_STEP,
                RNG_PATCHER_STEP,
                INITIALIZE_FRAMES_STEP,
                SHADOW_STACK_STEP,
            ),
        )

    def test_registry_binds_configured_shadow_stack_runner(self) -> None:
        step = build_steps(
            (SHADOW_STACK_STEP,),
            shadow_stack_options=ShadowStackStepOptions(
                hardenelf_size=0x8000,
                expand_only=True,
            ),
        )[0]

        with patch("binary_hardening.registry.run_shadow_stack_step") as run_step:
            step[1]("input", "output")

        options = run_step.call_args.kwargs["options"]
        self.assertTrue(options.expand_only)
        self.assertEqual(options.hardenelf_size, 0x8000)

    def test_registry_binds_configured_rng_patcher_runner(self) -> None:
        step = build_steps(
            (RNG_PATCHER_STEP,),
            rng_patcher_options=RngPatcherStepOptions(library_name="custom.so"),
        )[0]

        with patch("binary_hardening.registry.patch_rng_imports") as patch_rng:
            step[1]("input", "output")

        patch_rng.assert_called_once_with(
            "input",
            "output",
            library_name="custom.so",
            source_path=None,
        )

    def test_registry_binds_configured_initialize_frames_runner(self) -> None:
        step = build_steps(
            (INITIALIZE_FRAMES_STEP,),
            initialize_frames_options=InitializeFramesStepOptions(
                trampoline_size=0x8000,
            ),
        )[0]

        with patch("binary_hardening.registry.initialize_stack_frames") as initialize:
            step[1]("input", "output")

        initialize.assert_called_once_with(
            "input",
            "output",
            trampoline_size=0x8000,
        )

    def test_registry_binds_configured_fmtstr_checker_runner(self) -> None:
        step = build_steps(
            (FMTSTR_CHECKER_STEP,),
            fmtstr_checker_options=FmtStrCheckerStepOptions(
                trampoline_size=0x8000,
            ),
        )[0]

        with patch("binary_hardening.registry.patch_format_strings") as patch_fmtstr:
            step[1]("input", "output")

        patch_fmtstr.assert_called_once_with(
            "input",
            "output",
            trampoline_size=0x8000,
            library_name="libcheckformat.so",
            source_path=None,
        )

    def test_registry_rejects_duplicate_steps(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be unique"):
            build_steps((SHADOW_STACK_STEP, SHADOW_STACK_STEP))

    def test_registry_rejects_unknown_steps(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown pipeline step"):
            build_steps(("format-string-checker",))


if __name__ == "__main__":
    unittest.main()
