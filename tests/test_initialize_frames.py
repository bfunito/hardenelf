from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import lief

from initialize_frames.step import (
    INITIALIZE_FRAMES_STEP,
    FrameInitializationResult,
    initialize_stack_frames,
)
from binary_hardening.hardenelf import HARDENELF_SECTION
from safe_rng.step import RNG_PATCHER_STEP
from shstk_injector.steps.shadow_stack import SHADOW_STACK_STEP, InjectionResult
from tests.fixture_binaries import (
    BIN_DIR,
    build_fixtures,
    require_injector_dependencies,
    run_binary,
    run_pipeline_fixture,
)


class InitializeFramesTests(unittest.TestCase):
    def test_patched_binary_zeroes_stack_frame(self) -> None:
        input_path, output_path, result = run_pipeline_fixture(
            self,
            "initialize_frames",
            steps=(INITIALIZE_FRAMES_STEP,),
        )

        step_result = result.result_for_step(INITIALIZE_FRAMES_STEP)
        self.assertIsInstance(step_result, FrameInitializationResult)
        assert isinstance(step_result, FrameInitializationResult)

        self.assertNotEqual(run_binary(input_path).returncode, 0)
        self.assertEqual(run_binary(output_path).returncode, 0)
        self.assertGreaterEqual(len(step_result.initialized_frames), 2)

        rewritten = lief.parse(output_path)
        self.assertIsInstance(rewritten, lief.ELF.Binary)
        assert isinstance(rewritten, lief.ELF.Binary)
        self.assertTrue(rewritten.has_section(HARDENELF_SECTION))
        section = rewritten.get_section(HARDENELF_SECTION)
        self.assertIsNotNone(section)
        assert section is not None
        self.assertEqual(section.size % 0x1000, 0)
        self.assertGreaterEqual(section.size, 0x1000)

    def test_patched_pie_binary_zeroes_stack_frame(self) -> None:
        input_path, output_path, _ = run_pipeline_fixture(
            self,
            "initialize_frames_pie",
            steps=(INITIALIZE_FRAMES_STEP,),
        )

        self.assertTrue(_is_pie(input_path))
        self.assertTrue(_is_pie(output_path))
        self.assertNotEqual(run_binary(input_path).returncode, 0)
        self.assertEqual(run_binary(output_path).returncode, 0)

    def test_frame_and_shadow_stack_share_entry_trampolines(self) -> None:
        input_path, output_path, result = run_pipeline_fixture(
            self,
            "initialize_frames",
            steps=(INITIALIZE_FRAMES_STEP, SHADOW_STACK_STEP),
            hardenelf_size=0x6000,
        )

        frame_result = result.result_for_step(INITIALIZE_FRAMES_STEP)
        shadow_result = result.result_for_step(SHADOW_STACK_STEP)
        self.assertIsInstance(frame_result, FrameInitializationResult)
        self.assertIsInstance(shadow_result, InjectionResult)
        assert isinstance(frame_result, FrameInitializationResult)
        assert isinstance(shadow_result, InjectionResult)

        entry_by_function = {
            entry.function_address: entry
            for entry in shadow_result.trampolines
        }
        shared_frames = [
            frame
            for frame in frame_result.initialized_frames
            if frame.function_address in entry_by_function
        ]

        self.assertNotEqual(run_binary(input_path).returncode, 0)
        self.assertEqual(run_binary(output_path).returncode, 0)
        self.assertGreaterEqual(len(shared_frames), 2)
        for frame in shared_frames:
            self.assertEqual(
                frame.trampoline_address,
                entry_by_function[frame.function_address].trampoline_address,
            )

    def test_shared_entry_trampolines_work_when_steps_are_not_adjacent(self) -> None:
        _, output_path, result = run_pipeline_fixture(
            self,
            "initialize_frames",
            steps=(INITIALIZE_FRAMES_STEP, RNG_PATCHER_STEP, SHADOW_STACK_STEP),
            hardenelf_size=0x6000,
        )

        self.assertEqual(
            tuple(step.name for step in result.steps),
            (INITIALIZE_FRAMES_STEP, RNG_PATCHER_STEP, SHADOW_STACK_STEP),
        )
        self.assertEqual(run_binary(output_path).returncode, 0)

    def test_initialize_frames_is_noop_without_stack_allocations(self) -> None:
        build_fixtures(self)
        require_injector_dependencies(self)

        input_path = BIN_DIR / "entry_smoke"
        with TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "entry_smoke.initframes"
            result = initialize_stack_frames(input_path, output_path)

            self.assertEqual(result.initialized_frames, ())
            self.assertEqual(run_binary(output_path).returncode, 0)

            rewritten = lief.parse(output_path)
            self.assertIsInstance(rewritten, lief.ELF.Binary)
            assert isinstance(rewritten, lief.ELF.Binary)
            self.assertFalse(rewritten.has_section(HARDENELF_SECTION))

    def test_trampoline_size_must_be_positive(self) -> None:
        build_fixtures(self)
        require_injector_dependencies(self)

        input_path = BIN_DIR / "initialize_frames"
        with TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "initialize_frames.invalid"

            with self.assertRaisesRegex(
                ValueError,
                "trampoline_size must be greater than zero",
            ):
                initialize_stack_frames(input_path, output_path, trampoline_size=0)


def _is_pie(path: Path) -> bool:
    binary = lief.parse(path)
    assert isinstance(binary, lief.ELF.Binary)
    return bool(binary.is_pie)


if __name__ == "__main__":
    unittest.main()
