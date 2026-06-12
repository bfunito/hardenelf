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
