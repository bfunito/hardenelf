from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import unittest

from binary_hardening.cli import _parse_shadow_size, _print_step_result
from initialize_frames.step import FrameInitializationResult, SkippedFrame
from shstk_injector.entry_trampoline import EntryTrampoline
from shstk_injector.expand import AddedSection
from shstk_injector.return_trampoline import ReturnTrampoline
from shstk_injector.steps.shadow_stack import InjectionResult, SkippedFunction


class CliOutputTests(unittest.TestCase):
    def test_shadow_size_parser_accepts_auto(self) -> None:
        self.assertIsNone(_parse_shadow_size("auto"))

    def test_shadow_size_parser_accepts_integer(self) -> None:
        self.assertEqual(_parse_shadow_size("0x2000"), 0x2000)

    def test_shadow_stack_result_prints_skipped_function_details(self) -> None:
        result = InjectionResult(
            output_path=Path("patched"),
            shadow=AddedSection(".shadow", 0x500000, 0x1000, 0x100, ("ALLOC",)),
            saved_addrs=AddedSection(".saved_addrs", 0x501000, 0x2000, 0x100, ("WRITE",)),
            trampolines=(
                EntryTrampoline("patched_fn", 0x401000, 0x500000, 5, b"\x90" * 5),
            ),
            skipped=(
                SkippedFunction(
                    "tiny_fn",
                    0x401020,
                    "function is smaller than a near jump",
                ),
            ),
            return_trampolines=(
                ReturnTrampoline(
                    "patched_fn",
                    0x401000,
                    0x401010,
                    0x40100b,
                    0x500040,
                    5,
                    b"\xc3",
                ),
            ),
        )

        output = StringIO()
        with redirect_stdout(output):
            _print_step_result(result)

        self.assertIn("skipped functions: 1", output.getvalue())
        self.assertIn(
            "  - tiny_fn @ 0x401020: function is smaller than a near jump",
            output.getvalue(),
        )

    def test_initialize_frames_result_prints_skipped_function_details(self) -> None:
        result = FrameInitializationResult(
            output_path=Path("patched"),
            initialized_frames=(),
            skipped=(
                SkippedFrame(
                    "leaf_fn",
                    0x401040,
                    "function does not allocate a stack frame",
                ),
            ),
            section_name=".init_frames",
            section_address=0x600000,
            section_size=0x1000,
        )

        output = StringIO()
        with redirect_stdout(output):
            _print_step_result(result)

        self.assertIn("stack frames skipped: 1", output.getvalue())
        self.assertIn(
            "  - leaf_fn @ 0x401040: function does not allocate a stack frame",
            output.getvalue(),
        )


if __name__ == "__main__":
    unittest.main()
