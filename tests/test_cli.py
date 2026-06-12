from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import unittest

from binary_hardening.cli import _make_parser, _parse_hardenelf_size, _print_step_result
from initialize_frames.step import FrameInitializationResult, SkippedFrame
from binary_hardening.entry_trampoline import EntryTrampoline
from shstk_injector.expand import AddedSection
from binary_hardening.exit_trampoline import ReturnTrampoline
from shstk_injector.steps.shadow_stack import InjectionResult, SkippedFunction


class CliOutputTests(unittest.TestCase):
    def test_parser_accepts_short_modern_options(self) -> None:
        args = _make_parser().parse_args(
            [
                "-p",
                "shadow-stack",
                "-s",
                "auto",
                "-a",
                "0x2000",
                "-f",
                "0x3000",
                "-i",
                "0x5000",
                "-e",
                "-r",
                "compare-crash",
                "-m",
                "boom",
                "-t",
                "skip",
                "input",
                "output",
            ]
        )

        self.assertEqual(args.steps, ["shadow-stack"])
        self.assertIsNone(args.hardenelf_size)
        self.assertEqual(args.saved_addrs_size, 0x2000)
        self.assertEqual(args.fmtstr_trampoline_size, 0x3000)
        self.assertEqual(args.init_frame_trampoline_size, 0x5000)
        self.assertTrue(args.expand_only)
        self.assertEqual(args.return_address_action, "compare-crash")
        self.assertEqual(args.crash_message, "boom")
        self.assertEqual(args.trap_fallback, "skip")

    def test_parser_keeps_long_options_hidden(self) -> None:
        parser = _make_parser()
        args = parser.parse_args(
            [
                "--step",
                "shadow-stack",
                "--hardenelf-size",
                "0x2000",
                "--saved-addrs-size",
                "0x3000",
                "--fmtstr-trampoline-size",
                "0x4000",
                "--init-frame-trampoline-size",
                "0x5000",
                "--expand-only",
                "--return-address-action",
                "compare-crash",
                "--crash-message",
                "boom",
                "--trap-fallback",
                "skip",
                "input",
                "output",
            ]
        )
        help_text = parser.format_help()

        self.assertEqual(args.steps, ["shadow-stack"])
        self.assertEqual(args.hardenelf_size, 0x2000)
        self.assertEqual(args.saved_addrs_size, 0x3000)
        self.assertEqual(args.fmtstr_trampoline_size, 0x4000)
        self.assertEqual(args.init_frame_trampoline_size, 0x5000)
        self.assertTrue(args.expand_only)
        self.assertEqual(args.return_address_action, "compare-crash")
        self.assertEqual(args.crash_message, "boom")
        self.assertEqual(args.trap_fallback, "skip")
        self.assertIn("-p, --pass", help_text)
        self.assertIn("-r, --ret", help_text)
        self.assertNotIn("--return-address-action", help_text)
        self.assertNotIn("--fmtstr-trampoline-size", help_text)

    def test_hardenelf_size_parser_accepts_auto(self) -> None:
        self.assertIsNone(_parse_hardenelf_size("auto"))

    def test_hardenelf_size_parser_accepts_integer(self) -> None:
        self.assertEqual(_parse_hardenelf_size("0x2000"), 0x2000)

    def test_parser_accepts_auto_trampoline_sizes(self) -> None:
        args = _make_parser().parse_args(
            [
                "-p",
                "fmtstr-checker",
                "-p",
                "initialize-frames",
                "-f",
                "auto",
                "-i",
                "auto",
                "input",
                "output",
            ]
        )

        self.assertIsNone(args.fmtstr_trampoline_size)
        self.assertIsNone(args.init_frame_trampoline_size)

    def test_shadow_stack_result_prints_skipped_function_details(self) -> None:
        result = InjectionResult(
            output_path=Path("patched"),
            hardenelf=AddedSection(".hardenelf", 0x500000, 0x1000, 0x100, ("ALLOC",)),
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
            section_name=".hardenelf",
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
