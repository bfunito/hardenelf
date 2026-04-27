from __future__ import annotations

import ctypes
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import unittest

import lief

from fmtstr_checker.checkformat import build_checkformat_library
from fmtstr_checker.step import (
    FMTSTR_CHECKER_STEP,
    FMTSTR_DATA_SECTION,
    FMTSTR_TRAMPOLINE_SECTION,
    FmtStrPatchResult,
)
from shstk_injector.inject import patch_format_strings
from tests.fixture_binaries import (
    BIN_DIR,
    build_fixtures,
    require_injector_dependencies,
    run_binary,
    run_pipeline_fixture,
)


class FmtStrCheckerIntegrationTests(unittest.TestCase):
    def test_fmtstr_checker_rewrites_calls_and_adds_library(self) -> None:
        _, output_path, result = run_pipeline_fixture(
            self,
            "fmtstr_smoke",
            steps=(FMTSTR_CHECKER_STEP,),
        )

        step_result = result.result_for_step(FMTSTR_CHECKER_STEP)
        self.assertIsInstance(step_result, FmtStrPatchResult)
        assert isinstance(step_result, FmtStrPatchResult)

        self.assertIsNotNone(step_result.library_path)
        assert step_result.library_path is not None
        self.assertTrue(step_result.library_path.exists())
        self.assertIn("libcheckformat.so", step_result.libraries)
        self.assertIn("$ORIGIN", step_result.runpath)
        self.assertGreaterEqual(len(step_result.patched_calls), 8)

        target_names = {call.target_name for call in step_result.patched_calls}
        self.assertIn("printf", target_names)
        self.assertIn("fprintf", target_names)
        self.assertIn("snprintf", target_names)
        self.assertIn("sprintf", target_names)

        rewritten = lief.parse(output_path)
        self.assertIsInstance(rewritten, lief.ELF.Binary)
        assert isinstance(rewritten, lief.ELF.Binary)
        self.assertTrue(rewritten.has_section(FMTSTR_TRAMPOLINE_SECTION))
        self.assertTrue(rewritten.has_section(FMTSTR_DATA_SECTION))

    def test_patched_binary_allows_benign_dynamic_formats(self) -> None:
        _, output_path, _ = run_pipeline_fixture(
            self,
            "fmtstr_smoke",
            steps=(FMTSTR_CHECKER_STEP,),
        )

        escaped_percent = run_binary(output_path, "dynamic", "literal %%x\n")
        strerror_format = run_binary(output_path, "dynamic", "%m\n")
        reused_positional = run_binary(output_path, "one", "%1$d %1$d\n")
        fprintf_escaped = run_binary(output_path, "fprintf-dynamic", "ok %% done\n")

        self.assertEqual(escaped_percent.returncode, 0, escaped_percent.stderr)
        self.assertEqual(escaped_percent.stdout, "literal %x\n")
        self.assertEqual(strerror_format.returncode, 0, strerror_format.stderr)
        self.assertEqual(reused_positional.returncode, 0, reused_positional.stderr)
        self.assertEqual(reused_positional.stdout, "111 111\n")
        self.assertEqual(fprintf_escaped.returncode, 0, fprintf_escaped.stderr)
        self.assertEqual(fprintf_escaped.stdout, "ok % done\n")

    def test_patched_binary_blocks_argument_underflows(self) -> None:
        input_path, output_path, _ = run_pipeline_fixture(
            self,
            "fmtstr_smoke",
            steps=(FMTSTR_CHECKER_STEP,),
        )

        original_stack_read = run_binary(input_path, "dynamic", "%x\n")
        patched_stack_read = run_binary(output_path, "dynamic", "%x\n")
        original_positional = run_binary(input_path, "one", "%2$d\n")
        patched_positional = run_binary(output_path, "one", "%2$d\n")
        patched_star = run_binary(output_path, "width-missing", "%*s\n")

        self.assertEqual(original_stack_read.returncode, 0)
        self.assertEqual(original_positional.returncode, 0)
        self.assertNotEqual(patched_stack_read.returncode, 0)
        self.assertNotEqual(patched_positional.returncode, 0)
        self.assertNotEqual(patched_star.returncode, 0)
        self.assertIn("format string argument underflow", patched_stack_read.stderr)
        self.assertIn("format string argument underflow", patched_positional.stderr)
        self.assertIn("format string argument underflow", patched_star.stderr)

    def test_patched_binary_preserves_variadic_register_and_stack_arguments(self) -> None:
        _, output_path, _ = run_pipeline_fixture(
            self,
            "fmtstr_smoke",
            steps=(FMTSTR_CHECKER_STEP,),
        )

        width = run_binary(output_path, "width")
        floating = run_binary(output_path, "float")
        many = run_binary(output_path, "many")
        snprintf = run_binary(output_path, "snprintf")
        sprintf = run_binary(output_path, "sprintf")

        self.assertEqual(width.returncode, 0, width.stderr)
        self.assertEqual(width.stdout, "   abc\n")
        self.assertEqual(floating.returncode, 0, floating.stderr)
        self.assertEqual(floating.stdout, "3.25\n")
        self.assertEqual(many.returncode, 0, many.stderr)
        self.assertEqual(many.stdout, "1 2 3 4 5 6 7 8\n")
        self.assertEqual(snprintf.returncode, 0, snprintf.stderr)
        self.assertEqual(snprintf.stdout, "7:ok:%\n")
        self.assertEqual(sprintf.returncode, 0, sprintf.stderr)
        self.assertEqual(sprintf.stdout, "value:9\n")

    def test_fmtstr_checker_supports_pie_binaries(self) -> None:
        _, output_path, _ = run_pipeline_fixture(
            self,
            "fmtstr_smoke_pie",
            steps=(FMTSTR_CHECKER_STEP,),
        )

        benign = run_binary(output_path, "one", "%1$d\n")
        malicious = run_binary(output_path, "one", "%2$d\n")

        self.assertEqual(benign.returncode, 0, benign.stderr)
        self.assertEqual(benign.stdout, "111\n")
        self.assertNotEqual(malicious.returncode, 0)
        self.assertIn("format string argument underflow", malicious.stderr)

    def test_full_pipeline_composes_with_fmtstr_checker(self) -> None:
        _, output_path, _ = run_pipeline_fixture(self, "fmtstr_smoke")

        benign = run_binary(output_path, "one", "%1$d\n")
        malicious = run_binary(output_path, "one", "%2$d\n")
        floating = run_binary(output_path, "float")

        self.assertEqual(benign.returncode, 0, benign.stderr)
        self.assertEqual(benign.stdout, "111\n")
        self.assertNotEqual(malicious.returncode, 0)
        self.assertIn("format string argument underflow", malicious.stderr)
        self.assertEqual(floating.returncode, 0, floating.stderr)
        self.assertEqual(floating.stdout, "3.25\n")

    def test_fmtstr_checker_is_noop_when_target_imports_are_absent(self) -> None:
        build_fixtures(self)
        require_injector_dependencies(self)

        input_path = BIN_DIR / "entry_smoke"
        with TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "entry_smoke.fmtstr"
            result = patch_format_strings(input_path, output_path)

            self.assertEqual(result.patched_calls, ())
            self.assertIsNone(result.library_path)

            rewritten = lief.parse(output_path)
            self.assertIsInstance(rewritten, lief.ELF.Binary)
            assert isinstance(rewritten, lief.ELF.Binary)
            self.assertNotIn("libcheckformat.so", tuple(rewritten.libraries))


class CheckFormatLibraryTests(unittest.TestCase):
    def test_count_format_matches_glibc_format_edge_cases(self) -> None:
        if shutil.which("gcc") is None:
            self.skipTest("gcc is not available")

        with TemporaryDirectory() as tmpdir:
            library_path = build_checkformat_library(tmpdir)
            checkformat = ctypes.CDLL(str(library_path))
            checkformat.count_format.argtypes = [ctypes.c_char_p]
            checkformat.count_format.restype = ctypes.c_size_t

            cases = {
                b"literal %%x": 0,
                b"%m": 0,
                b"%d %s": 2,
                b"%*.*s": 3,
                b"%2$d": 2,
                b"%1$d %1$d": 1,
                b"%n": 1,
            }
            for fmt, expected in cases.items():
                with self.subTest(fmt=fmt):
                    self.assertEqual(checkformat.count_format(fmt), expected)


if __name__ == "__main__":
    unittest.main()
