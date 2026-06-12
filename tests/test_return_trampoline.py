import unittest
from types import SimpleNamespace
from unittest.mock import patch

import lief

from binary_hardening.x86 import SkipFunction
from tests.fixture_binaries import patch_fixture, run_binary, run_pipeline_fixture
from binary_hardening.exit_trampoline import (
    ReturnAddressAction,
    ReturnPatchStrategy,
    TrapFallbackCandidate,
    collect_return_sites,
)
from shstk_injector.steps.shadow_stack import SHADOW_STACK_STEP, TrapFallbackDecision


class ReturnTrampolineTests(unittest.TestCase):
    def test_patched_binary_restores_corrupted_return_address(self) -> None:
        input_path, output_path = patch_fixture(self, "return_restore")

        self.assertNotEqual(run_binary(input_path).returncode, 0)
        self.assertEqual(run_binary(output_path).returncode, 0)

    def test_patched_pie_binary_restores_corrupted_return_address(self) -> None:
        input_path, output_path = patch_fixture(self, "return_restore_pie")

        self.assertTrue(_is_pie(input_path))
        self.assertTrue(_is_pie(output_path))
        self.assertNotEqual(run_binary(input_path).returncode, 0)
        self.assertEqual(run_binary(output_path).returncode, 0)

    def test_compare_crash_preserves_valid_return_address(self) -> None:
        input_path, output_path = patch_fixture(
            self,
            "entry_smoke",
            return_address_action=ReturnAddressAction.COMPARE_CRASH,
        )

        self.assertEqual(run_binary(input_path).returncode, 0)
        self.assertEqual(run_binary(output_path).returncode, 0)

    def test_compare_crash_rejects_corrupted_return_address(self) -> None:
        _, output_path = patch_fixture(
            self,
            "return_restore",
            return_address_action=ReturnAddressAction.COMPARE_CRASH,
        )

        self.assertNotEqual(run_binary(output_path).returncode, 0)

    def test_compare_crash_prints_optional_message(self) -> None:
        message = "shadow stack mismatch\n"
        _, output_path = patch_fixture(
            self,
            "return_restore",
            return_address_action=ReturnAddressAction.COMPARE_CRASH,
            crash_message=message,
        )

        result = run_binary(output_path)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr, message)

    def test_canary_epilogue_uses_rbx_return_patch(self) -> None:
        _, output_path, pipeline_result = run_pipeline_fixture(
            self,
            "canary_return",
            steps=(SHADOW_STACK_STEP,),
        )
        result = pipeline_result.result_for_step(SHADOW_STACK_STEP)

        self.assertEqual(run_binary(output_path).returncode, 0)
        self.assertIn(
            ReturnPatchStrategy.RBX_JUMP,
            {trampoline.strategy for trampoline in result.return_trampolines},
        )

    def test_pie_canary_epilogue_uses_rbx_return_patch(self) -> None:
        _, output_path, pipeline_result = run_pipeline_fixture(
            self,
            "canary_return_pie",
            steps=(SHADOW_STACK_STEP,),
        )
        result = pipeline_result.result_for_step(SHADOW_STACK_STEP)

        self.assertEqual(run_binary(output_path).returncode, 0)
        self.assertIn(
            ReturnPatchStrategy.RBX_JUMP,
            {trampoline.strategy for trampoline in result.return_trampolines},
        )

    def test_rbx_epilogue_falls_back_to_short_code_cave_patch(self) -> None:
        input_path, output_path, pipeline_result = run_pipeline_fixture(
            self,
            "short_return_fallback",
            steps=(SHADOW_STACK_STEP,),
        )
        result = pipeline_result.result_for_step(SHADOW_STACK_STEP)

        self.assertNotEqual(run_binary(input_path).returncode, 0)
        self.assertEqual(run_binary(output_path).returncode, 0)
        self.assertIn(
            ReturnPatchStrategy.SHORT_CAVE,
            {trampoline.strategy for trampoline in result.return_trampolines},
        )

    def test_pie_rbx_epilogue_falls_back_to_short_code_cave_patch(self) -> None:
        input_path, output_path, pipeline_result = run_pipeline_fixture(
            self,
            "short_return_fallback_pie",
            steps=(SHADOW_STACK_STEP,),
        )
        result = pipeline_result.result_for_step(SHADOW_STACK_STEP)

        self.assertTrue(_is_pie(input_path))
        self.assertTrue(_is_pie(output_path))
        self.assertNotEqual(run_binary(input_path).returncode, 0)
        self.assertEqual(run_binary(output_path).returncode, 0)
        self.assertIn(
            ReturnPatchStrategy.SHORT_CAVE,
            {trampoline.strategy for trampoline in result.return_trampolines},
        )

    def test_short_jump_uses_donor_when_no_code_cave_is_available(self) -> None:
        with patch(
            "binary_hardening.exit_trampoline._find_short_jump_code_cave",
            return_value=None,
        ):
            input_path, output_path, pipeline_result = run_pipeline_fixture(
                self,
                "short_return_fallback",
                steps=(SHADOW_STACK_STEP,),
            )
        result = pipeline_result.result_for_step(SHADOW_STACK_STEP)

        self.assertNotEqual(run_binary(input_path).returncode, 0)
        self.assertEqual(run_binary(output_path).returncode, 0)
        self.assertIn(
            ReturnPatchStrategy.SHORT_DONOR,
            {trampoline.strategy for trampoline in result.return_trampolines},
        )

    def test_trap_fallback_handles_return_when_jump_strategies_fail(self) -> None:
        with (
            patch(
                "binary_hardening.exit_trampoline._find_short_jump_code_cave",
                return_value=None,
            ),
            patch(
                "binary_hardening.exit_trampoline._find_short_jump_donor",
                return_value=None,
            ),
        ):
            input_path, output_path, pipeline_result = run_pipeline_fixture(
                self,
                "short_return_fallback",
                steps=(SHADOW_STACK_STEP,),
                trap_fallback=TrapFallbackDecision.ALLOW,
                hardenelf_size=0x5000,
            )
        result = pipeline_result.result_for_step(SHADOW_STACK_STEP)

        self.assertNotEqual(run_binary(input_path).returncode, 0)
        self.assertEqual(run_binary(output_path).returncode, 0)
        self.assertIn(
            ReturnPatchStrategy.TRAP,
            {trampoline.strategy for trampoline in result.return_trampolines},
        )

    def test_pie_trap_fallback_handles_return_when_jump_strategies_fail(self) -> None:
        with (
            patch(
                "binary_hardening.exit_trampoline._find_short_jump_code_cave",
                return_value=None,
            ),
            patch(
                "binary_hardening.exit_trampoline._find_short_jump_donor",
                return_value=None,
            ),
        ):
            input_path, output_path, pipeline_result = run_pipeline_fixture(
                self,
                "short_return_fallback_pie",
                steps=(SHADOW_STACK_STEP,),
                trap_fallback=TrapFallbackDecision.ALLOW,
                hardenelf_size=0x5000,
            )
        result = pipeline_result.result_for_step(SHADOW_STACK_STEP)

        self.assertTrue(_is_pie(input_path))
        self.assertTrue(_is_pie(output_path))
        self.assertNotEqual(run_binary(input_path).returncode, 0)
        self.assertEqual(run_binary(output_path).returncode, 0)
        self.assertIn(
            ReturnPatchStrategy.TRAP,
            {trampoline.strategy for trampoline in result.return_trampolines},
        )

    def test_trap_fallback_skip_leaves_function_unpatched(self) -> None:
        with (
            patch(
                "binary_hardening.exit_trampoline._find_short_jump_code_cave",
                return_value=None,
            ),
            patch(
                "binary_hardening.exit_trampoline._find_short_jump_donor",
                return_value=None,
            ),
        ):
            _, _, pipeline_result = run_pipeline_fixture(
                self,
                "short_return_fallback",
                steps=(SHADOW_STACK_STEP,),
                trap_fallback=TrapFallbackDecision.SKIP,
            )
        result = pipeline_result.result_for_step(SHADOW_STACK_STEP)

        skipped = {function.function_name for function in result.skipped}
        self.assertIn("short_return_helper", skipped)
        self.assertNotIn(
            ReturnPatchStrategy.TRAP,
            {trampoline.strategy for trampoline in result.return_trampolines},
        )

    def test_unknown_function_size_is_not_trap_fallback_candidate(self) -> None:
        function = SimpleNamespace(size=0)

        with self.assertRaises(SkipFunction) as raised:
            collect_return_sites(None, None, function)

        self.assertEqual(str(raised.exception), "function size is unknown")
        self.assertNotIsInstance(raised.exception, TrapFallbackCandidate)


def _is_pie(path) -> bool:
    binary = lief.parse(path)
    assert isinstance(binary, lief.ELF.Binary)
    return bool(binary.is_pie)


if __name__ == "__main__":
    unittest.main()
