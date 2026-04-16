import unittest

import lief

from tests.fixture_binaries import patch_fixture, run_binary
from shstk_injector.return_trampoline import ReturnAddressAction


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


def _is_pie(path) -> bool:
    binary = lief.parse(path)
    assert isinstance(binary, lief.ELF.Binary)
    return bool(binary.is_pie)


if __name__ == "__main__":
    unittest.main()
