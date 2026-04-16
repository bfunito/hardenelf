import unittest

from tests.fixture_binaries import patch_fixture, run_binary


class EntryTrampolineTests(unittest.TestCase):
    def test_patched_binary_preserves_function_behavior(self) -> None:
        input_path, output_path = patch_fixture(self, "entry_smoke")

        self.assertEqual(run_binary(input_path).returncode, 0)
        self.assertEqual(run_binary(output_path).returncode, 0)

    def test_patched_binary_preserves_rip_relative_entry_behavior(self) -> None:
        input_path, output_path = patch_fixture(self, "rip_relative_entry")

        self.assertEqual(run_binary(input_path).returncode, 0)
        self.assertEqual(run_binary(output_path).returncode, 0)


if __name__ == "__main__":
    unittest.main()
