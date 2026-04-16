import unittest

from tests.fixture_binaries import patch_fixture, run_binary


class ReturnTrampolineTests(unittest.TestCase):
    def test_patched_binary_restores_corrupted_return_address(self) -> None:
        input_path, output_path = patch_fixture(self, "return_restore")

        self.assertNotEqual(run_binary(input_path).returncode, 0)
        self.assertEqual(run_binary(output_path).returncode, 0)


if __name__ == "__main__":
    unittest.main()
