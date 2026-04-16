import unittest

import lief

from tests.fixture_binaries import patch_fixture, run_binary


class EntryTrampolineTests(unittest.TestCase):
    def test_patched_binary_preserves_function_behavior(self) -> None:
        input_path, output_path = patch_fixture(self, "entry_smoke")

        self.assertEqual(run_binary(input_path).returncode, 0)
        self.assertEqual(run_binary(output_path).returncode, 0)

    def test_patched_pie_binary_preserves_function_behavior(self) -> None:
        input_path, output_path = patch_fixture(self, "entry_smoke_pie")

        self.assertTrue(_is_pie(input_path))
        self.assertTrue(_is_pie(output_path))
        self.assertEqual(run_binary(input_path).returncode, 0)
        self.assertEqual(run_binary(output_path).returncode, 0)

    def test_patched_binary_preserves_rip_relative_entry_behavior(self) -> None:
        input_path, output_path = patch_fixture(self, "rip_relative_entry")

        self.assertEqual(run_binary(input_path).returncode, 0)
        self.assertEqual(run_binary(output_path).returncode, 0)

    def test_patched_pie_binary_preserves_rip_relative_entry_behavior(self) -> None:
        input_path, output_path = patch_fixture(self, "rip_relative_entry_pie")

        self.assertTrue(_is_pie(input_path))
        self.assertTrue(_is_pie(output_path))
        self.assertEqual(run_binary(input_path).returncode, 0)
        self.assertEqual(run_binary(output_path).returncode, 0)


def _is_pie(path) -> bool:
    binary = lief.parse(path)
    assert isinstance(binary, lief.ELF.Binary)
    return bool(binary.is_pie)


if __name__ == "__main__":
    unittest.main()
