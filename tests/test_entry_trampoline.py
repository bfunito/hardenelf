import unittest

import lief

from binary_hardening.api import inject_trampolines
from tests.fixture_binaries import (
    BIN_DIR,
    PATCHED_DIR,
    build_fixtures,
    patch_fixture,
    require_injector_dependencies,
    run_binary,
)


class EntryTrampolineTests(unittest.TestCase):
    def test_auto_shadow_size_is_page_aligned(self) -> None:
        build_fixtures(self)
        require_injector_dependencies(self)

        input_path = BIN_DIR / "entry_smoke"
        output_path = PATCHED_DIR / "entry_smoke.auto"
        output_path.unlink(missing_ok=True)

        result = inject_trampolines(input_path, output_path)

        self.assertEqual(result.shadow.size % 0x1000, 0)
        self.assertGreaterEqual(result.shadow.size, 0x1000)
        self.assertEqual(run_binary(output_path).returncode, 0)

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
