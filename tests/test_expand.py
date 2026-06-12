from pathlib import Path
from stat import S_IMODE
from tempfile import TemporaryDirectory
import unittest

import lief

from shstk_injector.expand import (
    HARDENELF_SECTION,
    SAVED_ADDRS_SECTION,
    expand_binary,
)


class ExpandBinaryTests(unittest.TestCase):
    def test_adds_hardenelf_and_saved_addrs_sections(self) -> None:
        input_path = Path("/bin/true")
        if not input_path.exists():
            self.skipTest("/bin/true is not available")

        with TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "true.patched"

            result = expand_binary(
                input_path,
                output_path,
                hardenelf_size=0x80,
                saved_addrs_size=0x40,
            )

            rewritten = lief.parse(output_path)
            self.assertIsInstance(rewritten, lief.ELF.Binary)
            assert isinstance(rewritten, lief.ELF.Binary)

            hardenelf = rewritten.get_section(HARDENELF_SECTION)
            saved_addrs = rewritten.get_section(SAVED_ADDRS_SECTION)

            self.assertIsNotNone(hardenelf)
            self.assertIsNotNone(saved_addrs)
            assert hardenelf is not None
            assert saved_addrs is not None

            self.assertEqual(hardenelf.type, lief.ELF.Section.TYPE.PROGBITS)
            self.assertTrue(hardenelf.has(lief.ELF.Section.FLAGS.ALLOC))
            self.assertTrue(hardenelf.has(lief.ELF.Section.FLAGS.EXECINSTR))
            self.assertFalse(hardenelf.has(lief.ELF.Section.FLAGS.WRITE))
            self.assertEqual(hardenelf.size, 0x80)

            self.assertEqual(saved_addrs.type, lief.ELF.Section.TYPE.PROGBITS)
            self.assertTrue(saved_addrs.has(lief.ELF.Section.FLAGS.ALLOC))
            self.assertTrue(saved_addrs.has(lief.ELF.Section.FLAGS.WRITE))
            self.assertFalse(saved_addrs.has(lief.ELF.Section.FLAGS.EXECINSTR))
            self.assertEqual(saved_addrs.size, 0x40)

            self.assertEqual(result.hardenelf.virtual_address, hardenelf.virtual_address)
            self.assertEqual(
                S_IMODE(output_path.stat().st_mode),
                S_IMODE(input_path.stat().st_mode),
            )


if __name__ == "__main__":
    unittest.main()
