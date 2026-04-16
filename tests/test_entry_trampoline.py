from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest

import lief

from shstk_injector.entry_trampoline import (
    _relocate_instruction,
    inject_entry_trampolines,
)


class EntryTrampolineTests(unittest.TestCase):
    def test_writes_entry_trampolines_for_non_stripped_functions(self) -> None:
        try:
            import keystone  # noqa: F401
        except ImportError:
            self.skipTest("keystone-engine is not installed")

        gcc = shutil.which("gcc")
        if gcc is None:
            self.skipTest("gcc is not available")

        with TemporaryDirectory() as tmpdir:
            workdir = Path(tmpdir)
            input_path = workdir / "sample"
            output_path = workdir / "sample.patched"
            source_path = workdir / "sample.c"
            source_path.write_text(
                """
                __attribute__((noinline))
                int helper(int value) {
                    return value + 1;
                }

                int main(void) {
                    return helper(40) == 41 ? 0 : 1;
                }
                """,
                encoding="utf-8",
            )

            compile_result = subprocess.run(
                [
                    gcc,
                    "-g",
                    "-O0",
                    "-fno-pie",
                    "-no-pie",
                    str(source_path),
                    "-o",
                    str(input_path),
                ],
                cwd=workdir,
                check=False,
                capture_output=True,
                text=True,
            )
            if compile_result.returncode != 0:
                self.skipTest(f"could not build sample binary: {compile_result.stderr}")

            result = inject_entry_trampolines(
                input_path,
                output_path,
                shadow_size=0x2000,
                saved_addrs_size=0x2000,
            )

            helper_trampoline = next(
                trampoline
                for trampoline in result.trampolines
                if trampoline.function_name == "helper"
            )

            rewritten = lief.parse(output_path)
            self.assertIsInstance(rewritten, lief.ELF.Binary)
            assert isinstance(rewritten, lief.ELF.Binary)

            entry_bytes = bytes(
                rewritten.get_content_from_virtual_address(
                    helper_trampoline.function_address,
                    helper_trampoline.overwritten_size,
                )
            )
            self.assertEqual(entry_bytes[0], 0xE9)
            self.assertEqual(
                entry_bytes[5:],
                b"\x90" * (helper_trampoline.overwritten_size - 5),
            )

            trampoline_bytes = bytes(
                rewritten.get_content_from_virtual_address(
                    helper_trampoline.trampoline_address,
                    1,
                )
            )
            self.assertEqual(trampoline_bytes, b"\x9c")

            run_result = subprocess.run([output_path], check=False)
            self.assertEqual(run_result.returncode, 0)

    def test_rewrites_rip_relative_instruction_for_shadow_address(self) -> None:
        try:
            from capstone import CS_ARCH_X86, CS_MODE_64, Cs
            from keystone import KS_ARCH_X86, KS_MODE_64, Ks
        except ImportError:
            self.skipTest("capstone or keystone-engine is not installed")

        old_address = 0x1000
        new_address = 0x5000
        assembler = Ks(KS_ARCH_X86, KS_MODE_64)
        original_bytes, _ = assembler.asm(
            "mov rax, qword ptr [rip + 0x1234]",
            addr=old_address,
        )

        disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
        disassembler.detail = True
        instruction = next(disassembler.disasm(bytes(original_bytes), old_address))

        relocated = _relocate_instruction(assembler, instruction, new_address)
        relocated_instruction = next(disassembler.disasm(relocated, new_address))

        original_target = instruction.address + instruction.size + instruction.disp
        relocated_target = (
            relocated_instruction.address
            + relocated_instruction.size
            + relocated_instruction.disp
        )
        self.assertEqual(relocated_target, original_target)
        self.assertEqual(len(relocated), len(original_bytes))


if __name__ == "__main__":
    unittest.main()
