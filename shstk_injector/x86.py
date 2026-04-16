"""Shared x86-64 assembly and patching helpers."""

from __future__ import annotations

import struct
from typing import Any

import lief


NEAR_JUMP_SIZE = 5


def make_disassembler() -> Any:
    try:
        import capstone
    except ImportError as exc:
        raise RuntimeError("Capstone is required; install the capstone package") from exc

    disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    disassembler.detail = True
    return disassembler


def make_assembler() -> Any:
    try:
        import keystone
    except ImportError as exc:
        raise RuntimeError(
            "Keystone is required; install the keystone-engine package"
        ) from exc

    return keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)


def ensure_x86_64(binary: lief.ELF.Binary) -> None:
    if binary.header.machine_type != lief.ELF.ARCH.X86_64:
        raise ValueError("trampolines are currently implemented only for x86-64")
    if binary.header.identity_class != lief.ELF.Header.CLASS.ELF64:
        raise ValueError("trampolines require a 64-bit ELF binary")


def function_code_limit(function: Any) -> int:
    section_limit = function.section.virtual_address + function.section.size
    max_size = section_limit - function.address
    if function.size > 0:
        max_size = min(max_size, function.size)
    return max_size


def ensure_relocatable_instruction(instruction: Any, context: str) -> None:
    import capstone

    blocked_groups = (
        capstone.CS_GRP_JUMP,
        capstone.CS_GRP_CALL,
        capstone.CS_GRP_RET,
        capstone.CS_GRP_IRET,
    )
    if any(instruction.group(group) for group in blocked_groups):
        raise SkipFunction(
            f"{context} instruction {instruction.mnemonic} changes control flow"
        )


def is_return_instruction(instruction: Any) -> bool:
    import capstone

    return instruction.group(capstone.CS_GRP_RET)


def assemble(assembler: Any, assembly: str, address: int) -> bytes:
    try:
        encoding, _ = assembler.asm(_normalize_assembly(assembly), addr=address)
    except Exception as exc:
        raise SkipFunction(f"could not assemble trampoline code: {exc}") from exc
    return bytes(encoding)


def make_jump(source: int, target: int) -> bytes:
    displacement = target - (source + NEAR_JUMP_SIZE)
    if not -(2**31) <= displacement < 2**31:
        raise SkipFunction("relative jump target is outside the signed 32-bit range")
    return b"\xe9" + struct.pack("<i", displacement)


def ranges_overlap(left: tuple[int, int], right: tuple[int, int]) -> bool:
    return left[0] < right[1] and right[0] < left[1]


def pad_to_alignment(body: bytes, alignment: int = 0x10) -> bytes:
    padding = (-len(body)) % alignment
    return body + (b"\x90" * padding)


def _normalize_assembly(assembly: str) -> str:
    return "\n".join(line.strip() for line in assembly.splitlines() if line.strip())


class SkipFunction(Exception):
    """Raised internally when a function cannot be patched safely."""
