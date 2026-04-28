"""Instruction relocation helpers for trampoline bodies."""

from __future__ import annotations

import re
from typing import Any

from binary_hardening.x86 import SkipFunction, assemble


_RIP_OPERAND_RE = re.compile(r"\brip(?:\s*([+-])\s*(0x[0-9a-fA-F]+|\d+))?")


def relocate_instruction(assembler: Any, instruction: Any, new_address: int) -> bytes:
    if not _has_rip_relative_operand(instruction):
        return bytes(instruction.bytes)

    original_target = instruction.address + instruction.size + _rip_displacement(
        instruction
    )
    new_displacement = original_target - (new_address + instruction.size)
    rewritten_operands = _rewrite_rip_operand(instruction.op_str, new_displacement)
    rewritten = assemble(
        assembler,
        f"{instruction.mnemonic} {rewritten_operands}",
        new_address,
    )
    if len(rewritten) != instruction.size:
        raise SkipFunction(
            f"relocated {instruction.mnemonic} changed size from "
            f"{instruction.size} to {len(rewritten)} bytes"
        )
    return rewritten


def _has_rip_relative_operand(instruction: Any) -> bool:
    import capstone.x86_const as x86

    return any(
        operand.type == x86.X86_OP_MEM and operand.mem.base == x86.X86_REG_RIP
        for operand in instruction.operands
    )


def _rip_displacement(instruction: Any) -> int:
    import capstone.x86_const as x86

    for operand in instruction.operands:
        if operand.type == x86.X86_OP_MEM and operand.mem.base == x86.X86_REG_RIP:
            return operand.mem.disp
    raise SkipFunction("missing RIP-relative displacement")


def _rewrite_rip_operand(operands: str, displacement: int) -> str:
    replacement = f"rip + 0x{displacement:x}"
    if displacement < 0:
        replacement = f"rip - 0x{-displacement:x}"

    rewritten, count = _RIP_OPERAND_RE.subn(replacement, operands, count=1)
    if count != 1:
        raise SkipFunction("could not rewrite RIP-relative operand")
    return rewritten
