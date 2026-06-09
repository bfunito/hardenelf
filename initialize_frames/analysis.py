"""Function analysis for stack-frame initialization."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import lief

from binary_hardening.symbols import FunctionSymbol, iter_function_symbols
from binary_hardening.x86 import (
    NEAR_JUMP_SIZE,
    SkipFunction,
    ensure_relocatable_instruction,
    function_code_limit,
    ranges_overlap,
)


@dataclass(frozen=True)
class FrameInitializationSite:
    """Patch plan for zeroing one function's stack frame."""

    function: FunctionSymbol
    frame_size: int
    patch_address: int
    overwritten_instructions: tuple[Any, ...]

    @property
    def overwritten_size(self) -> int:
        return sum(instruction.size for instruction in self.overwritten_instructions)

    @property
    def original_bytes(self) -> bytes:
        return b"".join(
            bytes(instruction.bytes) for instruction in self.overwritten_instructions
        )

def collect_initialization_site(
    binary: lief.ELF.Binary,
    disassembler: Any,
    function: FunctionSymbol,
) -> FrameInitializationSite:
    """Find the post-prologue patch point for a conventional stack frame."""

    instructions = _disassemble_function(binary, disassembler, function)
    prologue_end_index, frame_size = _find_frame_prologue(instructions)
    patch_instructions = _collect_patch_instructions(instructions, prologue_end_index)
    patch_address = patch_instructions[0].address

    _ensure_patch_range_has_no_internal_branch_target(
        instructions,
        patch_address,
        sum(instruction.size for instruction in patch_instructions),
    )

    return FrameInitializationSite(
        function=function,
        frame_size=frame_size,
        patch_address=patch_address,
        overwritten_instructions=tuple(patch_instructions),
    )


def _disassemble_function(
    binary: lief.ELF.Binary,
    disassembler: Any,
    function: FunctionSymbol,
) -> list[Any]:
    if function.size <= 0:
        raise SkipFunction("function size is unknown")

    max_size = function_code_limit(function)
    if max_size < NEAR_JUMP_SIZE:
        raise SkipFunction("function is smaller than a near jump")

    code = bytes(binary.get_content_from_virtual_address(function.address, max_size))
    instructions = list(disassembler.disasm(code, function.address))
    if not instructions:
        raise SkipFunction("could not disassemble function body")
    return instructions


def _find_frame_prologue(instructions: list[Any]) -> tuple[int, int]:
    index = 0
    if index < len(instructions) and instructions[index].mnemonic == "endbr64":
        index += 1

    if index >= len(instructions) or not _is_push_rbp(instructions[index]):
        raise SkipFunction("missing canonical push rbp prologue")
    index += 1

    if index >= len(instructions) or not _is_mov_rbp_rsp(instructions[index]):
        raise SkipFunction("missing canonical mov rbp, rsp prologue")
    index += 1

    if index >= len(instructions) or not _is_sub_rsp_imm(instructions[index]):
        raise SkipFunction("function does not allocate a stack frame")

    frame_size = _immediate_operand_value(instructions[index])
    if frame_size <= 0:
        raise SkipFunction("stack frame allocation is empty")
    index += 1
    return index, frame_size


def _collect_patch_instructions(
    instructions: list[Any],
    start_index: int,
) -> list[Any]:
    selected: list[Any] = []
    total_size = 0

    for instruction in instructions[start_index:]:
        ensure_relocatable_instruction(instruction, "frame-initializer")
        selected.append(instruction)
        total_size += instruction.size
        if total_size >= NEAR_JUMP_SIZE:
            return selected

    raise SkipFunction("could not collect enough post-prologue bytes")


def _ensure_patch_range_has_no_internal_branch_target(
    instructions: list[Any],
    patch_address: int,
    overwritten_size: int,
) -> None:
    patch_range = (patch_address, patch_address + overwritten_size)

    for instruction in instructions:
        target = _direct_branch_target(instruction)
        if target is None:
            continue
        if ranges_overlap(patch_range, (target, target + 1)) and target != patch_address:
            raise SkipFunction("patch range has an internal branch target")


def _direct_branch_target(instruction: Any) -> int | None:
    import capstone
    import capstone.x86_const as x86

    if not instruction.group(capstone.CS_GRP_JUMP):
        return None
    if len(instruction.operands) != 1:
        return None

    operand = instruction.operands[0]
    if operand.type != x86.X86_OP_IMM:
        return None
    return int(operand.imm)


def _is_push_rbp(instruction: Any) -> bool:
    import capstone.x86_const as x86

    return (
        instruction.mnemonic == "push"
        and len(instruction.operands) == 1
        and instruction.operands[0].type == x86.X86_OP_REG
        and instruction.operands[0].reg == x86.X86_REG_RBP
    )


def _is_mov_rbp_rsp(instruction: Any) -> bool:
    import capstone.x86_const as x86

    return (
        instruction.mnemonic == "mov"
        and len(instruction.operands) == 2
        and instruction.operands[0].type == x86.X86_OP_REG
        and instruction.operands[0].reg == x86.X86_REG_RBP
        and instruction.operands[1].type == x86.X86_OP_REG
        and instruction.operands[1].reg == x86.X86_REG_RSP
    )


def _is_sub_rsp_imm(instruction: Any) -> bool:
    import capstone.x86_const as x86

    return (
        instruction.mnemonic == "sub"
        and len(instruction.operands) == 2
        and instruction.operands[0].type == x86.X86_OP_REG
        and instruction.operands[0].reg == x86.X86_REG_RSP
        and instruction.operands[1].type == x86.X86_OP_IMM
    )


def _immediate_operand_value(instruction: Any) -> int:
    import capstone.x86_const as x86

    for operand in instruction.operands:
        if operand.type == x86.X86_OP_IMM:
            return int(operand.imm)
    raise SkipFunction("missing stack-frame size immediate")
