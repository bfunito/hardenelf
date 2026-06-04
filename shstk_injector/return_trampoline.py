"""Return-site trampoline discovery and code generation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

import lief

from binary_hardening.relocation import relocate_instruction
from binary_hardening.x86 import (
    NEAR_JUMP_SIZE,
    SkipFunction,
    assemble,
    ensure_relocatable_instruction,
    function_code_limit,
    is_return_instruction,
    load_r11_with_address,
    ranges_overlap,
)


class ReturnAddressAction(str, Enum):
    """How return trampolines handle saved return addresses."""

    RESTORE = "restore"
    COMPARE_CRASH = "compare-crash"


class ReturnPatchStrategy(str, Enum):
    """Return-site patch encoding selected for a function."""

    NEAR_JUMP = "near-jump"
    RBX_JUMP = "rbx-jump"


@dataclass(frozen=True)
class ReturnTrampoline:
    """Summary of a return trampoline written for one return site."""

    function_name: str
    function_address: int
    return_address: int
    patch_address: int
    trampoline_address: int
    overwritten_size: int
    original_bytes: bytes
    strategy: ReturnPatchStrategy = ReturnPatchStrategy.NEAR_JUMP


@dataclass(frozen=True)
class ReturnSite:
    instructions: tuple[Any, ...]
    ret_instruction: Any
    strategy: ReturnPatchStrategy = ReturnPatchStrategy.NEAR_JUMP

    @property
    def patch_address(self) -> int:
        return self.instructions[0].address

    @property
    def overwritten_size(self) -> int:
        instruction_size = sum(instruction.size for instruction in self.instructions)
        return instruction_size + self.ret_instruction.size

    @property
    def original_bytes(self) -> bytes:
        body = b"".join(bytes(instruction.bytes) for instruction in self.instructions)
        return body + bytes(self.ret_instruction.bytes)


def collect_return_sites(
    binary: lief.ELF.Binary,
    disassembler: Any,
    function: Any,
) -> list[ReturnSite]:
    if function.size <= 0:
        raise SkipFunction("function size is unknown")

    max_size = function_code_limit(function)
    if max_size < NEAR_JUMP_SIZE:
        raise SkipFunction("function is smaller than a near jump")

    code = bytes(binary.get_content_from_virtual_address(function.address, max_size))
    instructions = list(disassembler.disasm(code, function.address))
    if not instructions:
        raise SkipFunction("could not disassemble function body")

    ret_indexes = [
        index
        for index, instruction in enumerate(instructions)
        if is_return_instruction(instruction)
    ]
    if not ret_indexes:
        raise SkipFunction("function has no return instruction")

    try:
        return_sites = [
            _collect_near_return_site_at_index(instructions, ret_index)
            for ret_index in ret_indexes
        ]
        _ensure_non_overlapping_return_sites(return_sites)
        _ensure_return_patches_are_not_branch_targets(instructions, return_sites)
        return return_sites
    except SkipFunction as near_jump_error:
        rbx_sites = _collect_rbx_return_sites(instructions, ret_indexes)
        if rbx_sites is not None:
            return rbx_sites
        raise near_jump_error


def build_return_trampoline(
    *,
    assembler: Any,
    return_site: ReturnSite,
    trampoline_address: int,
    saved_addrs_address: int,
    action: ReturnAddressAction = ReturnAddressAction.RESTORE,
    crash_message: bytes | None = None,
    allow_absolute_saved_addrs: bool = True,
) -> bytes:
    relocated = bytearray()
    for instruction in return_site.instructions:
        relocated_instruction = relocate_instruction(
            assembler,
            instruction,
            trampoline_address + len(relocated),
        )
        relocated.extend(relocated_instruction)

    check_address = trampoline_address + len(relocated)
    if action is ReturnAddressAction.RESTORE:
        check = _build_restore_block(
            assembler,
            check_address,
            saved_addrs_address,
            allow_absolute_saved_addrs=allow_absolute_saved_addrs,
            restore_rbx=return_site.strategy is ReturnPatchStrategy.RBX_JUMP,
        )
    elif action is ReturnAddressAction.COMPARE_CRASH:
        check = _build_compare_crash_block(
            assembler,
            check_address,
            saved_addrs_address,
            crash_message,
            allow_absolute_saved_addrs=allow_absolute_saved_addrs,
            restore_rbx=return_site.strategy is ReturnPatchStrategy.RBX_JUMP,
        )
    else:
        raise ValueError(f"unsupported return address action: {action}")

    return bytes(relocated) + check + bytes(return_site.ret_instruction.bytes)


def _build_restore_block(
    assembler: Any,
    block_address: int,
    saved_addrs_address: int,
    *,
    allow_absolute_saved_addrs: bool,
    restore_rbx: bool = False,
) -> bytes:
    saved_addrs_load = load_r11_with_address(
        assembler,
        block_address,
        saved_addrs_address,
        allow_absolute=allow_absolute_saved_addrs,
    )
    tail_address = block_address + len(saved_addrs_load)
    record_size = 16 if restore_rbx else 8
    rbx_restore = "mov rbx, qword ptr [r10 + 8]" if restore_rbx else ""
    tail = assemble(
        assembler,
        f"""
            mov r10, qword ptr [r11]
            sub r10, {record_size}
            mov qword ptr [r11], r10
            mov r11, qword ptr [r10]
            {rbx_restore}
            mov qword ptr [rsp], r11
        """,
        tail_address,
    )
    return saved_addrs_load + tail


def _build_compare_crash_block(
    assembler: Any,
    block_address: int,
    saved_addrs_address: int,
    crash_message: bytes | None,
    *,
    allow_absolute_saved_addrs: bool,
    restore_rbx: bool = False,
) -> bytes:
    message_block = ""
    if crash_message:
        message_block = f"""
            mov eax, 1
            mov edi, 2
            lea rsi, qword ptr [rip + crash_message]
            mov edx, {len(crash_message)}
            syscall
        """

    data_block = ""
    if crash_message:
        data_block = f"""
            crash_message:
            {_byte_directive(crash_message)}
        """

    saved_addrs_load = load_r11_with_address(
        assembler,
        block_address,
        saved_addrs_address,
        allow_absolute=allow_absolute_saved_addrs,
    )
    tail_address = block_address + len(saved_addrs_load)
    record_size = 16 if restore_rbx else 8
    rbx_restore = "mov rbx, qword ptr [r10 + 8]" if restore_rbx else ""
    tail = assemble(
        assembler,
        f"""
            mov r10, qword ptr [r11]
            sub r10, {record_size}
            mov qword ptr [r11], r10
            mov r11, qword ptr [r10]
            cmp qword ptr [rsp], r11
            je return_address_ok
            {message_block}
            ud2
            {data_block}
        return_address_ok:
            {rbx_restore}
        """,
        tail_address,
    )
    return saved_addrs_load + tail


def _byte_directive(data: bytes) -> str:
    return ".byte " + ", ".join(f"0x{byte:02x}" for byte in data)


def _collect_near_return_site_at_index(
    instructions: list[Any],
    ret_index: int,
) -> ReturnSite:
    ret_instruction = instructions[ret_index]
    selected: list[Any] = []
    total_size = ret_instruction.size

    for instruction in reversed(instructions[:ret_index]):
        ensure_relocatable_instruction(instruction, "return")
        selected.append(instruction)
        total_size += instruction.size
        if total_size >= NEAR_JUMP_SIZE:
            return ReturnSite(
                tuple(reversed(selected)),
                ret_instruction,
                ReturnPatchStrategy.NEAR_JUMP,
            )

    raise SkipFunction(
        f"could not collect enough bytes before return at 0x{ret_instruction.address:x}"
    )


def _collect_rbx_return_sites(
    instructions: list[Any],
    ret_indexes: list[int],
) -> list[ReturnSite] | None:
    if len(ret_indexes) != 1:
        return None
    if _function_mentions_rbx(instructions):
        return None

    ret_index = ret_indexes[0]
    ret_instruction = instructions[ret_index]
    selected: list[Any] = []
    total_size = ret_instruction.size

    for instruction in reversed(instructions[:ret_index]):
        ensure_relocatable_instruction(instruction, "return")
        selected.append(instruction)
        total_size += instruction.size
        if total_size == 2:
            site = ReturnSite(
                tuple(reversed(selected)),
                ret_instruction,
                ReturnPatchStrategy.RBX_JUMP,
            )
            _ensure_return_patches_are_not_branch_targets(instructions, [site])
            return [site]
        if total_size > 2:
            return None

    return None


def _function_mentions_rbx(instructions: list[Any]) -> bool:
    import capstone.x86_const as x86

    rbx_registers = {
        x86.X86_REG_RBX,
        x86.X86_REG_EBX,
        x86.X86_REG_BX,
        x86.X86_REG_BL,
        x86.X86_REG_BH,
    }

    for instruction in instructions:
        registers_read, registers_written = instruction.regs_access()
        if any(register in rbx_registers for register in registers_read):
            return True
        if any(register in rbx_registers for register in registers_written):
            return True
    return False


def _ensure_non_overlapping_return_sites(return_sites: list[ReturnSite]) -> None:
    ranges: list[tuple[int, int]] = []
    for return_site in return_sites:
        current_range = (
            return_site.patch_address,
            return_site.patch_address + return_site.overwritten_size,
        )
        if any(ranges_overlap(current_range, seen_range) for seen_range in ranges):
            raise SkipFunction("return patch ranges overlap")
        ranges.append(current_range)


def _ensure_return_patches_are_not_branch_targets(
    instructions: list[Any],
    return_sites: list[ReturnSite],
) -> None:
    patch_ranges = tuple(
        (
            return_site.patch_address,
            return_site.patch_address + return_site.overwritten_size,
        )
        for return_site in return_sites
    )

    for instruction in instructions:
        target = _direct_branch_target(instruction)
        if target is None:
            continue
        for start, end in patch_ranges:
            if start < target < end:
                raise SkipFunction("return patch range has an internal branch target")


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
