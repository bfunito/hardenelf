"""Return-site trampoline discovery and code generation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

import lief

from shstk_injector.relocation import relocate_instruction
from shstk_injector.x86 import (
    NEAR_JUMP_SIZE,
    SkipFunction,
    assemble,
    ensure_relocatable_instruction,
    function_code_limit,
    is_return_instruction,
    ranges_overlap,
)


class ReturnAddressAction(str, Enum):
    """How return trampolines handle saved return addresses."""

    RESTORE = "restore"
    COMPARE_CRASH = "compare-crash"


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


@dataclass(frozen=True)
class ReturnSite:
    instructions: tuple[Any, ...]
    ret_instruction: Any

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

    return_sites = [
        _collect_return_site_at_index(instructions, ret_index)
        for ret_index in ret_indexes
    ]
    _ensure_non_overlapping_return_sites(return_sites)
    return return_sites


def build_return_trampoline(
    *,
    assembler: Any,
    return_site: ReturnSite,
    trampoline_address: int,
    saved_addrs_address: int,
    action: ReturnAddressAction = ReturnAddressAction.RESTORE,
    crash_message: bytes | None = None,
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
        check = _build_restore_block(assembler, check_address, saved_addrs_address)
    elif action is ReturnAddressAction.COMPARE_CRASH:
        check = _build_compare_crash_block(
            assembler,
            check_address,
            saved_addrs_address,
            crash_message,
        )
    else:
        raise ValueError(f"unsupported return address action: {action}")

    return bytes(relocated) + check + bytes(return_site.ret_instruction.bytes)


def _build_restore_block(
    assembler: Any,
    block_address: int,
    saved_addrs_address: int,
) -> bytes:
    return assemble(
        assembler,
        f"""
            mov r11, 0x{saved_addrs_address:x}
            mov r10, qword ptr [r11]
            sub r10, 8
            mov qword ptr [r11], r10
            mov r10, qword ptr [r10]
            mov qword ptr [rsp], r10
        """,
        block_address,
    )


def _build_compare_crash_block(
    assembler: Any,
    block_address: int,
    saved_addrs_address: int,
    crash_message: bytes | None,
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

    return assemble(
        assembler,
        f"""
            mov r11, 0x{saved_addrs_address:x}
            mov r10, qword ptr [r11]
            sub r10, 8
            mov qword ptr [r11], r10
            mov r10, qword ptr [r10]
            cmp qword ptr [rsp], r10
            je return_address_ok
            {message_block}
            ud2
            {data_block}
        return_address_ok:
        """,
        block_address,
    )


def _byte_directive(data: bytes) -> str:
    return ".byte " + ", ".join(f"0x{byte:02x}" for byte in data)


def _collect_return_site_at_index(
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
            return ReturnSite(tuple(reversed(selected)), ret_instruction)

    raise SkipFunction(
        f"could not collect enough bytes before return at 0x{ret_instruction.address:x}"
    )


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
