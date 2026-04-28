"""Function-entry trampoline discovery and code generation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import lief

from binary_hardening.relocation import relocate_instruction
from binary_hardening.x86 import (
    NEAR_JUMP_SIZE,
    SkipFunction,
    assemble,
    ensure_relocatable_instruction,
    function_code_limit,
    load_r11_with_address,
    make_jump,
)


@dataclass(frozen=True)
class EntryTrampoline:
    """Summary of an entry trampoline written for one function."""

    function_name: str
    function_address: int
    trampoline_address: int
    overwritten_size: int
    original_bytes: bytes


def collect_entry_instructions(
    binary: lief.ELF.Binary,
    disassembler: Any,
    function: Any,
) -> list[Any]:
    max_size = function_code_limit(function)
    if max_size < NEAR_JUMP_SIZE:
        raise SkipFunction("function is smaller than a near jump")

    code_size = min(max_size, 64)
    code = bytes(binary.get_content_from_virtual_address(function.address, code_size))
    instructions: list[Any] = []
    total_size = 0

    for instruction in disassembler.disasm(code, function.address):
        ensure_relocatable_instruction(instruction, "entry")
        instructions.append(instruction)
        total_size += instruction.size
        if total_size >= NEAR_JUMP_SIZE:
            return instructions

    raise SkipFunction("could not disassemble enough entry bytes")


def build_entry_trampoline(
    *,
    assembler: Any,
    instructions: list[Any],
    trampoline_address: int,
    return_address: int,
    saved_addrs_address: int,
    allow_absolute_saved_addrs: bool = True,
) -> bytes:
    register_save = assemble(
        assembler,
        """
            pushfq
            push rax
            push r10
            push r11
        """,
        trampoline_address,
    )
    saved_addrs_load_address = trampoline_address + len(register_save)
    saved_addrs_load = load_r11_with_address(
        assembler,
        saved_addrs_load_address,
        saved_addrs_address,
        allow_absolute=allow_absolute_saved_addrs,
    )
    prologue_tail_address = saved_addrs_load_address + len(saved_addrs_load)
    prologue_tail = assemble(
        assembler,
        """
            mov r10, qword ptr [r11]
            test r10, r10
            jne cursor_ready
            lea r10, qword ptr [r11 + 8]
        cursor_ready:
            mov rax, qword ptr [rsp + 32]
            mov qword ptr [r10], rax
            add r10, 8
            mov qword ptr [r11], r10
            pop r11
            pop r10
            pop rax
            popfq
        """,
        prologue_tail_address,
    )
    prologue = register_save + saved_addrs_load + prologue_tail

    relocated_address = trampoline_address + len(prologue)
    relocated = bytearray()
    for instruction in instructions:
        relocated_instruction = relocate_instruction(
            assembler,
            instruction,
            relocated_address + len(relocated),
        )
        relocated.extend(relocated_instruction)

    jump_back_address = relocated_address + len(relocated)
    return prologue + bytes(relocated) + make_jump(jump_back_address, return_address)
