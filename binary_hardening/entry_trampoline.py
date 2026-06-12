"""Neutral function-entry trampoline discovery and code generation."""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Callable
from typing import Any

import lief

from binary_hardening.x86 import (
    NEAR_JUMP_SIZE,
    SkipFunction,
    ensure_relocatable_instruction,
    function_code_limit,
    make_jump,
)
from binary_hardening.relocation import relocate_instruction


@dataclass(frozen=True)
class EntryTrampoline:
    """Summary of an entry trampoline written for one function."""

    function_name: str
    function_address: int
    trampoline_address: int
    overwritten_size: int
    original_bytes: bytes


EntryPayloadBuilder = Callable[[int], bytes]


def collect_entry_instructions(
    binary: lief.ELF.Binary,
    disassembler: Any,
    function: Any,
    *,
    min_size: int = NEAR_JUMP_SIZE,
) -> list[Any]:
    max_size = function_code_limit(function)
    required_size = max(NEAR_JUMP_SIZE, min_size)
    if max_size < required_size:
        raise SkipFunction("function is smaller than the required entry patch")

    code_size = min(max_size, 64)
    code = bytes(binary.get_content_from_virtual_address(function.address, code_size))
    instructions: list[Any] = []
    total_size = 0

    for instruction in disassembler.disasm(code, function.address):
        ensure_relocatable_instruction(instruction, "entry")
        instructions.append(instruction)
        total_size += instruction.size
        if total_size >= required_size:
            return instructions

    raise SkipFunction("could not disassemble enough entry bytes")


def build_entry_trampoline(
    *,
    assembler: Any,
    instructions: list[Any],
    trampoline_address: int,
    return_address: int,
    before_relocated: tuple[EntryPayloadBuilder, ...] = (),
    after_relocated: tuple[EntryPayloadBuilder, ...] = (),
) -> bytes:
    body = bytearray()
    for builder in before_relocated:
        body.extend(builder(trampoline_address + len(body)))

    relocated = bytearray()
    for instruction in instructions:
        relocated_instruction = relocate_instruction(
            assembler,
            instruction,
            trampoline_address + len(body) + len(relocated),
        )
        relocated.extend(relocated_instruction)

    body.extend(relocated)
    for builder in after_relocated:
        body.extend(builder(trampoline_address + len(body)))

    jump_back_address = trampoline_address + len(body)
    body.extend(make_jump(jump_back_address, return_address))
    return bytes(body)


def make_entry_patch(
    *,
    function_address: int,
    trampoline_address: int,
    overwritten_size: int,
) -> bytes:
    """Return patched bytes for a function-entry jump."""

    patch = make_jump(function_address, trampoline_address)
    return patch + b"\x90" * (overwritten_size - len(patch))
