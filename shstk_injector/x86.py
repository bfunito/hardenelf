"""Backward-compatible imports for shared x86 helpers."""

from binary_hardening.x86 import (
    NEAR_JUMP_SIZE,
    RIP_RELATIVE_LEA_R11_SIZE,
    SkipFunction,
    assemble,
    ensure_relocatable_instruction,
    ensure_x86_64,
    function_code_limit,
    is_pie_binary,
    is_return_instruction,
    load_r11_with_address,
    make_assembler,
    make_disassembler,
    make_jump,
    pad_to_alignment,
    ranges_overlap,
)

__all__ = [
    "NEAR_JUMP_SIZE",
    "RIP_RELATIVE_LEA_R11_SIZE",
    "SkipFunction",
    "assemble",
    "ensure_relocatable_instruction",
    "ensure_x86_64",
    "function_code_limit",
    "is_pie_binary",
    "is_return_instruction",
    "load_r11_with_address",
    "make_assembler",
    "make_disassembler",
    "make_jump",
    "pad_to_alignment",
    "ranges_overlap",
]
