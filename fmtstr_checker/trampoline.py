"""x86-64 trampoline generation for format-string checks."""

from __future__ import annotations

import struct
from typing import Any

from fmtstr_checker.analysis import FormatCall
from shstk_injector.x86 import SkipFunction, assemble, make_jump


_LOAD_R11_RIP_MEM_SIZE = 7


def build_format_trampoline(
    *,
    assembler: Any,
    call: FormatCall,
    trampoline_address: int,
    check_format_slot_address: int,
) -> bytes:
    """Build a trampoline that checks a format string then tail-jumps to libc."""

    save = assemble(
        assembler,
        """
            push rax
            push rdi
            push rsi
            push rdx
            push rcx
            push r8
            push r9
            sub rsp, 0x80
            movdqu xmmword ptr [rsp + 0x00], xmm0
            movdqu xmmword ptr [rsp + 0x10], xmm1
            movdqu xmmword ptr [rsp + 0x20], xmm2
            movdqu xmmword ptr [rsp + 0x30], xmm3
            movdqu xmmword ptr [rsp + 0x40], xmm4
            movdqu xmmword ptr [rsp + 0x50], xmm5
            movdqu xmmword ptr [rsp + 0x60], xmm6
            movdqu xmmword ptr [rsp + 0x70], xmm7
        """,
        trampoline_address,
    )

    setup_address = trampoline_address + len(save)
    setup = assemble(
        assembler,
        f"""
            mov rdi, {call.format_register}
            mov rsi, 0x{call.n_variadic:x}
        """,
        setup_address,
    )

    load_address = setup_address + len(setup)
    load = _load_r11_from_slot(
        assembler,
        load_address,
        check_format_slot_address,
    )

    check_call_address = load_address + len(load)
    check_call = assemble(assembler, "call r11", check_call_address)

    restore_address = check_call_address + len(check_call)
    restore = assemble(
        assembler,
        """
            movdqu xmm0, xmmword ptr [rsp + 0x00]
            movdqu xmm1, xmmword ptr [rsp + 0x10]
            movdqu xmm2, xmmword ptr [rsp + 0x20]
            movdqu xmm3, xmmword ptr [rsp + 0x30]
            movdqu xmm4, xmmword ptr [rsp + 0x40]
            movdqu xmm5, xmmword ptr [rsp + 0x50]
            movdqu xmm6, xmmword ptr [rsp + 0x60]
            movdqu xmm7, xmmword ptr [rsp + 0x70]
            add rsp, 0x80
            pop r9
            pop r8
            pop rcx
            pop rdx
            pop rsi
            pop rdi
            pop rax
        """,
        restore_address,
    )

    jump_address = restore_address + len(restore)
    return save + setup + load + check_call + restore + make_jump(
        jump_address,
        call.original_target,
    )


def make_call(source: int, target: int) -> bytes:
    """Build a five-byte relative call instruction."""

    displacement = target - (source + 5)
    if not -(2**31) <= displacement < 2**31:
        raise SkipFunction("relative call target is outside the signed 32-bit range")
    return b"\xe8" + struct.pack("<i", displacement)


def _load_r11_from_slot(
    assembler: Any,
    instruction_address: int,
    slot_address: int,
) -> bytes:
    displacement = slot_address - (instruction_address + _LOAD_R11_RIP_MEM_SIZE)
    if not -(2**31) <= displacement < 2**31:
        raise SkipFunction("check_format pointer is outside RIP-relative range")

    encoded = assemble(
        assembler,
        f"mov r11, qword ptr [rip {_format_signed_hex(displacement)}]",
        instruction_address,
    )
    if len(encoded) != _LOAD_R11_RIP_MEM_SIZE:
        raise SkipFunction("RIP-relative check_format load changed size")
    return encoded


def _format_signed_hex(value: int) -> str:
    if value < 0:
        return f"- 0x{-value:x}"
    return f"+ 0x{value:x}"


__all__ = [
    "build_format_trampoline",
    "make_call",
]
