"""Trampoline generation for stack-frame initialization."""

from __future__ import annotations

from typing import Any

from binary_hardening.relocation import relocate_instruction
from binary_hardening.x86 import assemble, make_jump
from initialize_frames.analysis import FrameInitializationSite


def build_frame_initializer_trampoline(
    *,
    assembler: Any,
    site: FrameInitializationSite,
    trampoline_address: int,
) -> bytes:
    """Build a trampoline that zeroes a frame and preserves original behavior."""

    initializer = assemble(
        assembler,
        f"""
            pushfq
            push rax
            push rcx
            push rdi
            lea rdi, qword ptr [rbp - {site.frame_size}]
            mov rcx, {site.frame_size}
            xor eax, eax
            cld
            rep stosb
            pop rdi
            pop rcx
            pop rax
            popfq
        """,
        trampoline_address,
    )

    relocated_address = trampoline_address + len(initializer)
    relocated = bytearray()
    for instruction in site.overwritten_instructions:
        relocated_instruction = relocate_instruction(
            assembler,
            instruction,
            relocated_address + len(relocated),
        )
        relocated.extend(relocated_instruction)

    jump_back_address = relocated_address + len(relocated)
    return initializer + bytes(relocated) + make_jump(
        jump_back_address,
        site.patch_address + site.overwritten_size,
    )


def make_patch_jump(site: FrameInitializationSite, trampoline_address: int) -> bytes:
    """Return the jump that replaces the original post-prologue instructions."""

    patch = make_jump(site.patch_address, trampoline_address)
    return patch + b"\x90" * (site.overwritten_size - len(patch))
