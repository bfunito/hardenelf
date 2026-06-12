"""Stack-frame initialization payload generation."""

from __future__ import annotations

from typing import Any

from binary_hardening.x86 import assemble
from initialize_frames.analysis import FrameInitializationSite


def build_frame_initializer_payload(
    *,
    assembler: Any,
    site: FrameInitializationSite,
    block_address: int,
) -> bytes:
    """Build the entry-trampoline payload that zeroes local stack storage."""

    return assemble(
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
        block_address,
    )
