"""Software shadow-stack trampoline injection for x86-64 ELF function symbols."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import struct
from typing import Any, Iterable

import lief

from shstk_injector.expand import (
    SAVED_ADDRS_SECTION,
    SHADOW_SECTION,
    AddedSection,
    expand_binary,
    _require_section,
    _section_summary,
)


NEAR_JUMP_SIZE = 5
SHADOW_STACK_CURSOR_SIZE = 8
_RIP_OPERAND_RE = re.compile(r"\brip(?:\s*([+-])\s*(0x[0-9a-fA-F]+|\d+))?")
_SKIPPED_ENTRY_SYMBOLS = frozenset({"_start"})


@dataclass(frozen=True)
class EntryTrampoline:
    """Summary of an entry trampoline written for one function."""

    function_name: str
    function_address: int
    trampoline_address: int
    overwritten_size: int
    original_bytes: bytes


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
class SkippedFunction:
    """A function symbol that could not be patched safely."""

    function_name: str
    function_address: int
    reason: str


@dataclass(frozen=True)
class EntryInjectionResult:
    """Summary returned after adding entry and return trampolines."""

    output_path: Path
    shadow: AddedSection
    saved_addrs: AddedSection
    trampolines: tuple[EntryTrampoline, ...]
    skipped: tuple[SkippedFunction, ...]
    return_trampolines: tuple[ReturnTrampoline, ...] = ()


@dataclass(frozen=True)
class _FunctionSymbol:
    name: str
    address: int
    size: int
    section: lief.ELF.Section


@dataclass(frozen=True)
class _ReturnSite:
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


def inject_entry_trampolines(
    input_path: Path | str,
    output_path: Path | str,
    *,
    shadow_size: int = 0x1000,
    saved_addrs_size: int = 0x1000,
) -> EntryInjectionResult:
    """Expand an ELF binary and patch function entries and returns.

    The first eight bytes of ``.saved_addrs`` hold a runtime cursor. Saved
    return addresses start immediately after that cursor.
    """

    disassembler = _make_disassembler()
    assembler = _make_assembler()

    expanded = expand_binary(
        input_path,
        output_path,
        shadow_size=shadow_size,
        saved_addrs_size=saved_addrs_size,
    )
    output_file = expanded.output_path

    binary = lief.parse(output_file)
    if binary is None or not isinstance(binary, lief.ELF.Binary):
        raise ValueError(f"LIEF could not parse expanded binary {output_file}")
    _ensure_x86_64(binary)

    shadow = _require_section(binary, SHADOW_SECTION)
    saved_addrs = _require_section(binary, SAVED_ADDRS_SECTION)
    if saved_addrs.size <= SHADOW_STACK_CURSOR_SIZE:
        raise ValueError(".saved_addrs must be larger than eight bytes")

    shadow_cursor = shadow.virtual_address
    shadow_end = shadow.virtual_address + shadow.size
    trampolines: list[EntryTrampoline] = []
    return_trampolines: list[ReturnTrampoline] = []
    skipped: list[SkippedFunction] = []

    for function in _iter_function_symbols(binary):
        try:
            entry_instructions = _collect_entry_instructions(
                binary,
                disassembler,
                function,
            )
            return_sites = _collect_return_sites(binary, disassembler, function)

            entry_overwritten_size = sum(
                instruction.size for instruction in entry_instructions
            )
            entry_patch_range = (
                function.address,
                function.address + entry_overwritten_size,
            )
            for return_site in return_sites:
                return_patch_range = (
                    return_site.patch_address,
                    return_site.patch_address + return_site.overwritten_size,
                )
                if _ranges_overlap(entry_patch_range, return_patch_range):
                    raise _SkipFunction("entry and return patches overlap")

            entry_body = _build_entry_trampoline(
                assembler=assembler,
                instructions=entry_instructions,
                trampoline_address=shadow_cursor,
                return_address=function.address + entry_overwritten_size,
                saved_addrs_address=saved_addrs.virtual_address,
            )
            entry_body = _pad_to_alignment(entry_body)
            return_bodies: list[tuple[_ReturnSite, int, bytes]] = []
            next_shadow_cursor = shadow_cursor + len(entry_body)

            for return_site in return_sites:
                return_body = _build_return_trampoline(
                    assembler=assembler,
                    return_site=return_site,
                    trampoline_address=next_shadow_cursor,
                    saved_addrs_address=saved_addrs.virtual_address,
                )
                return_body = _pad_to_alignment(return_body)
                return_bodies.append((return_site, next_shadow_cursor, return_body))
                next_shadow_cursor += len(return_body)

            if next_shadow_cursor > shadow_end:
                skipped.append(
                    SkippedFunction(
                        function.name,
                        function.address,
                        "not enough room left in .shadow",
                    )
                )
                continue

            entry_patch = _make_jump(function.address, shadow_cursor)
            entry_patch += b"\x90" * (entry_overwritten_size - NEAR_JUMP_SIZE)

            binary.patch_address(shadow_cursor, list(entry_body))
            binary.patch_address(function.address, list(entry_patch))

            trampolines.append(
                EntryTrampoline(
                    function_name=function.name,
                    function_address=function.address,
                    trampoline_address=shadow_cursor,
                    overwritten_size=entry_overwritten_size,
                    original_bytes=b"".join(
                        bytes(instruction.bytes) for instruction in entry_instructions
                    ),
                )
            )

            for return_site, return_trampoline_address, return_body in return_bodies:
                return_patch = _make_jump(
                    return_site.patch_address,
                    return_trampoline_address,
                )
                return_patch += b"\x90" * (
                    return_site.overwritten_size - NEAR_JUMP_SIZE
                )

                binary.patch_address(return_trampoline_address, list(return_body))
                binary.patch_address(return_site.patch_address, list(return_patch))
                return_trampolines.append(
                    ReturnTrampoline(
                        function_name=function.name,
                        function_address=function.address,
                        return_address=return_site.ret_instruction.address,
                        patch_address=return_site.patch_address,
                        trampoline_address=return_trampoline_address,
                        overwritten_size=return_site.overwritten_size,
                        original_bytes=return_site.original_bytes,
                    )
                )

            shadow_cursor = next_shadow_cursor
        except _SkipFunction as exc:
            skipped.append(SkippedFunction(function.name, function.address, str(exc)))

    if not trampolines:
        raise ValueError("no complete function trampolines were written")

    binary.write(output_file)
    rewritten = lief.parse(output_file)
    if rewritten is None or not isinstance(rewritten, lief.ELF.Binary):
        raise ValueError(f"LIEF wrote {output_file}, but could not parse it back")

    return EntryInjectionResult(
        output_path=output_file,
        shadow=_section_summary(_require_section(rewritten, SHADOW_SECTION)),
        saved_addrs=_section_summary(_require_section(rewritten, SAVED_ADDRS_SECTION)),
        trampolines=tuple(trampolines),
        skipped=tuple(skipped),
        return_trampolines=tuple(return_trampolines),
    )


def _make_disassembler() -> Any:
    try:
        import capstone
    except ImportError as exc:
        raise RuntimeError("Capstone is required; install the capstone package") from exc

    disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    disassembler.detail = True
    return disassembler


def _make_assembler() -> Any:
    try:
        import keystone
    except ImportError as exc:
        raise RuntimeError(
            "Keystone is required; install the keystone-engine package"
        ) from exc

    return keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)


def _ensure_x86_64(binary: lief.ELF.Binary) -> None:
    if binary.header.machine_type != lief.ELF.ARCH.X86_64:
        raise ValueError("entry trampolines are currently implemented only for x86-64")
    if binary.header.identity_class != lief.ELF.Header.CLASS.ELF64:
        raise ValueError("entry trampolines require a 64-bit ELF binary")


def _iter_function_symbols(binary: lief.ELF.Binary) -> Iterable[_FunctionSymbol]:
    seen_addresses: set[int] = set()
    functions: list[_FunctionSymbol] = []

    for symbol in binary.symtab_symbols:
        if symbol.type != lief.ELF.Symbol.TYPE.FUNC:
            continue
        if symbol.value == 0 or symbol.name in _SKIPPED_ENTRY_SYMBOLS:
            continue
        if symbol.value in seen_addresses:
            continue

        section = binary.section_from_virtual_address(symbol.value)
        if section is None or not section.has(lief.ELF.Section.FLAGS.EXECINSTR):
            continue
        if section.name.startswith(".plt"):
            continue

        seen_addresses.add(symbol.value)
        functions.append(
            _FunctionSymbol(
                name=symbol.name or f"sub_{symbol.value:x}",
                address=symbol.value,
                size=symbol.size,
                section=section,
            )
        )

    return sorted(functions, key=lambda function: function.address)


def _collect_entry_instructions(
    binary: lief.ELF.Binary,
    disassembler: Any,
    function: _FunctionSymbol,
) -> list[Any]:
    max_size = _function_code_limit(function)
    if max_size < NEAR_JUMP_SIZE:
        raise _SkipFunction("function is smaller than a near jump")

    code_size = min(max_size, 64)
    code = bytes(binary.get_content_from_virtual_address(function.address, code_size))
    instructions: list[Any] = []
    total_size = 0

    for instruction in disassembler.disasm(code, function.address):
        _ensure_relocatable_entry_instruction(instruction)
        instructions.append(instruction)
        total_size += instruction.size
        if total_size >= NEAR_JUMP_SIZE:
            return instructions

    raise _SkipFunction("could not disassemble enough entry bytes")


def _collect_return_sites(
    binary: lief.ELF.Binary,
    disassembler: Any,
    function: _FunctionSymbol,
) -> list[_ReturnSite]:
    if function.size <= 0:
        raise _SkipFunction("function size is unknown")

    max_size = _function_code_limit(function)
    if max_size < NEAR_JUMP_SIZE:
        raise _SkipFunction("function is smaller than a near jump")

    code = bytes(binary.get_content_from_virtual_address(function.address, max_size))
    instructions = list(disassembler.disasm(code, function.address))
    if not instructions:
        raise _SkipFunction("could not disassemble function body")

    ret_indexes = [
        index
        for index, instruction in enumerate(instructions)
        if _is_return_instruction(instruction)
    ]
    if not ret_indexes:
        raise _SkipFunction("function has no return instruction")

    return_sites = [
        _collect_return_site_at_index(instructions, ret_index)
        for ret_index in ret_indexes
    ]
    _ensure_non_overlapping_return_sites(return_sites)
    return return_sites


def _collect_return_site_at_index(
    instructions: list[Any],
    ret_index: int,
) -> _ReturnSite:
    ret_instruction = instructions[ret_index]
    selected: list[Any] = []
    total_size = ret_instruction.size

    for instruction in reversed(instructions[:ret_index]):
        _ensure_relocatable_return_instruction(instruction)
        selected.append(instruction)
        total_size += instruction.size
        if total_size >= NEAR_JUMP_SIZE:
            return _ReturnSite(tuple(reversed(selected)), ret_instruction)

    raise _SkipFunction(
        f"could not collect enough bytes before return at 0x{ret_instruction.address:x}"
    )


def _ensure_non_overlapping_return_sites(return_sites: list[_ReturnSite]) -> None:
    ranges: list[tuple[int, int]] = []
    for return_site in return_sites:
        current_range = (
            return_site.patch_address,
            return_site.patch_address + return_site.overwritten_size,
        )
        if any(_ranges_overlap(current_range, seen_range) for seen_range in ranges):
            raise _SkipFunction("return patch ranges overlap")
        ranges.append(current_range)


def _function_code_limit(function: _FunctionSymbol) -> int:
    section_limit = function.section.virtual_address + function.section.size
    max_size = section_limit - function.address
    if function.size > 0:
        max_size = min(max_size, function.size)
    return max_size


def _ensure_relocatable_entry_instruction(instruction: Any) -> None:
    _ensure_relocatable_instruction(instruction, "entry")


def _ensure_relocatable_return_instruction(instruction: Any) -> None:
    _ensure_relocatable_instruction(instruction, "return")


def _ensure_relocatable_instruction(instruction: Any, context: str) -> None:
    import capstone

    blocked_groups = (
        capstone.CS_GRP_JUMP,
        capstone.CS_GRP_CALL,
        capstone.CS_GRP_RET,
        capstone.CS_GRP_IRET,
    )
    if any(instruction.group(group) for group in blocked_groups):
        raise _SkipFunction(
            f"{context} instruction {instruction.mnemonic} changes control flow"
        )


def _is_return_instruction(instruction: Any) -> bool:
    import capstone

    return instruction.group(capstone.CS_GRP_RET)


def _build_entry_trampoline(
    *,
    assembler: Any,
    instructions: list[Any],
    trampoline_address: int,
    return_address: int,
    saved_addrs_address: int,
) -> bytes:
    prologue = _assemble(
        assembler,
        f"""
            pushfq
            push rax
            push r10
            push r11
            mov r11, 0x{saved_addrs_address:x}
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
        trampoline_address,
    )

    relocated_address = trampoline_address + len(prologue)
    relocated = bytearray()
    for instruction in instructions:
        relocated_instruction = _relocate_instruction(
            assembler,
            instruction,
            relocated_address + len(relocated),
        )
        relocated.extend(relocated_instruction)

    jump_back_address = relocated_address + len(relocated)
    return prologue + bytes(relocated) + _make_jump(jump_back_address, return_address)


def _build_return_trampoline(
    *,
    assembler: Any,
    return_site: _ReturnSite,
    trampoline_address: int,
    saved_addrs_address: int,
) -> bytes:
    relocated = bytearray()
    for instruction in return_site.instructions:
        relocated_instruction = _relocate_instruction(
            assembler,
            instruction,
            trampoline_address + len(relocated),
        )
        relocated.extend(relocated_instruction)

    restore_address = trampoline_address + len(relocated)
    restore = _assemble(
        assembler,
        f"""
            mov r11, 0x{saved_addrs_address:x}
            mov r10, qword ptr [r11]
            sub r10, 8
            mov qword ptr [r11], r10
            mov r10, qword ptr [r10]
            mov qword ptr [rsp], r10
        """,
        restore_address,
    )
    return bytes(relocated) + restore + bytes(return_site.ret_instruction.bytes)


def _relocate_instruction(assembler: Any, instruction: Any, new_address: int) -> bytes:
    if not _has_rip_relative_operand(instruction):
        return bytes(instruction.bytes)

    original_target = instruction.address + instruction.size + _rip_displacement(
        instruction
    )
    new_displacement = original_target - (new_address + instruction.size)
    rewritten_operands = _rewrite_rip_operand(instruction.op_str, new_displacement)
    rewritten = _assemble(
        assembler,
        f"{instruction.mnemonic} {rewritten_operands}",
        new_address,
    )
    if len(rewritten) != instruction.size:
        raise _SkipFunction(
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
    raise _SkipFunction("missing RIP-relative displacement")


def _rewrite_rip_operand(operands: str, displacement: int) -> str:
    replacement = f"rip + 0x{displacement:x}"
    if displacement < 0:
        replacement = f"rip - 0x{-displacement:x}"

    rewritten, count = _RIP_OPERAND_RE.subn(replacement, operands, count=1)
    if count != 1:
        raise _SkipFunction("could not rewrite RIP-relative operand")
    return rewritten


def _assemble(assembler: Any, assembly: str, address: int) -> bytes:
    try:
        encoding, _ = assembler.asm(_normalize_assembly(assembly), addr=address)
    except Exception as exc:
        raise _SkipFunction(f"could not assemble trampoline code: {exc}") from exc
    return bytes(encoding)


def _normalize_assembly(assembly: str) -> str:
    return "\n".join(line.strip() for line in assembly.splitlines() if line.strip())


def _make_jump(source: int, target: int) -> bytes:
    displacement = target - (source + NEAR_JUMP_SIZE)
    if not -(2**31) <= displacement < 2**31:
        raise _SkipFunction("relative jump target is outside the signed 32-bit range")
    return b"\xe9" + struct.pack("<i", displacement)


def _ranges_overlap(left: tuple[int, int], right: tuple[int, int]) -> bool:
    return left[0] < right[1] and right[0] < left[1]


def _pad_to_alignment(body: bytes, alignment: int = 0x10) -> bytes:
    padding = (-len(body)) % alignment
    return body + (b"\x90" * padding)


class _SkipFunction(Exception):
    """Raised internally when a function cannot be patched safely."""
