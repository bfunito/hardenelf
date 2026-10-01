"""Static discovery of printf-like call sites."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import lief

from binary_hardening.symbols import FunctionSymbol, iter_function_symbols
from binary_hardening.x86 import function_code_limit


ARG_REGISTERS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
XMM_REGISTERS = tuple(f"xmm{index}" for index in range(8))
_PLT_ENTRY_SIZE = 0x10


@dataclass(frozen=True)
class FormatFunctionSpec:
    """Calling-convention facts for one protected function."""

    name: str
    fmt_arg_index: int
    variadic: bool = True

    @property
    def format_register(self) -> str:
        return ARG_REGISTERS[self.fmt_arg_index]

    @property
    def variadic_gpr_registers(self) -> tuple[str, ...]:
        return ARG_REGISTERS[self.fmt_arg_index + 1 :]


@dataclass(frozen=True)
class FormatCall:
    """One direct call to a printf-like PLT stub that can be patched."""

    function_name: str
    call_address: int
    target_name: str
    original_target: int
    instruction_size: int
    n_variadic: int
    format_register: str


@dataclass(frozen=True)
class SkippedFormatCall:
    """A printf-like call site that cannot be patched safely."""

    function_name: str
    call_address: int
    target_name: str
    reason: str


FORMAT_FUNCTIONS = {
    "printf": FormatFunctionSpec("printf", 0),
    "fprintf": FormatFunctionSpec("fprintf", 1),
    "dprintf": FormatFunctionSpec("dprintf", 1),
    "sprintf": FormatFunctionSpec("sprintf", 1),
    "snprintf": FormatFunctionSpec("snprintf", 2),
    "syslog": FormatFunctionSpec("syslog", 1),
    "err": FormatFunctionSpec("err", 1),
    "errx": FormatFunctionSpec("errx", 1),
    "warn": FormatFunctionSpec("warn", 0),
    "warnx": FormatFunctionSpec("warnx", 0),
    "error": FormatFunctionSpec("error", 2),
    "vprintf": FormatFunctionSpec("vprintf", 0, variadic=False),
    "vfprintf": FormatFunctionSpec("vfprintf", 1, variadic=False),
    "vdprintf": FormatFunctionSpec("vdprintf", 1, variadic=False),
    "vsprintf": FormatFunctionSpec("vsprintf", 1, variadic=False),
    "vsnprintf": FormatFunctionSpec("vsnprintf", 2, variadic=False),
    "vsyslog": FormatFunctionSpec("vsyslog", 1, variadic=False),
    "verr": FormatFunctionSpec("verr", 1, variadic=False),
    "verrx": FormatFunctionSpec("verrx", 1, variadic=False),
    "vwarn": FormatFunctionSpec("vwarn", 0, variadic=False),
    "vwarnx": FormatFunctionSpec("vwarnx", 0, variadic=False),
}


def find_format_calls(
    binary: lief.ELF.Binary,
    disassembler: Any,
) -> tuple[tuple[FormatCall, ...], tuple[SkippedFormatCall, ...]]:
    """Find direct calls to supported printf-like imports."""

    plt_targets = _resolve_plt_targets(binary, disassembler)
    if not plt_targets:
        return (), ()

    calls: list[FormatCall] = []
    skipped: list[SkippedFormatCall] = []

    for function in iter_function_symbols(binary, infer_missing_sizes=True):
        instructions = _disassemble_function(binary, disassembler, function)
        for index, instruction in enumerate(instructions):
            direct_target = _direct_call_target(instruction)
            if direct_target is None:
                continue

            target_name = plt_targets.get(direct_target)
            if target_name is None:
                continue

            spec = FORMAT_FUNCTIONS[target_name]
            if not spec.variadic:
                skipped.append(
                    SkippedFormatCall(
                        function.name,
                        instruction.address,
                        target_name,
                        "va_list calls cannot be counted statically",
                    )
                )
                continue

            if instruction.size != 5:
                skipped.append(
                    SkippedFormatCall(
                        function.name,
                        instruction.address,
                        target_name,
                        "only five-byte direct calls can be patched",
                    )
                )
                continue

            n_variadic = _estimate_variadic_count(
                instructions[:index],
                spec,
                function.address,
            )
            calls.append(
                FormatCall(
                    function_name=function.name,
                    call_address=instruction.address,
                    target_name=target_name,
                    original_target=direct_target,
                    instruction_size=instruction.size,
                    n_variadic=n_variadic,
                    format_register=spec.format_register,
                )
            )

    return tuple(calls), tuple(skipped)


def _resolve_plt_targets(
    binary: lief.ELF.Binary,
    disassembler: Any,
) -> dict[int, str]:
    relocations = tuple(
        relocation
        for relocation in binary.pltgot_relocations
        if relocation.has_symbol
        and _base_symbol_name(relocation.symbol.name) in FORMAT_FUNCTIONS
    )
    got_to_name = {
        relocation.address: _base_symbol_name(relocation.symbol.name)
        for relocation in relocations
    }
    targets: dict[int, str] = {}

    for section_name in (".plt.sec", ".plt"):
        section = binary.get_section(section_name)
        if section is None:
            continue
        code = bytes(section.content)
        for instruction in disassembler.disasm(code, section.virtual_address):
            got_address = _rip_relative_jump_target(instruction)
            if got_address not in got_to_name:
                continue
            stub_address = _plt_entry_start(section, instruction.address)
            targets.setdefault(stub_address, got_to_name[got_address])
            targets.setdefault(instruction.address, got_to_name[got_address])

    plt = binary.get_section(".plt")
    plt_relocations = tuple(binary.pltgot_relocations)
    if (
        plt is not None
        and plt.size >= (len(plt_relocations) + 1) * _PLT_ENTRY_SIZE
    ):
        for index, relocation in enumerate(binary.pltgot_relocations):
            if not relocation.has_symbol:
                continue
            name = _base_symbol_name(relocation.symbol.name)
            if name in FORMAT_FUNCTIONS:
                targets.setdefault(
                    plt.virtual_address + ((index + 1) * _PLT_ENTRY_SIZE),
                    name,
                )

    plt_sec = binary.get_section(".plt.sec")
    if (
        plt_sec is not None
        and plt_sec.size >= len(plt_relocations) * _PLT_ENTRY_SIZE
    ):
        for index, relocation in enumerate(binary.pltgot_relocations):
            if not relocation.has_symbol:
                continue
            name = _base_symbol_name(relocation.symbol.name)
            if name in FORMAT_FUNCTIONS:
                targets.setdefault(
                    plt_sec.virtual_address + (index * _PLT_ENTRY_SIZE),
                    name,
                )

    return targets


def _disassemble_function(
    binary: lief.ELF.Binary,
    disassembler: Any,
    function: FunctionSymbol,
) -> list[Any]:
    code_size = function_code_limit(function)
    code = bytes(binary.get_content_from_virtual_address(function.address, code_size))
    return list(disassembler.disasm(code, function.address))


def _direct_call_target(instruction: Any) -> int | None:
    import capstone
    import capstone.x86_const as x86

    if not instruction.group(capstone.CS_GRP_CALL):
        return None
    if len(instruction.operands) != 1:
        return None

    operand = instruction.operands[0]
    if operand.type != x86.X86_OP_IMM:
        return None
    return int(operand.imm)


def _rip_relative_jump_target(instruction: Any) -> int | None:
    import capstone
    import capstone.x86_const as x86

    if not instruction.group(capstone.CS_GRP_JUMP):
        return None
    if len(instruction.operands) != 1:
        return None

    operand = instruction.operands[0]
    if operand.type != x86.X86_OP_MEM or operand.mem.base != x86.X86_REG_RIP:
        return None
    return instruction.address + instruction.size + operand.mem.disp


def _plt_entry_start(section: lief.ELF.Section, instruction_address: int) -> int:
    offset = instruction_address - section.virtual_address
    if offset < 0:
        return instruction_address
    return section.virtual_address + ((offset // _PLT_ENTRY_SIZE) * _PLT_ENTRY_SIZE)


def _estimate_variadic_count(
    previous_instructions: list[Any],
    spec: FormatFunctionSpec,
    function_address: int,
) -> int:
    window = _call_setup_window(previous_instructions)
    gpr_count = _count_gpr_variadic_args(window, spec)
    vector_count = _vector_argument_count(window)
    stack_count = _stack_argument_count(window, function_address)
    return gpr_count + vector_count + stack_count


def _call_setup_window(instructions: list[Any], limit: int = 96) -> list[Any]:
    import capstone

    start = max(0, len(instructions) - limit)
    for index in range(len(instructions) - 1, start - 1, -1):
        instruction = instructions[index]
        if (
            instruction.group(capstone.CS_GRP_CALL)
            or instruction.group(capstone.CS_GRP_RET)
            or instruction.mnemonic.startswith("jmp")
        ):
            start = index + 1
            break
    return instructions[start:]


def _written_registers(instructions: list[Any]) -> set[str]:
    import capstone
    import capstone.x86_const as x86

    written: set[str] = set()
    for instruction in instructions:
        for operand in instruction.operands:
            if operand.type != x86.X86_OP_REG:
                continue
            if not (operand.access & capstone.CS_AC_WRITE):
                continue
            register = _canonical_register(instruction.reg_name(operand.reg))
            if register is not None:
                written.add(register)
    return written


def _count_gpr_variadic_args(
    instructions: list[Any],
    spec: FormatFunctionSpec,
) -> int:
    count = 0
    for register in spec.variadic_gpr_registers:
        if not _register_is_live_argument(instructions, register):
            break
        count += 1
    return count


def _register_is_live_argument(instructions: list[Any], register: str) -> bool:
    for instruction in reversed(instructions):
        if _instruction_writes_register(instruction, register):
            return True
        if _instruction_reads_register(instruction, register):
            return False
    return False


def _instruction_writes_register(instruction: Any, register: str) -> bool:
    import capstone
    import capstone.x86_const as x86

    for operand in instruction.operands:
        if operand.type != x86.X86_OP_REG:
            continue
        if not (operand.access & capstone.CS_AC_WRITE):
            continue
        if _canonical_register(instruction.reg_name(operand.reg)) == register:
            return True
    return False


def _instruction_reads_register(instruction: Any, register: str) -> bool:
    import capstone
    import capstone.x86_const as x86

    for operand in instruction.operands:
        if operand.type != x86.X86_OP_REG:
            continue
        if not (operand.access & capstone.CS_AC_READ):
            continue
        if _canonical_register(instruction.reg_name(operand.reg)) == register:
            return True
    return False


def _vector_argument_count(instructions: list[Any]) -> int:
    explicit_al = _explicit_al_count(instructions)
    if explicit_al is not None:
        return explicit_al

    written = _written_registers(instructions)
    count = 0
    for register in XMM_REGISTERS:
        if register not in written:
            break
        count += 1
    return count


def _explicit_al_count(instructions: list[Any]) -> int | None:
    import capstone
    import capstone.x86_const as x86

    for instruction in reversed(instructions):
        writes_rax = False
        for operand in instruction.operands:
            if operand.type != x86.X86_OP_REG:
                continue
            if not (operand.access & capstone.CS_AC_WRITE):
                continue
            if _canonical_register(instruction.reg_name(operand.reg)) == "rax":
                writes_rax = True
                break
        if not writes_rax:
            continue

        if instruction.mnemonic == "xor" and len(instruction.operands) == 2:
            left, right = instruction.operands
            if (
                left.type == x86.X86_OP_REG
                and right.type == x86.X86_OP_REG
                and _canonical_register(instruction.reg_name(left.reg)) == "rax"
                and _canonical_register(instruction.reg_name(right.reg)) == "rax"
            ):
                return 0

        if instruction.mnemonic == "mov" and len(instruction.operands) == 2:
            source = instruction.operands[1]
            if source.type == x86.X86_OP_IMM:
                return int(source.imm) & 0xFF

        return None

    return 0


def _stack_argument_count(
    instructions: list[Any],
    function_address: int,
) -> int:
    import capstone
    import capstone.x86_const as x86

    prologue_saves = _prologue_save_addresses(instructions, function_address)
    push_count = sum(
        1
        for instruction in instructions
        if instruction.mnemonic == "push"
        and instruction.address not in prologue_saves
    )
    stack_slots: set[int] = set()

    for instruction in instructions:
        for operand in instruction.operands:
            if operand.type != x86.X86_OP_MEM:
                continue
            if not (operand.access & capstone.CS_AC_WRITE):
                continue
            if operand.mem.base != x86.X86_REG_RSP or operand.mem.disp < 0:
                continue
            stack_slots.add(operand.mem.disp // 8)

    return push_count + len(stack_slots)


def _prologue_save_addresses(
    instructions: list[Any],
    function_address: int,
) -> set[int]:
    if not instructions or instructions[0].address != function_address:
        return set()

    index = 0
    if instructions[index].mnemonic == "endbr64":
        index += 1

    if index >= len(instructions) or not _is_register_push(instructions[index], "rbp"):
        return set()
    rbp_push = instructions[index]
    index += 1

    if index >= len(instructions) or not _is_mov_rbp_rsp(instructions[index]):
        return set()
    index += 1

    saves = {rbp_push.address}
    while index < len(instructions) and _is_callee_saved_push(instructions[index]):
        saves.add(instructions[index].address)
        index += 1
    return saves


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


def _is_register_push(instruction: Any, register: str) -> bool:
    import capstone.x86_const as x86

    return (
        instruction.mnemonic == "push"
        and len(instruction.operands) == 1
        and instruction.operands[0].type == x86.X86_OP_REG
        and instruction.reg_name(instruction.operands[0].reg) == register
    )


def _is_callee_saved_push(instruction: Any) -> bool:
    return any(
        _is_register_push(instruction, register)
        for register in ("rbx", "r12", "r13", "r14", "r15")
    )


def _canonical_register(name: str) -> str | None:
    aliases = {
        "rax": "rax",
        "eax": "rax",
        "ax": "rax",
        "al": "rax",
        "rdi": "rdi",
        "edi": "rdi",
        "di": "rdi",
        "dil": "rdi",
        "rsi": "rsi",
        "esi": "rsi",
        "si": "rsi",
        "sil": "rsi",
        "rdx": "rdx",
        "edx": "rdx",
        "dx": "rdx",
        "dl": "rdx",
        "rcx": "rcx",
        "ecx": "rcx",
        "cx": "rcx",
        "cl": "rcx",
        "r8": "r8",
        "r8d": "r8",
        "r8w": "r8",
        "r8b": "r8",
        "r9": "r9",
        "r9d": "r9",
        "r9w": "r9",
        "r9b": "r9",
    }
    if name in aliases:
        return aliases[name]
    if name in XMM_REGISTERS:
        return name
    return None


def _base_symbol_name(symbol_name: str) -> str:
    return symbol_name.split("@", 1)[0]


__all__ = [
    "FORMAT_FUNCTIONS",
    "FormatCall",
    "FormatFunctionSpec",
    "SkippedFormatCall",
    "find_format_calls",
]
