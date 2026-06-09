"""Command line interface for the binary hardening pipeline."""

from __future__ import annotations

import argparse
from importlib.metadata import PackageNotFoundError, version
import os
import sys
from pathlib import Path

from fmtstr_checker.step import (
    FMTSTR_CHECKER_STEP,
    FmtStrCheckerStepOptions,
    FmtStrPatchResult,
)
from initialize_frames.step import (
    INITIALIZE_FRAMES_STEP,
    FrameInitializationResult,
    InitializeFramesStepOptions,
)
from safe_rng.step import RngPatchResult
from shstk_injector.expand import ExpansionResult
from shstk_injector.return_trampoline import ReturnAddressAction
from shstk_injector.steps.shadow_stack import (
    SHADOW_STACK_STEP,
    InjectionResult,
    ShadowStackStepOptions,
    TrapFallbackDecision,
)

from .api import run_hardening_pipeline
from .pipeline import PipelineResult
from .registry import (
    available_step_names,
    available_steps,
)


class _CliHelpFormatter(argparse.RawTextHelpFormatter):
    def __init__(self, *args: object, **kwargs: object) -> None:
        kwargs.setdefault("max_help_position", 30)
        kwargs.setdefault("width", 96)
        super().__init__(*args, **kwargs)


def main(argv: list[str] | None = None) -> int:
    parser = _make_parser()
    args = parser.parse_args(argv)
    selected_steps = tuple(args.steps or available_step_names())
    if (
        args.crash_message is not None
        and args.return_address_action != ReturnAddressAction.COMPARE_CRASH.value
    ):
        parser.error("--crash-message requires --return-address-action compare-crash")
    _validate_shadow_stack_selection(parser, args, selected_steps)
    _validate_initialize_frames_selection(parser, args, selected_steps)
    _validate_fmtstr_selection(parser, args, selected_steps)

    try:
        trap_fallback_callback = (
            _prompt_trap_fallback
            if args.trap_fallback == TrapFallbackDecision.ASK.value
            else None
        )
        result = run_hardening_pipeline(
            args.input,
            args.output,
            steps=selected_steps,
            shadow_stack_options=ShadowStackStepOptions(
                shadow_size=args.shadow_size,
                saved_addrs_size=args.saved_addrs_size,
                return_address_action=args.return_address_action,
                crash_message=args.crash_message,
                expand_only=args.expand_only,
                trap_fallback=args.trap_fallback,
                trap_fallback_callback=trap_fallback_callback,
            ),
            fmtstr_checker_options=FmtStrCheckerStepOptions(
                trampoline_size=args.fmtstr_trampoline_size,
            ),
            initialize_frames_options=InitializeFramesStepOptions(
                trampoline_size=args.init_frame_trampoline_size,
            ),
        )
    except Exception as exc:
        parser.exit(1, f"error: {exc}\n")

    _print_result(result)
    return 0


def _make_parser() -> argparse.ArgumentParser:
    step_list = "\n".join(
        f"  {name:<18} {description}" for name, description in available_steps()
    )
    parser = argparse.ArgumentParser(
        prog="hardenelf",
        description="Patch ELF binaries with selectable hardening passes.",
        epilog=(
            "passes:\n"
            f"{step_list}\n\n"
            "examples:\n"
            "  hardenelf input output\n"
            "  hardenelf -p shadow-stack -r compare-crash input output\n"
            "  hardenelf --pass fmtstr-checker --pass rng-patcher input output"
        ),
        formatter_class=_CliHelpFormatter,
    )
    parser.add_argument("input", type=Path, metavar="INPUT", help="ELF binary to patch")
    parser.add_argument("output", type=Path, metavar="OUTPUT", help="patched binary path")

    pipeline = parser.add_argument_group("pipeline")
    pipeline.add_argument(
        "-p",
        "--pass",
        dest="steps",
        action="append",
        choices=available_step_names(),
        metavar="NAME",
        help="hardening pass to run; repeat to choose order; default: all",
    )
    pipeline.add_argument(
        "--step",
        dest="steps",
        action="append",
        choices=available_step_names(),
        help=argparse.SUPPRESS,
    )

    shadow = parser.add_argument_group("shadow stack")
    shadow.add_argument(
        "-s",
        "--shadow",
        dest="shadow_size",
        type=_parse_shadow_size,
        default=None,
        metavar="SIZE",
        help=".shadow size: auto, decimal, or 0x-prefixed; default: auto",
    )
    shadow.add_argument(
        "-a",
        "--saved",
        dest="saved_addrs_size",
        type=_parse_int,
        default=0x1000,
        metavar="SIZE",
        help=".saved_addrs size: decimal or 0x-prefixed; default: 0x1000",
    )
    shadow.add_argument(
        "-e",
        "--expand",
        dest="expand_only",
        action="store_true",
        help="only add shadow-stack sections",
    )
    shadow.add_argument(
        "-r",
        "--ret",
        dest="return_address_action",
        choices=[action.value for action in ReturnAddressAction],
        default=ReturnAddressAction.RESTORE.value,
        metavar="MODE",
        help="return handling: restore or compare-crash; default: restore",
    )
    shadow.add_argument(
        "-m",
        "--message",
        dest="crash_message",
        metavar="TEXT",
        help="stderr text before compare-crash trap",
    )
    shadow.add_argument(
        "-t",
        "--trap",
        dest="trap_fallback",
        choices=[decision.value for decision in TrapFallbackDecision],
        default=TrapFallbackDecision.ASK.value,
        metavar="MODE",
        help="SIGTRAP fallback: ask, allow, or skip; default: ask",
    )

    trampolines = parser.add_argument_group("trampoline space")
    trampolines.add_argument(
        "-f",
        "--fmtstr",
        dest="fmtstr_trampoline_size",
        type=_parse_int,
        default=0x4000,
        metavar="SIZE",
        help=".fmtstr_tramp size: decimal or 0x-prefixed; default: 0x4000",
    )
    trampolines.add_argument(
        "-i",
        "--frames",
        dest="init_frame_trampoline_size",
        type=_parse_int,
        default=0x4000,
        metavar="SIZE",
        help=".init_frames size: decimal or 0x-prefixed; default: 0x4000",
    )

    compatibility = parser.add_argument_group("compatibility")
    compatibility.add_argument(
        "--shadow-size",
        dest="shadow_size",
        type=_parse_shadow_size,
        help=argparse.SUPPRESS,
    )
    compatibility.add_argument(
        "--saved-addrs-size",
        dest="saved_addrs_size",
        type=_parse_int,
        help=argparse.SUPPRESS,
    )
    compatibility.add_argument(
        "--fmtstr-trampoline-size",
        dest="fmtstr_trampoline_size",
        type=_parse_int,
        help=argparse.SUPPRESS,
    )
    compatibility.add_argument(
        "--init-frame-trampoline-size",
        dest="init_frame_trampoline_size",
        type=_parse_int,
        help=argparse.SUPPRESS,
    )
    compatibility.add_argument(
        "--expand-only",
        dest="expand_only",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    compatibility.add_argument(
        "--return-address-action",
        dest="return_address_action",
        choices=[action.value for action in ReturnAddressAction],
        help=argparse.SUPPRESS,
    )
    compatibility.add_argument(
        "--crash-message",
        dest="crash_message",
        help=argparse.SUPPRESS,
    )
    compatibility.add_argument(
        "--trap-fallback",
        dest="trap_fallback",
        choices=[decision.value for decision in TrapFallbackDecision],
        help=argparse.SUPPRESS,
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {_package_version()}",
    )
    return parser


def _package_version() -> str:
    try:
        return version("hardenelf")
    except PackageNotFoundError:
        return "0.1.0"


def _parse_int(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def _parse_shadow_size(value: str) -> int | None:
    if value == "auto":
        return None
    return _parse_int(value)


def _color_enabled() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _style(text: str, code: str) -> str:
    if not _color_enabled():
        return text
    return f"\033[{code}m{text}\033[0m"


def _accent(text: str) -> str:
    return _style(text, "1;36")


def _success(text: str) -> str:
    return _style(text, "1;32")


def _muted(text: str) -> str:
    return _style(text, "2")


def _print_fact(indent: str, label: str, value: object) -> None:
    print(f"{indent}{_muted(f'{label}:')} {value}")


def _validate_shadow_stack_selection(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    selected_steps: tuple[str, ...],
) -> None:
    if SHADOW_STACK_STEP in selected_steps:
        return

    shadow_stack_options_requested = (
        args.expand_only
        or args.shadow_size is not None
        or args.saved_addrs_size != 0x1000
        or args.return_address_action != ReturnAddressAction.RESTORE.value
        or args.crash_message is not None
        or args.trap_fallback != TrapFallbackDecision.ASK.value
    )
    if shadow_stack_options_requested:
        parser.error("shadow-stack options require the shadow-stack pipeline step")


def _validate_fmtstr_selection(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    selected_steps: tuple[str, ...],
) -> None:
    if FMTSTR_CHECKER_STEP in selected_steps:
        return

    if args.fmtstr_trampoline_size != 0x4000:
        parser.error(
            "--fmtstr-trampoline-size requires the fmtstr-checker pipeline step"
        )


def _validate_initialize_frames_selection(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    selected_steps: tuple[str, ...],
) -> None:
    if INITIALIZE_FRAMES_STEP in selected_steps:
        return

    if args.init_frame_trampoline_size != 0x4000:
        parser.error(
            "--init-frame-trampoline-size requires the initialize-frames pipeline step"
        )


def _print_result(result: PipelineResult) -> None:
    print(_accent("hardenelf"))
    print(f"{_success('OK')} output: {result.output_path}")
    if len(result.steps) == 1:
        print(f"{_muted('pass:')} {result.steps[0].name}")
        _print_step_result(result.steps[0].result)
        return

    print(f"{_muted('passes:')} {', '.join(step.name for step in result.steps)}")
    for index, step in enumerate(result.steps, start=1):
        print()
        print(_accent(f"[{index}/{len(result.steps)}] {step.name}"))
        _print_step_result(step.result, indent="  ")


def _print_step_result(
    result: (
        ExpansionResult
        | InjectionResult
        | RngPatchResult
        | FmtStrPatchResult
        | FrameInitializationResult
        | object
    ),
    *,
    indent: str = "",
) -> None:
    if isinstance(result, RngPatchResult):
        _print_fact(indent, "rng imports patched", len(result.patched_imports))
        if result.library_path is not None:
            _print_fact(indent, "library", result.library_path)
        if result.runpath:
            _print_fact(indent, "runpath", ":".join(result.runpath))
        return

    if isinstance(result, FmtStrPatchResult):
        _print_fact(indent, "format calls patched", len(result.patched_calls))
        if result.skipped_calls:
            _print_fact(indent, "format calls skipped", len(result.skipped_calls))
        if result.library_path is not None:
            _print_fact(indent, "library", result.library_path)
        if result.runpath:
            _print_fact(indent, "runpath", ":".join(result.runpath))
        return

    if isinstance(result, FrameInitializationResult):
        _print_fact(indent, "initialized stack frames", len(result.initialized_frames))
        if result.skipped:
            _print_fact(indent, "stack frames skipped", len(result.skipped))
            for skipped in result.skipped:
                print(
                    f"{indent}  - {skipped.function_name} "
                    f"@ 0x{skipped.function_address:x}: {skipped.reason}"
                )
        if result.section_address is not None:
            print(
                f"{indent}{result.section_name}: "
                f"va=0x{result.section_address:x} "
                f"size=0x{result.section_size:x}"
            )
        return

    if not isinstance(result, (ExpansionResult, InjectionResult)):
        print(f"{indent}{_success('completed')}")
        return

    for section in (result.shadow, result.saved_addrs):
        flags = ",".join(section.flags)
        print(
            f"{indent}{section.name}: "
            f"va=0x{section.virtual_address:x} "
            f"offset=0x{section.file_offset:x} "
            f"size=0x{section.size:x} "
            f"flags={flags}"
        )
    if isinstance(result, InjectionResult):
        _print_fact(indent, "pie", "yes" if result.is_pie else "no")
        _print_fact(indent, "entry trampolines", len(result.trampolines))
        _print_fact(indent, "return trampolines", len(result.return_trampolines))
        if result.skipped:
            _print_fact(indent, "skipped functions", len(result.skipped))
            for skipped in result.skipped:
                print(
                    f"{indent}  - {skipped.function_name} "
                    f"@ 0x{skipped.function_address:x}: {skipped.reason}"
                )


def _prompt_trap_fallback(function_name: str, function_address: int, reason: str) -> bool:
    if not sys.stdin.isatty():
        return False

    prompt = (
        "shadow-stack trap fallback needed for "
        f"{function_name} @ 0x{function_address:x}: {reason}\n"
        "Use costly SIGTRAP-based return trampoline for this function? [y/N] "
    )
    try:
        answer = input(prompt)
    except EOFError:
        return False
    return answer.strip().lower() in {"y", "yes"}


if __name__ == "__main__":
    raise SystemExit(main())
