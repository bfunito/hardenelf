"""Command line interface for the binary hardening pipeline."""

from __future__ import annotations

import argparse
from importlib.metadata import PackageNotFoundError, version
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
    PipelineOptions,
    available_step_names,
)


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
            options=PipelineOptions(
                shadow_stack=ShadowStackStepOptions(
                    shadow_size=args.shadow_size,
                    saved_addrs_size=args.saved_addrs_size,
                    return_address_action=args.return_address_action,
                    crash_message=args.crash_message,
                    expand_only=args.expand_only,
                    trap_fallback=args.trap_fallback,
                    trap_fallback_callback=trap_fallback_callback,
                ),
                fmtstr_checker=FmtStrCheckerStepOptions(
                    trampoline_size=args.fmtstr_trampoline_size,
                ),
                initialize_frames=InitializeFramesStepOptions(
                    trampoline_size=args.init_frame_trampoline_size,
                ),
            ),
        )
    except Exception as exc:
        parser.exit(1, f"error: {exc}\n")

    _print_result(result)
    return 0


def _make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hardenelf",
        description="Run selectable binary hardening passes against an ELF binary.",
    )
    parser.add_argument("input", type=Path, help="input ELF binary")
    parser.add_argument("output", type=Path, help="rewritten output binary")
    parser.add_argument(
        "--step",
        dest="steps",
        action="append",
        choices=available_step_names(),
        help=(
            "pipeline step to run; repeat in the desired order. "
            "Defaults to all implemented steps in registry order"
        ),
    )
    parser.add_argument(
        "--shadow-size",
        type=_parse_int,
        default=0x1000,
        help=(
            "size of the executable .shadow section; accepts decimal or "
            "0x-prefixed values"
        ),
    )
    parser.add_argument(
        "--saved-addrs-size",
        type=_parse_int,
        default=0x1000,
        help=(
            "size of the writable .saved_addrs section; accepts decimal or "
            "0x-prefixed values"
        ),
    )
    parser.add_argument(
        "--fmtstr-trampoline-size",
        type=_parse_int,
        default=0x4000,
        help=(
            "size of the executable .fmtstr_tramp section; accepts decimal or "
            "0x-prefixed values"
        ),
    )
    parser.add_argument(
        "--init-frame-trampoline-size",
        type=_parse_int,
        default=0x4000,
        help=(
            "size of the executable .init_frames section; accepts decimal or "
            "0x-prefixed values"
        ),
    )
    parser.add_argument(
        "--expand-only",
        action="store_true",
        help="only add .shadow and .saved_addrs without writing trampolines",
    )
    parser.add_argument(
        "--return-address-action",
        choices=[action.value for action in ReturnAddressAction],
        default=ReturnAddressAction.RESTORE.value,
        help=(
            "return-site behavior: restore saved return addresses, or compare and "
            "crash on mismatch"
        ),
    )
    parser.add_argument(
        "--crash-message",
        help="message to write to stderr before crashing in compare-crash mode",
    )
    parser.add_argument(
        "--trap-fallback",
        choices=[decision.value for decision in TrapFallbackDecision],
        default=TrapFallbackDecision.ASK.value,
        help=(
            "one-byte trap fallback for return sites that cannot use jump "
            "strategies; ask prompts per function, allow always uses it, skip never "
            "uses it"
        ),
    )
    parser.add_argument(
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


def _validate_shadow_stack_selection(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    selected_steps: tuple[str, ...],
) -> None:
    if SHADOW_STACK_STEP in selected_steps:
        return

    shadow_stack_options_requested = (
        args.expand_only
        or args.shadow_size != 0x1000
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
    print(f"wrote {result.output_path}")
    if len(result.steps) == 1:
        _print_step_result(result.steps[0].result)
        return

    print(f"pipeline steps: {', '.join(step.name for step in result.steps)}")
    for step in result.steps:
        print(f"[{step.name}]")
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
        print(f"{indent}rng imports patched: {len(result.patched_imports)}")
        if result.library_path is not None:
            print(f"{indent}library: {result.library_path}")
        if result.runpath:
            print(f"{indent}runpath: {':'.join(result.runpath)}")
        return

    if isinstance(result, FmtStrPatchResult):
        print(f"{indent}format calls patched: {len(result.patched_calls)}")
        if result.skipped_calls:
            print(f"{indent}format calls skipped: {len(result.skipped_calls)}")
        if result.library_path is not None:
            print(f"{indent}library: {result.library_path}")
        if result.runpath:
            print(f"{indent}runpath: {':'.join(result.runpath)}")
        return

    if isinstance(result, FrameInitializationResult):
        print(f"{indent}initialized stack frames: {len(result.initialized_frames)}")
        if result.skipped:
            print(f"{indent}stack frames skipped: {len(result.skipped)}")
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
        print(f"{indent}completed")
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
        print(f"{indent}pie: {'yes' if result.is_pie else 'no'}")
        print(f"{indent}entry trampolines: {len(result.trampolines)}")
        print(f"{indent}return trampolines: {len(result.return_trampolines)}")
        if result.skipped:
            print(f"{indent}skipped functions: {len(result.skipped)}")
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
