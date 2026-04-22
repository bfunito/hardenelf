"""Command line interface for the SHSTK injector prototype."""

from __future__ import annotations

import argparse
from pathlib import Path

from shstk_injector import __version__
from shstk_injector.expand import ExpansionResult
from shstk_injector.inject import EntryInjectionResult, PipelineResult, run_injection_pipeline
from shstk_injector.return_trampoline import ReturnAddressAction
from shstk_injector.steps import SHADOW_STACK_STEP, available_step_names
from shstk_injector.steps.shadow_stack import ShadowStackStepOptions


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

    try:
        result = run_injection_pipeline(
            args.input,
            args.output,
            steps=selected_steps,
            shadow_stack_options=ShadowStackStepOptions(
                shadow_size=args.shadow_size,
                saved_addrs_size=args.saved_addrs_size,
                return_address_action=args.return_address_action,
                crash_message=args.crash_message,
                expand_only=args.expand_only,
            ),
        )
    except Exception as exc:
        parser.exit(1, f"error: {exc}\n")

    _print_result(result)
    return 0


def _make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shstk-injector",
        description=(
            "Inject trampolines that save and protect return addresses in an "
            "ELF binary."
        ),
    )
    parser.add_argument("input", type=Path, help="input ELF binary")
    parser.add_argument("output", type=Path, help="rewritten output binary")
    parser.add_argument(
        "--step",
        dest="steps",
        action="append",
        choices=available_step_names(),
        help=(
            "pipeline step to run; repeat to select a subset. "
            "Defaults to all implemented steps in registry order"
        ),
    )
    parser.add_argument(
        "--shadow-size",
        type=_parse_int,
        default=0x1000,
        help="size of the executable .shadow section; accepts decimal or 0x-prefixed values",
    )
    parser.add_argument(
        "--saved-addrs-size",
        type=_parse_int,
        default=0x1000,
        help="size of the writable .saved_addrs section; accepts decimal or 0x-prefixed values",
    )
    parser.add_argument(
        "--expand-only",
        action="store_true",
        help="only add .shadow and .saved_addrs without writing entry trampolines",
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
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


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
    )
    if shadow_stack_options_requested:
        parser.error("shadow-stack options require the shadow-stack pipeline step")


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
    result: ExpansionResult | EntryInjectionResult | object,
    *,
    indent: str = "",
) -> None:
    if not isinstance(result, (ExpansionResult, EntryInjectionResult)):
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
    if isinstance(result, EntryInjectionResult):
        print(f"{indent}pie: {'yes' if result.is_pie else 'no'}")
        print(f"{indent}entry trampolines: {len(result.trampolines)}")
        print(f"{indent}return trampolines: {len(result.return_trampolines)}")
        if result.skipped:
            print(f"{indent}skipped functions: {len(result.skipped)}")


if __name__ == "__main__":
    raise SystemExit(main())
