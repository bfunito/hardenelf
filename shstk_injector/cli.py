"""Command line interface for the SHSTK injector prototype."""

from __future__ import annotations

import argparse
from pathlib import Path

from shstk_injector import __version__
from shstk_injector.expand import ExpansionResult, expand_binary
from shstk_injector.inject import EntryInjectionResult, inject_entry_trampolines
from shstk_injector.return_trampoline import ReturnAddressAction


def main(argv: list[str] | None = None) -> int:
    parser = _make_parser()
    args = parser.parse_args(argv)
    if (
        args.crash_message is not None
        and args.return_address_action != ReturnAddressAction.COMPARE_CRASH.value
    ):
        parser.error("--crash-message requires --return-address-action compare-crash")

    try:
        if args.expand_only:
            result = expand_binary(
                args.input,
                args.output,
                shadow_size=args.shadow_size,
                saved_addrs_size=args.saved_addrs_size,
            )
        else:
            result = inject_entry_trampolines(
                args.input,
                args.output,
                shadow_size=args.shadow_size,
                saved_addrs_size=args.saved_addrs_size,
                return_address_action=args.return_address_action,
                crash_message=args.crash_message,
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


def _print_result(result: ExpansionResult | EntryInjectionResult) -> None:
    print(f"wrote {result.output_path}")
    for section in (result.shadow, result.saved_addrs):
        flags = ",".join(section.flags)
        print(
            f"{section.name}: "
            f"va=0x{section.virtual_address:x} "
            f"offset=0x{section.file_offset:x} "
            f"size=0x{section.size:x} "
            f"flags={flags}"
        )
    if isinstance(result, EntryInjectionResult):
        print(f"pie: {'yes' if result.is_pie else 'no'}")
        print(f"entry trampolines: {len(result.trampolines)}")
        print(f"return trampolines: {len(result.return_trampolines)}")
        if result.skipped:
            print(f"skipped functions: {len(result.skipped)}")


if __name__ == "__main__":
    raise SystemExit(main())
