"""Backward-compatible CLI entrypoint."""

from binary_hardening.cli import main

__all__ = ["main"]


if __name__ == "__main__":
    raise SystemExit(main())
