from __future__ import annotations

import importlib
from pathlib import Path
import shutil
import subprocess
import unittest

from binary_hardening.api import inject_trampolines, run_hardening_pipeline
from binary_hardening.exit_trampoline import ReturnAddressAction
from shstk_injector.steps.shadow_stack import (
    ShadowStackStepOptions,
    TrapFallbackDecision,
)


TESTS_DIR = Path(__file__).resolve().parent
BIN_DIR = TESTS_DIR / "bin"
PATCHED_DIR = TESTS_DIR / "patched"


def build_fixtures(test_case: unittest.TestCase) -> None:
    if shutil.which("make") is None:
        test_case.skipTest("make is not available")
    if shutil.which("gcc") is None:
        test_case.skipTest("gcc is not available")

    result = subprocess.run(
        ["make", "-C", str(TESTS_DIR), "all"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        test_case.skipTest(f"could not build C fixtures: {result.stderr}")


def require_injector_dependencies(test_case: unittest.TestCase) -> None:
    for module_name, package_name in (
        ("capstone", "capstone"),
        ("keystone", "keystone-engine"),
    ):
        try:
            importlib.import_module(module_name)
        except ImportError:
            test_case.skipTest(f"{package_name} is not installed")


def patch_fixture(
    test_case: unittest.TestCase,
    name: str,
    *,
    hardenelf_size: int = 0x3000,
    saved_addrs_size: int = 0x2000,
    return_address_action: ReturnAddressAction | str = ReturnAddressAction.RESTORE,
    crash_message: str | bytes | None = None,
    trap_fallback: TrapFallbackDecision | str = TrapFallbackDecision.ASK,
) -> tuple[Path, Path]:
    build_fixtures(test_case)
    require_injector_dependencies(test_case)

    input_path = BIN_DIR / name
    output_path = PATCHED_DIR / f"{name}.patched"
    output_path.unlink(missing_ok=True)

    inject_trampolines(
        input_path,
        output_path,
        hardenelf_size=hardenelf_size,
        saved_addrs_size=saved_addrs_size,
        return_address_action=return_address_action,
        crash_message=crash_message,
        trap_fallback=trap_fallback,
    )
    return input_path, output_path


def run_pipeline_fixture(
    test_case: unittest.TestCase,
    name: str,
    *,
    steps: tuple[str, ...] | None = None,
    hardenelf_size: int = 0x3000,
    saved_addrs_size: int = 0x2000,
    return_address_action: ReturnAddressAction | str = ReturnAddressAction.RESTORE,
    crash_message: str | bytes | None = None,
    trap_fallback: TrapFallbackDecision | str = TrapFallbackDecision.ASK,
) -> tuple[Path, Path, object]:
    build_fixtures(test_case)
    require_injector_dependencies(test_case)

    input_path = BIN_DIR / name
    output_path = PATCHED_DIR / f"{name}.pipeline"
    output_path.unlink(missing_ok=True)
    (output_path.parent / "libsaferand.so").unlink(missing_ok=True)
    (output_path.parent / "libcheckformat.so").unlink(missing_ok=True)

    result = run_hardening_pipeline(
        input_path,
        output_path,
        steps=steps,
        shadow_stack_options=ShadowStackStepOptions(
            hardenelf_size=hardenelf_size,
            saved_addrs_size=saved_addrs_size,
            return_address_action=return_address_action,
            crash_message=crash_message,
            trap_fallback=trap_fallback,
        ),
    )
    return input_path, output_path, result


def run_binary(path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(path), *args],
        check=False,
        capture_output=True,
        text=True,
    )
