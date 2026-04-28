from __future__ import annotations

import ctypes
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import unittest

import lief

from binary_hardening.api import patch_rng_functions
from safe_rng.saferand import build_saferand_library
from safe_rng.step import RNG_PATCHER_STEP, RngPatchResult
from tests.fixture_binaries import (
    BIN_DIR,
    build_fixtures,
    require_injector_dependencies,
    run_binary,
    run_pipeline_fixture,
)


class RngPatcherIntegrationTests(unittest.TestCase):
    def test_rng_patcher_rewrites_imports_and_adds_library(self) -> None:
        _, output_path, result = run_pipeline_fixture(
            self,
            "rng_smoke",
            steps=(RNG_PATCHER_STEP,),
        )

        self.assertIsInstance(result.result_for_step(RNG_PATCHER_STEP), RngPatchResult)
        step_result = result.result_for_step(RNG_PATCHER_STEP)
        assert isinstance(step_result, RngPatchResult)

        self.assertIsNotNone(step_result.library_path)
        assert step_result.library_path is not None
        self.assertTrue(step_result.library_path.exists())
        self.assertIn("libsaferand.so", step_result.libraries)
        self.assertIn("$ORIGIN", step_result.runpath)

        rewritten = lief.parse(output_path)
        self.assertIsInstance(rewritten, lief.ELF.Binary)
        assert isinstance(rewritten, lief.ELF.Binary)

        imported_names = {symbol.name for symbol in rewritten.imported_symbols}
        self.assertIn("saferand_rand", imported_names)
        self.assertIn("saferand_random_r", imported_names)
        self.assertIn("saferand_seed48", imported_names)
        self.assertIn(
            "rand",
            {patched.original_name for patched in step_result.patched_imports},
        )
        self.assertIn(
            "random_r",
            {patched.original_name for patched in step_result.patched_imports},
        )
        self.assertIn(
            "seed48",
            {patched.original_name for patched in step_result.patched_imports},
        )

    def test_rng_patched_binary_breaks_seeded_determinism(self) -> None:
        input_path, output_path, _ = run_pipeline_fixture(
            self,
            "rng_smoke",
            steps=(RNG_PATCHER_STEP,),
        )

        original_first = run_binary(input_path)
        original_second = run_binary(input_path)
        patched_first = run_binary(output_path)
        patched_second = run_binary(output_path)

        self.assertEqual(original_first.returncode, 0)
        self.assertEqual(original_second.returncode, 0)
        self.assertEqual(patched_first.returncode, 0)
        self.assertEqual(patched_second.returncode, 0)
        self.assertEqual(
            original_first.stdout.splitlines()[1:],
            original_second.stdout.splitlines()[1:],
        )
        self.assertNotEqual(
            patched_first.stdout.splitlines()[1:],
            patched_second.stdout.splitlines()[1:],
        )

    def test_rng_patched_pie_binary_breaks_seeded_determinism(self) -> None:
        input_path, output_path, _ = run_pipeline_fixture(
            self,
            "rng_smoke_pie",
            steps=(RNG_PATCHER_STEP,),
        )

        rewritten = lief.parse(output_path)
        self.assertIsInstance(rewritten, lief.ELF.Binary)
        assert isinstance(rewritten, lief.ELF.Binary)
        self.assertTrue(bool(rewritten.is_pie))

        self.assertEqual(run_binary(input_path).returncode, 0)
        self.assertEqual(run_binary(output_path).returncode, 0)
        self.assertNotEqual(
            run_binary(output_path).stdout.splitlines()[1:],
            run_binary(output_path).stdout.splitlines()[1:],
        )

    def test_rng_patcher_is_noop_when_target_imports_are_absent(self) -> None:
        build_fixtures(self)
        require_injector_dependencies(self)

        input_path = BIN_DIR / "entry_smoke"
        with TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "entry_smoke.rng"
            result = patch_rng_functions(input_path, output_path)

            self.assertEqual(result.patched_imports, ())
            self.assertIsNone(result.library_path)

            rewritten = lief.parse(output_path)
            self.assertIsInstance(rewritten, lief.ELF.Binary)
            assert isinstance(rewritten, lief.ELF.Binary)
            self.assertNotIn("libsaferand.so", tuple(rewritten.libraries))

    def test_full_pipeline_runs_against_rng_fixture(self) -> None:
        input_path, output_path, result = run_pipeline_fixture(self, "rng_smoke")

        self.assertEqual(run_binary(input_path).returncode, 0)
        self.assertEqual(run_binary(output_path).returncode, 0)
        self.assertIsInstance(result.result_for_step(RNG_PATCHER_STEP), RngPatchResult)


class SaferandLibraryTests(unittest.TestCase):
    def test_bundled_library_exports_working_rng_apis(self) -> None:
        if shutil.which("gcc") is None:
            self.skipTest("gcc is not available")

        with TemporaryDirectory() as tmpdir:
            library_path = build_saferand_library(tmpdir)
            saferand = ctypes.CDLL(str(library_path))

            saferand.rand.restype = ctypes.c_int
            saferand.srand.argtypes = [ctypes.c_uint]
            saferand.rand_r.argtypes = [ctypes.POINTER(ctypes.c_uint)]
            saferand.rand_r.restype = ctypes.c_int
            saferand.random.restype = ctypes.c_long
            saferand.random_r.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int32)]
            saferand.random_r.restype = ctypes.c_int
            saferand.lrand48.restype = ctypes.c_long
            saferand.nrand48.argtypes = [ctypes.POINTER(ctypes.c_ushort)]
            saferand.nrand48.restype = ctypes.c_long
            saferand.mrand48.restype = ctypes.c_long
            saferand.jrand48.argtypes = [ctypes.POINTER(ctypes.c_ushort)]
            saferand.jrand48.restype = ctypes.c_long
            saferand.drand48.restype = ctypes.c_double
            saferand.erand48.argtypes = [ctypes.POINTER(ctypes.c_ushort)]
            saferand.erand48.restype = ctypes.c_double
            saferand.seed48.argtypes = [ctypes.POINTER(ctypes.c_ushort)]
            saferand.seed48.restype = ctypes.POINTER(ctypes.c_ushort)
            saferand.lcong48.argtypes = [ctypes.POINTER(ctypes.c_ushort)]

            first_sequence = _collect_rand_sequence(saferand)
            second_sequence = _collect_rand_sequence(saferand)

            self.assertNotEqual(first_sequence, second_sequence)

            rand_r_seed = ctypes.c_uint(0x12345678)
            rand_r_value = saferand.rand_r(ctypes.byref(rand_r_seed))
            self.assertGreaterEqual(rand_r_value, 0)
            self.assertLessEqual(rand_r_value, 0x7FFFFFFF)
            self.assertNotEqual(rand_r_seed.value, 0x12345678)

            random_r_value = ctypes.c_int32()
            self.assertEqual(saferand.random_r(ctypes.c_void_p(1), ctypes.byref(random_r_value)), 0)
            self.assertGreaterEqual(random_r_value.value, 0)

            nrand48_state = (ctypes.c_ushort * 3)(0x1111, 0x2222, 0x3333)
            nrand48_value = saferand.nrand48(nrand48_state)
            self.assertGreaterEqual(nrand48_value, 0)

            jrand48_state = (ctypes.c_ushort * 3)(0x4444, 0x5555, 0x6666)
            jrand48_value = saferand.jrand48(jrand48_state)
            self.assertGreaterEqual(jrand48_value, -(2**31))
            self.assertLess(jrand48_value, 2**31)

            self.assertGreaterEqual(saferand.lrand48(), 0)
            self.assertGreaterEqual(saferand.random(), 0)
            self.assertGreaterEqual(saferand.rand(), 0)
            self.assertGreaterEqual(saferand.drand48(), 0.0)
            self.assertLess(saferand.drand48(), 1.0)

            erand48_state = (ctypes.c_ushort * 3)(0x7777, 0x8888, 0x9999)
            erand48_value = saferand.erand48(erand48_state)
            self.assertGreaterEqual(erand48_value, 0.0)
            self.assertLess(erand48_value, 1.0)

            seed48_state = (ctypes.c_ushort * 3)(0xaaaa, 0xbbbb, 0xcccc)
            self.assertIsNotNone(saferand.seed48(seed48_state))
            lcong48_state = (ctypes.c_ushort * 7)(1, 2, 3, 4, 5, 6, 7)
            saferand.lcong48(lcong48_state)


def _collect_rand_sequence(saferand: ctypes.CDLL) -> tuple[int, int, int, int]:
    saferand.srand(12345)
    return (
        saferand.rand(),
        saferand.rand(),
        saferand.rand(),
        saferand.rand(),
    )


if __name__ == "__main__":
    unittest.main()
