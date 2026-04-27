# SHSTK Injector

Prototype binary rewriter for injecting security hardening passes into
non-stripped ELF binaries, including PIE executables. The current implementation
ships three pipeline steps:

- `shadow-stack`, which expands the target binary with `.shadow` and
  `.saved_addrs` sections and then patches function entry and return sites with
  trampolines that save return addresses and either restore them or validate
  them before returning.
- `rng-patcher`, which rewrites imported libc RNG symbols to `saferand_*`,
  adds `libsaferand.so` as a dependency, and emits the shared library next to
  the patched binary with `$ORIGIN` in `RUNPATH`.
- `fmtstr-checker`, which patches direct calls to printf-like PLT stubs through
  per-call trampolines. Each trampoline checks the runtime format string with
  `libcheckformat.so` before tail-jumping to the original libc function.

## Usage

Install the package in editable mode:

```bash
python -m pip install -e .
```

Rewrite an ELF binary with all implemented pipeline steps:

```bash
shstk-injector ./input-binary ./patched-binary
```

Select a subset of the pipeline explicitly:

```bash
shstk-injector --step shadow-stack ./input-binary ./patched-binary
```

Patch only the unsafe RNG imports:

```bash
shstk-injector --step rng-patcher ./input-binary ./patched-binary
```

Patch only printf-like calls:

```bash
shstk-injector --step fmtstr-checker ./input-binary ./patched-binary
```

The format-string checker currently protects direct x86-64 PLT calls where the
number of variadic arguments can be recovered from the call setup. It skips
`va_list` forwarding APIs such as `vprintf`, because the number of arguments in
the `va_list` is not statically recoverable at the call site.

The current `shadow-stack` step still accepts its existing options. By default,
return trampolines restore the saved return address. To compare the saved and
live return addresses and crash on mismatch instead:

```bash
shstk-injector --return-address-action compare-crash ./input-binary ./patched-binary
```

Compare-and-crash mode can print a custom message to stderr before trapping:

```bash
shstk-injector \
  --return-address-action compare-crash \
  --crash-message "shadow stack mismatch" \
  ./input-binary ./patched-binary
```

Only expand the binary with the sections required by the `shadow-stack` step:

```bash
shstk-injector --expand-only ./input-binary ./expanded-binary
```

Optional section sizes accept decimal or `0x`-prefixed values:

```bash
shstk-injector --shadow-size 0x2000 --saved-addrs-size 0x2000 ./input ./output
```

Run the tests:

```bash
python -m pytest
```
