# hardenelf

Prototype binary rewriter for injecting security hardening passes into
non-stripped ELF binaries, including PIE executables. The current implementation
ships four pipeline steps:

- `initialize-frames`, which patches conventional frame-pointer functions so
  their allocated stack frame is zeroed immediately after setup.
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
hardenelf ./input-binary ./patched-binary
```

Select a subset of the pipeline explicitly. Repeating `--pass` preserves the
order you provide:

```bash
hardenelf --pass shadow-stack ./input-binary ./patched-binary
hardenelf \
  --pass fmtstr-checker \
  --pass rng-patcher \
  ./input-binary \
  ./patched-binary
```

Patch only the unsafe RNG imports:

```bash
hardenelf --pass rng-patcher ./input-binary ./patched-binary
```

Patch only stack-frame initialization:

```bash
hardenelf --pass initialize-frames ./input-binary ./patched-binary
```

The frame initializer currently targets x86-64 functions with the canonical
`push rbp; mov rbp, rsp; sub rsp, imm` prologue emitted by unoptimized builds.
Functions without an allocated frame are reported as skipped.

Patch only printf-like calls:

```bash
hardenelf --pass fmtstr-checker ./input-binary ./patched-binary
```

The format-string checker currently protects direct x86-64 PLT calls where the
number of variadic arguments can be recovered from the call setup. It skips
`va_list` forwarding APIs such as `vprintf`, because the number of arguments in
the `va_list` is not statically recoverable at the call site.

The `shadow-stack` step exposes its own options. By default, return trampolines
restore the saved return address. To compare the saved and live return addresses
and crash on mismatch instead:

```bash
hardenelf --ret compare-crash ./input-binary ./patched-binary
```

Compare-and-crash mode can print a custom message to stderr before trapping:

```bash
hardenelf \
  --ret compare-crash \
  --message "shadow stack mismatch" \
  ./input-binary ./patched-binary
```

If all jump-based return patch strategies fail, `--trap ask` prompts
before using the costly one-byte `int3`/`SIGTRAP` fallback. Use
`--trap allow` or `--trap skip` for non-interactive runs.

Only expand the binary with the sections required by the `shadow-stack` step:

```bash
hardenelf --expand ./input-binary ./expanded-binary
```

By default, `.shadow`, `.fmtstr_tramp`, and `.init_frames` are sized
automatically from the generated trampoline bodies and rounded up to a page
boundary. You can still override section sizes with decimal or `0x`-prefixed
values:

```bash
hardenelf --shadow 0x2000 --saved 0x2000 --fmtstr 0x3000 --frames 0x3000 ./input ./output
```

Use `--shadow auto`, `--fmtstr auto`, or `--frames auto` to request the default
automatic behavior explicitly.

Run the tests:

```bash
python -m pytest
```
