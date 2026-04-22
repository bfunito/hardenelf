# SHSTK Injector

Prototype binary rewriter for injecting security hardening passes into
non-stripped ELF binaries, including PIE executables. The current implementation
ships one pipeline step, `shadow-stack`, which expands the target binary with
`.shadow` and `.saved_addrs` sections and then patches function entry and return
sites with trampolines that save return addresses and either restore them or
validate them before returning.

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
