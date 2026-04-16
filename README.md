# SHSTK Injector

Prototype binary rewriter for injecting a software shadow stack into non-stripped
ELF binaries. The tool expands the target binary with `.shadow` and
`.saved_addrs` sections, then patches function entry and return sites with
trampolines that save and restore return addresses.

## Usage

Install the package in editable mode:

```bash
python -m pip install -e .
```

Rewrite an ELF binary:

```bash
shstk-injector ./input-binary ./patched-binary
```

Only expand the binary with the injector sections:

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
