# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Rules

@AGENTS.md

The rules live there and only there — this file never restates them. Read `AGENTS.md` first,
then `HANDOFF.md`, `docs/STATUS.md` and `docs/PLAN.md`. Commands, settled decisions,
deployment and what the owner reviews are in the appendix at the bottom of `AGENTS.md`.

What follows is the map of the code.

## What this is

A one-shot CLI over the vendor PKCS#11 library `wtpkcs11ecp`, which drives a Rutoken
hardware wallet. Every invocation loads the library, does one thing, and exits. There is no
daemon, no config file, no state on disk.

There is no `pyca/pkcs11` or any other binding — the whole FFI layer is hand-written
`ctypes` in three files, and that is where the sharp edges are.

## Layout

| File | Role |
| --- | --- |
| `main.py` | `argparse` setup, PIN input, and one flat `if/elif` chain that picks the command |
| `commands.py` | Everything else — 2200 lines, all command logic and console output |
| `version.py` | `__version__`, the only place the version lives — see `AGENTS.md` |
| `pkcs11.py` | Loads the shared library; the `@pkcs11_command` decorator |
| `pkcs11_structs.py` | `CK_*` structures and every PKCS#11 constant the tool uses |
| `pkcs11_definitions.py` | `define_pkcs11_functions()` — `argtypes`/`restype` for each `C_*` call |
| `scripts/download_wtpkcs11ecp.py` | Fetches the vendor library from the `3rdparty` GitHub release |

## The command pattern

Every command is a **pair** of functions, and the split exists for the tests:

```python
@pkcs11_command                     # loads the library, passes it as the first argument
def sign(pkcs11, wallet_id=0, ...):
    run_command_sign(pkcs11, wallet_id=wallet_id, ...)

def run_command_sign(pkcs11, wallet_id=0, ...):   # the real body; takes the library as a parameter
    define_pkcs11_functions(pkcs11)
    ...
```

`main.py` imports and calls the decorated name. Tests either monkeypatch
`pkcs11.load_pkcs11_lib` and call the decorated name, or call `run_command_*` directly with
a `SimpleNamespace` mock. **Keep both halves when you add a command** — a body written
straight into the decorated function is untestable here.

`define_pkcs11_functions(pkcs11)` must be the first line of every `run_command_*`. It is
what installs `argtypes`/`restype`; without it `ctypes` guesses, and pointer arguments get
truncated to 32 bits on 64-bit builds. Tests neutralise it
(`monkeypatch.setattr(commands, 'define_pkcs11_functions', lambda x: None)`) because a
`SimpleNamespace` has nowhere to put those attributes.

Inside a body the shape is always the same: flat `if` steps guarded by `had_error`, with
`initialized` / `session_opened` / `logged_in` flags, and a `finally` that unwinds
`C_Logout` → `C_CloseSession` → `C_Finalize` in that order. Errors are **printed, not
raised** — see the pitfall about exit codes below.

## Non-obvious couplings

**Struct packing is per-platform, and inconsistently so.** `CK_INFO`, `CK_SLOT_INFO`,
`CK_TOKEN_INFO`, `CK_TOKEN_INFO_EXTENDED` and `CK_VERSION` set `_pack_ = 1` **only on
Windows**; `CK_ATTRIBUTE` and `CK_MECHANISM` set it **always**. That asymmetry is what the
vendor library expects. Adding `_pack_` to the first group unconditionally, or dropping it
from the second, silently misaligns fields — the calls still return `CKR_OK` and the values
come back wrong.

Every `_pack_` is paired with `_layout_ = "ms"`, which names the layout `_pack_` already
forced and silences CPython's deprecation of the implicit default (an import error from
Python 3.19). **A new `_pack_` must come with `_layout_`** — `tests/test_struct_layout.py`
fails otherwise, and also pins that the packed structures carry no padding.

**Reading an attribute takes two `C_GetAttributeValue` calls.** `safe_get_attributes()`
asks for the length first (`pValue=None`), allocates, then asks again. It returns `None` for
the whole object on `CKR_OBJECT_HANDLE_INVALID` and skips an attribute whose length comes
back as `(CK_ULONG)-1`. Never call `C_GetAttributeValue` directly — go through it.
`CKA_KEY_TYPE` is the one attribute it decodes, into an `int` using `sys.byteorder`;
everything else stays `bytes`.

**`key-number` is a position, not an identifier.** `--list-keys`, `--delete-key` and
`--sign` each rebuild the list from scratch: pair public and private handles by `CKA_ID`,
then `sorted(enumerate(pairs), key=lambda i: (i[1]['key_id'] or b'', i[0]))`, 1-based. So a
number is only valid against a listing made with the *same* PIN state — `--list-keys`
without `--pin` sees public keys only, and its numbering can differ from what
`--delete-key --pin ...` will act on. Change the sort in one place and you must change all
three.

**Key derivation for `--import-key` happens in Python, not on the token.**
`run_command_import_keys` does BIP39 itself — `PBKDF2-HMAC-SHA512(mnemonic, b"mnemonic",
2048)`, then `HMAC-SHA512(b"Bitcoin seed", seed)` split into master key and chain code — and
ships the result via `C_CreateObject` with `CKK_VENDOR_BIP32`. Generation with
`--get-mnemonic` is the opposite: the token does everything through the vendor mechanism
`CKM_VENDOR_BIP32_WITH_BIP39_KEY_PAIR_GEN` and the phrase is read back off the token. The
two paths must agree on the attribute template or an imported key will not behave like a
generated one.

**Secrets are wiped by hand.** Mnemonics, seeds and master keys live in `bytearray`s that
the `finally` block clears with `_zero_bytearray()`, and the `ctypes` buffers handed to the
library are cleared with `ctypes.memset` right after. `bytes` is immutable and cannot be
wiped — keep those buffers `bytearray`, and add a new secret to both lists in `finally`.

**BIP32 key templates carry the secp256r1 OID.** `SECP256R1_OID_DER`
(`1.2.840.10045.3.1.7`) is what the vendor expects in `CKA_EC_PARAMS` for vendor BIP32 keys,
even though BIP32 is a secp256k1 construction elsewhere. This was fixed deliberately
(`49d3028`, `f9efd3b`, `04a10f5`); it is not a typo.

## Pitfalls

**The library is looked up next to `sys.executable`, not the working directory.**
`load_pkcs11_lib()` builds its path from `os.path.dirname(sys.executable)`. In a PyInstaller
`--onefile` build that is `dist/`, which is why CI copies the `.so`/`.dll`/`.dylib` there and
why it works. Running `python main.py` from a checkout looks beside the **Python
interpreter** instead — so the README's "put the library into the working directory" only
holds for the built binary. Expect `RuntimeError: Ошибка загрузки ...` from a source
checkout unless the library sits next to the interpreter.

**Every command exits 0.** Nothing in `main.py` or `commands.py` calls `sys.exit` or returns
a status; failures are printed and the process ends successfully. A shell script or CI step
cannot tell a failed command from a working one except by matching output — which is exactly
what the build workflows do (`grep -F "Library Description: ..."`). Do not assume you can
add a check by looking at `$?`.

**Console strings are asserted by the tests.** Output is Russian and several tests match on
it — `"Нет подключенного кошелька" in captured.out`, `out.count("Ключ №") == 2`,
`"--key-number" in err`. Rewording a message means updating the test in the same change.

**`--force` deletes every object on the token**, not just key pairs, and needs the PIN.
`--force` and `--key-number` are mutually exclusive, rejected in both `main.py` and
`run_command_delete_key_pair`.

**`--pin` and `--new-pin` are `nargs='?'`, so three states are distinct**: a value, the flag
with no value (`PROMPT` sentinel), and the flag absent (`None`). `resolve_secret()` turns
those into a PIN, asking via `getpass` on a terminal and reading one stdin line otherwise.
Only `--list-keys` passes `required=False`, which is what keeps `--list-keys` with no `--pin`
from consuming a line of stdin — every other command asks. Comparing `args.pin` against
`None` alone would collapse the last two states and reintroduce the leak.

## Tests

`tests/` replaces the shared library with a `SimpleNamespace` whose `C_*` attributes are
plain Python functions. They drive real `ctypes` buffers — a mock reads its template back
through `ctypes.cast(template_ptr, ctypes.POINTER(CK_ATTRIBUTE * count))` — so they do catch
marshalling mistakes. They prove nothing about the device.

Each file has its own `sys.path.insert(0, ...)` pointing at the repo root; there is no
`conftest.py` and no packaging. Run `pytest` from the repository root or the imports fail.

## What is not in this repository

- The `wtpkcs11ecp` library itself — fetched, never committed.
- Any linter, formatter or type checker, and any config for one.
- A `requirements.txt` for running the tool: it has no runtime dependencies beyond the
  standard library.
- Any way to exercise the token without hardware.
