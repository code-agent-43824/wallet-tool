# AGENTS.md — wallet-tool

Canonical development rules: [coding-rules](https://scm.aktivco.ru/prototypes/coding-rules)
(raw: https://scm.aktivco.ru/prototypes/coding-rules/-/raw/main/AGENTS.md).
This file does NOT duplicate the canon (goose injects every subdirectory's
AGENTS.md into each session's context) — project-specific material only.
The map of the code lives in `CLAUDE.md`.

## What this is

CLI tool for Rutoken ECP tokens via PKCS#11 (ctypes, Python 3.11+; `.devcontainer`
pins 3.12, CI uses `3.x`). No server, no production deploy.

## Commands

| Task | Command |
| --- | --- |
| Install test dependencies | `pip install -r requirements-dev.txt` |
| Run all tests | `python -m pytest` |
| Run one file | `python -m pytest tests/test_sign.py` |
| Run one test | `python -m pytest tests/test_sign.py::test_sign_hash_ec_success` |
| Install build dependencies | `pip install -r requirements-build.txt` |
| Build the executable | `pyinstaller --onefile main.py` (writes `dist/main`) |
| Fetch the vendor PKCS#11 library | `python scripts/download_wtpkcs11ecp.py --artifact linux-x64/libwtpkcs11ecp.so` |

There is **no linter and no formatter** in this project — nothing to run, and nothing that
gates the trunk. Do not add one without the owner's decision.

## Settled decisions

- **The vendor library `wtpkcs11ecp` is never committed.** It is fetched by
  `scripts/download_wtpkcs11ecp.py` from the versioned static archive at
  `mescheryakov.pro` and is covered by `.gitignore` (`*.so`, `*.dll`, `*.dylib`). Each
  artifact is pinned by SHA-256 in the repository. Reason: vendor binaries stay out of git,
  while immutable versioned URLs and local pins make the build reproducible.
- **Console output, error messages and CLI help are in Russian; identifiers are in English.**
  Reason: the tool is used by Russian-speaking operators. Tests assert on the exact
  Russian strings, so a wording change is a change in two places.
- **Every command re-runs `C_Initialize` / `C_Finalize` and opens its own session.**
  There is no long-lived handle and no daemon. Reason: the process is a one-shot CLI; a
  crashed command must not leave the token logged in.
- **`main.py` dispatches with a plain chain of `if`s, not subparsers.** Reason: every
  command is a flag on one flat namespace, and the shape is asserted by the tests. Each
  branch returns the command's exit code, which `main()` hands to `sys.exit`.

## Version discipline

`version.py` holds `__version__` and is the only place the number lives; `main.py` imports
it for `--version`. It carries the version the **next** release will have, so raise it in
the change that readies the release, not after.

Releases are tagged `vMAJOR.MINOR` matching that number — `v0.1` through `v0.6` so far, and
`__version__` is now `0.7`. They are cut by hand on GitHub; publishing one triggers
`.github/workflows/release.yml`, which builds and attaches the artifacts. There is no
changelog.

## Deployment

A push to the trunk builds executables for Linux, macOS and Windows; nothing is published
from it. Artifacts reach users only when the owner publishes a GitHub Release, which
triggers `release.yml`.

The vendor archive is separate static infrastructure under
`/home/openclaw/sites/mescheryakov.pro/public/downloads/wallet-tool/wtpkcs11ecp`. Only
Watson changes it. Version directories are immutable: publish a new directory, verify
every required file over HTTPS, then update the pinned version and SHA-256 in the repository.
Never replace a file at an existing versioned URL.

Publishing a release is **the owner's action**. An agent never cuts a release.

## What the owner reviews

**Everything that touches the token is verified by the owner on real hardware.** No agent in
this repository has a Rutoken wallet: the tests replace the PKCS#11 library with a
`SimpleNamespace` mock, so they prove the ctypes marshalling and the command flow and
nothing about the device.

Pause and hand over to the owner after any change to key generation, key import, signing,
deletion or the PIN, and say plainly in the report that the change was not run against
hardware.
