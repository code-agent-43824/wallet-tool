import io
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import main


class FakeStdin(io.StringIO):
    def __init__(self, text="", tty=False):
        super().__init__(text)
        self._tty = tty

    def isatty(self):
        return self._tty


def test_read_secret_uses_getpass_on_a_terminal(monkeypatch):
    monkeypatch.setattr(main.sys, "stdin", FakeStdin(tty=True))
    asked = []

    def fake_getpass(prompt):
        asked.append(prompt)
        return "12345678"

    monkeypatch.setattr(main.getpass, "getpass", fake_getpass)

    assert main.read_secret("PIN-код: ") == "12345678"
    assert asked == ["PIN-код: "]


def test_read_secret_reads_one_line_when_piped(monkeypatch):
    monkeypatch.setattr(main.sys, "stdin", FakeStdin("12345678\nвторая строка\n"))

    def fail(prompt):  # pragma: no cover - вызов означал бы попытку читать с tty
        raise AssertionError("getpass не должен вызываться для перенаправленного stdin")

    monkeypatch.setattr(main.getpass, "getpass", fail)

    assert main.read_secret("PIN-код: ") == "12345678"


def test_read_secret_strips_windows_line_ending(monkeypatch):
    monkeypatch.setattr(main.sys, "stdin", FakeStdin("12345678\r\n"))
    assert main.read_secret("PIN-код: ") == "12345678"


def test_read_secret_on_empty_stdin_is_empty(monkeypatch):
    monkeypatch.setattr(main.sys, "stdin", FakeStdin(""))
    assert main.read_secret("PIN-код: ") == ""


def test_resolve_secret_keeps_explicit_value(monkeypatch):
    monkeypatch.setattr(main, "read_secret", lambda prompt: "спрошенный")
    assert main.resolve_secret("87654321", "PIN-код: ", True) == "87654321"
    assert main.resolve_secret("87654321", "PIN-код: ", False) == "87654321"


def test_resolve_secret_asks_when_flag_has_no_value(monkeypatch):
    prompts = []
    monkeypatch.setattr(
        main, "read_secret", lambda prompt: prompts.append(prompt) or "спрошенный"
    )
    # --pin без значения спрашивает даже там, где PIN не обязателен.
    assert main.resolve_secret(main.PROMPT, "PIN-код: ", False) == "спрошенный"
    assert prompts == ["PIN-код: "]


def test_resolve_secret_asks_when_required_and_absent(monkeypatch):
    monkeypatch.setattr(main, "read_secret", lambda prompt: "спрошенный")
    assert main.resolve_secret(None, "PIN-код: ", True) == "спрошенный"


def test_resolve_secret_stays_empty_when_optional_and_absent(monkeypatch):
    def fail(prompt):  # pragma: no cover
        raise AssertionError("не должны спрашивать PIN, когда он не обязателен")

    monkeypatch.setattr(main, "read_secret", fail)
    assert main.resolve_secret(None, "PIN-код: ", False) is None


@pytest.mark.parametrize(
    "argv, expected",
    [
        (["--list-keys"], None),
        (["--list-keys", "--pin", "12345678"], "12345678"),
        (["--list-keys", "--pin"], main.PROMPT),
        (["--sign", "--pin", "--key-number", "1"], main.PROMPT),
    ],
)
def test_parser_distinguishes_absent_flag_from_flag_without_value(
    monkeypatch, argv, expected
):
    """--pin без значения и отсутствие --pin должны различаться."""

    seen = []
    monkeypatch.setattr(main.sys, "argv", ["main.py", *argv])

    for name in ("list_keys", "sign"):
        monkeypatch.setattr(main, name, lambda *a, **kw: None)
    monkeypatch.setattr(
        main, "resolve_secret", lambda value, prompt, required: seen.append(value)
    )

    main.main()

    assert seen == [expected]
