import os
import re
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import main
import version


def test_version_matches_release_tag_format():
    """Теги релизов выглядят как v0.6, значит версия — MAJOR.MINOR."""

    assert re.fullmatch(r"\d+\.\d+", version.__version__), version.__version__


def test_main_reports_the_same_version(monkeypatch, capsys):
    monkeypatch.setattr(main.sys, "argv", ["main.py", "--version"])

    with pytest.raises(SystemExit) as excinfo:
        main.main()

    assert excinfo.value.code == 0
    assert capsys.readouterr().out.strip() == f"wallet-tool {version.__version__}"


def test_version_has_a_single_source():
    """main.py не должен объявлять свою версию рядом с version.py."""

    source = open(
        os.path.join(os.path.dirname(__file__), "..", "main.py"), encoding="utf-8"
    ).read()
    assert version.__version__ not in source
