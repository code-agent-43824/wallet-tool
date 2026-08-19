import hashlib
import importlib.util
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

_spec = importlib.util.spec_from_file_location(
    "download_wtpkcs11ecp", REPO_ROOT / "scripts" / "download_wtpkcs11ecp.py"
)
download = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(download)

DIGEST_OF_EMPTY = hashlib.sha256(b"").hexdigest()


def write(tmp_path, text, name="checksums.sha256"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_sha256_of_matches_hashlib(tmp_path):
    payload = b"wtpkcs11ecp" * 100
    target = tmp_path / "asset.zip"
    target.write_bytes(payload)
    assert download.sha256_of(target) == hashlib.sha256(payload).hexdigest()


def test_load_checksums_parses_sha256sum_format(tmp_path):
    path = write(
        tmp_path,
        "# комментарий\n"
        "\n"
        f"{DIGEST_OF_EMPTY}  linux-x86_64.zip\n"
        f"{DIGEST_OF_EMPTY.upper()} *windows-x86_64.zip\n",
    )
    assert download.load_checksums(path) == {
        "linux-x86_64.zip": DIGEST_OF_EMPTY,
        "windows-x86_64.zip": DIGEST_OF_EMPTY,
    }


def test_load_checksums_missing_file_is_empty(tmp_path):
    assert download.load_checksums(tmp_path / "absent.sha256") == {}


def test_load_checksums_rejects_malformed_line(tmp_path):
    path = write(tmp_path, f"{DIGEST_OF_EMPTY}\n")
    with pytest.raises(SystemExit) as excinfo:
        download.load_checksums(path)
    assert "expected" in str(excinfo.value)


def test_load_checksums_rejects_non_digest(tmp_path):
    path = write(tmp_path, "not-a-digest  linux-x86_64.zip\n")
    with pytest.raises(SystemExit) as excinfo:
        download.load_checksums(path)
    assert "not a SHA-256 digest" in str(excinfo.value)


def test_resolve_expected_digest_uses_checksum_file(tmp_path):
    digest = download.resolve_expected_digest(
        "linux-x86_64.zip",
        None,
        {"linux-x86_64.zip": DIGEST_OF_EMPTY},
        tmp_path / "checksums.sha256",
    )
    assert digest == DIGEST_OF_EMPTY


def test_resolve_expected_digest_override_wins(tmp_path):
    other = hashlib.sha256(b"other").hexdigest()
    digest = download.resolve_expected_digest(
        "linux-x86_64.zip",
        other.upper(),
        {"linux-x86_64.zip": DIGEST_OF_EMPTY},
        tmp_path / "checksums.sha256",
    )
    assert digest == other


def test_resolve_expected_digest_fails_closed_when_unpinned(tmp_path):
    with pytest.raises(SystemExit) as excinfo:
        download.resolve_expected_digest(
            "linux-arm64.zip", None, {}, tmp_path / "checksums.sha256"
        )
    message = str(excinfo.value)
    assert "No SHA-256 pinned" in message
    assert "linux-arm64.zip" in message


def test_verify_digest_accepts_match(tmp_path):
    target = tmp_path / "asset.zip"
    target.write_bytes(b"")
    download.verify_digest(target, "asset.zip", DIGEST_OF_EMPTY)


def test_verify_digest_rejects_mismatch(tmp_path):
    target = tmp_path / "asset.zip"
    target.write_bytes(b"tampered")
    with pytest.raises(SystemExit) as excinfo:
        download.verify_digest(target, "asset.zip", DIGEST_OF_EMPTY)
    message = str(excinfo.value)
    assert "SHA-256 mismatch" in message
    assert "Refusing to use it" in message


def test_shipped_checksum_file_covers_the_assets_ci_downloads():
    """Пины должны быть на месте для всех трёх платформ из build-*.yml."""

    checksums = download.load_checksums(download.DEFAULT_CHECKSUM_FILE)
    for asset in (
        "linux-x86_64.zip",
        "macos_x86_64+arm64.zip",
        "windows-x86_64.zip",
    ):
        assert asset in checksums, f"нет пина для {asset}"
        assert len(checksums[asset]) == 64
