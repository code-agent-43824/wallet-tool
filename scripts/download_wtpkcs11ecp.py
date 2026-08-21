#!/usr/bin/env python3
"""Download a pinned wtpkcs11ecp library from the static vendor archive."""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Optional

DEFAULT_BASE_URL = "https://mescheryakov.pro/downloads/wallet-tool/wtpkcs11ecp"
DEFAULT_VERSION = "2.18.2.0"
DEFAULT_CACHE_DIR = Path(".cache") / "wtpkcs11ecp"
DEFAULT_CHECKSUM_FILE = Path(__file__).resolve().with_name("wtpkcs11ecp.sha256")
HEX_DIGITS = set("0123456789abcdef")


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalise_digest(value: str, source: str) -> str:
    digest = value.strip().lower()
    if len(digest) != 64 or not set(digest) <= HEX_DIGITS:
        raise SystemExit(f"{source}: '{value}' is not a SHA-256 digest")
    return digest


def load_checksums(path: Path) -> dict[str, str]:
    """Read a sha256sum-style file into {artifact path: digest}."""

    checksums: dict[str, str] = {}
    if not path.exists():
        return checksums

    for number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            raise SystemExit(
                f"{path}:{number}: expected '<sha256>  <artifact path>', got {raw_line!r}"
            )
        digest = normalise_digest(parts[0], f"{path}:{number}")
        checksums[parts[1].strip().lstrip("*")] = digest
    return checksums


def resolve_expected_digest(
    artifact: str,
    override: Optional[str],
    checksums: dict[str, str],
    checksum_file: Path,
) -> str:
    if override:
        return normalise_digest(override, "--sha256")

    digest = checksums.get(artifact)
    if digest is None:
        raise SystemExit(
            f"No SHA-256 pinned for artifact '{artifact}' in {checksum_file}. "
            "Vendor binaries must be pinned: add the digest to that file, or pass "
            "--sha256 explicitly for a one-off download."
        )
    return digest


def verify_digest(path: Path, artifact: str, expected: str) -> None:
    actual = sha256_of(path)
    if actual != expected:
        raise SystemExit(
            f"SHA-256 mismatch for artifact '{artifact}':\n"
            f"  expected {expected}\n"
            f"  actual   {actual}\n"
            "The downloaded file does not match the pinned digest. Refusing to use it."
        )


def normalise_relative_path(value: str, source: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise SystemExit(f"{source}: expected a safe relative path, got {value!r}")
    return path.as_posix()


def download_file(url: str, destination: Path) -> None:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "wallet-tool-build-scripts"},
    )
    with urllib.request.urlopen(request) as response, destination.open("wb") as handle:  # type: ignore[arg-type]
        shutil.copyfileobj(response, handle)


def resolve_cache_dir(cache_dir: Optional[Path]) -> Path:
    if cache_dir:
        base = cache_dir
    else:
        env_value = os.environ.get("WTPKCS11_CACHE_DIR")
        base = Path(env_value) if env_value else DEFAULT_CACHE_DIR
    return base if base.is_absolute() else Path.cwd() / base


def build_url(base_url: str, version: str, artifact: str) -> str:
    relative_url = "/".join(
        urllib.parse.quote(part, safe="")
        for part in PurePosixPath(version, artifact).parts
    )
    return f"{base_url.rstrip('/')}/{relative_url}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Download wtpkcs11ecp from the static archive")
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"Archive base URL (default: {DEFAULT_BASE_URL}).",
    )
    parser.add_argument(
        "--version",
        default=DEFAULT_VERSION,
        help=f"Library version directory (default: {DEFAULT_VERSION}).",
    )
    parser.add_argument(
        "--artifact",
        required=True,
        help="Library path inside the version directory.",
    )
    parser.add_argument(
        "--target",
        type=Path,
        help="Destination path. Defaults to the artifact filename.",
    )
    parser.add_argument(
        "--checksum-file",
        type=Path,
        default=DEFAULT_CHECKSUM_FILE,
        help=(
            "File pinning the SHA-256 of each artifact, in sha256sum format "
            f"(default: {DEFAULT_CHECKSUM_FILE.name} next to this script)."
        ),
    )
    parser.add_argument(
        "--sha256",
        help="Expected SHA-256. Overrides the checksum file for a one-off download.",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        help=(
            "Directory where downloaded libraries are cached. Defaults to "
            ".cache/wtpkcs11ecp or WTPKCS11_CACHE_DIR."
        ),
    )
    args = parser.parse_args()

    version = normalise_relative_path(args.version, "--version")
    artifact = normalise_relative_path(args.artifact, "--artifact")
    target = args.target or Path(PurePosixPath(artifact).name)
    target = target if target.is_absolute() else Path.cwd() / target

    checksums = load_checksums(args.checksum_file)
    expected = resolve_expected_digest(artifact, args.sha256, checksums, args.checksum_file)
    cache_path = resolve_cache_dir(args.cache_dir) / version / Path(artifact)
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        downloaded = Path(tmpdir) / Path(artifact).name
        if cache_path.exists():
            print(f"Using cached artifact {cache_path}")
            shutil.copy2(cache_path, downloaded)
        else:
            url = build_url(args.base_url, version, artifact)
            print(f"Downloading '{artifact}' from {url}...")
            download_file(url, downloaded)

        verify_digest(downloaded, artifact, expected)
        print(f"SHA-256 verified: {expected}")
        if not cache_path.exists():
            shutil.copy2(downloaded, cache_path)

        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(downloaded, target)

    print(f"Library saved to {target}")


if __name__ == "__main__":
    main()
