#!/usr/bin/env python3
"""Utility for downloading wtpkcs11ecp libraries from the 3rd-party release."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable, Optional
import zipfile

API_BASE = "https://api.github.com"
DEFAULT_RELEASE_TAG = "3rdparty"
DEFAULT_CACHE_DIR = Path(".cache") / "wtpkcs11ecp"
DEFAULT_CHECKSUM_FILE = Path(__file__).resolve().with_name("wtpkcs11ecp.sha256")
HEX_DIGITS = set("0123456789abcdef")


def make_headers(token: Optional[str], accept: str) -> dict[str, str]:
    headers = {
        "User-Agent": "wallet-tool-build-scripts",
        "Accept": accept,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_release(repo: str, tag: str, token: Optional[str]) -> dict:
    url = f"{API_BASE}/repos/{repo}/releases/tags/{tag}"
    request = urllib.request.Request(url, headers=make_headers(token, "application/vnd.github+json"))
    try:
        with urllib.request.urlopen(request) as response:  # type: ignore[arg-type]
            return json.load(response)
    except urllib.error.HTTPError as exc:  # pragma: no cover - network failures are reported
        message = exc.read().decode("utf-8", errors="ignore")
        raise SystemExit(
            f"Failed to fetch release '{tag}' from repo '{repo}': {exc.code} {exc.reason}\n{message}"
        ) from exc


def find_asset(assets: Iterable[dict], name: Optional[str], patterns: Iterable[str]) -> dict:
    patterns_lc = [p.lower() for p in patterns]

    def matches(asset: dict) -> bool:
        asset_name_lc = asset.get("name", "").lower()
        return all(p in asset_name_lc for p in patterns_lc)

    if name:
        for asset in assets:
            if asset.get("name") == name:
                return asset
        raise SystemExit(f"Asset with exact name '{name}' not found in release")

    candidates = [asset for asset in assets if matches(asset)]
    if not candidates:
        raise SystemExit(
            "No assets matched the specified patterns. "
            "Use --pattern multiple times or --asset-name to select the asset explicitly."
        )
    if len(candidates) > 1:
        asset_names = ", ".join(a.get("name", "<unknown>") for a in candidates)
        raise SystemExit(
            "Multiple assets match the specified patterns: "
            f"{asset_names}. Provide a more specific pattern or --asset-name."
        )
    return candidates[0]


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
    """Read a sha256sum-style file into {asset name: digest}."""

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
                f"{path}:{number}: expected '<sha256>  <asset name>', got {raw_line!r}"
            )
        digest = normalise_digest(parts[0], f"{path}:{number}")
        # sha256sum marks binary mode with a leading '*' on the name.
        checksums[parts[1].strip().lstrip("*")] = digest
    return checksums


def resolve_expected_digest(
    asset_name: str,
    override: Optional[str],
    checksums: dict[str, str],
    checksum_file: Path,
) -> str:
    if override:
        return normalise_digest(override, "--sha256")

    digest = checksums.get(asset_name)
    if digest is None:
        raise SystemExit(
            f"No SHA-256 pinned for asset '{asset_name}' in {checksum_file}. "
            "Vendor binaries must be pinned: add the digest to that file, or pass "
            "--sha256 explicitly for a one-off download."
        )
    return digest


def verify_digest(path: Path, asset_name: str, expected: str) -> None:
    actual = sha256_of(path)
    if actual != expected:
        raise SystemExit(
            f"SHA-256 mismatch for asset '{asset_name}':\n"
            f"  expected {expected}\n"
            f"  actual   {actual}\n"
            "The release asset does not match the pinned digest. Refusing to use it."
        )


def download_asset(url: str, token: Optional[str], destination: Path) -> None:
    request = urllib.request.Request(url, headers=make_headers(token, "application/octet-stream"))
    with urllib.request.urlopen(request) as response, destination.open("wb") as handle:  # type: ignore[arg-type]
        shutil.copyfileobj(response, handle)


def extract_library_from_zip(zip_path: Path, pattern: str, target: Path) -> Path:
    with zipfile.ZipFile(zip_path) as archive:
        members = archive.namelist()
        pattern_lc = pattern.lower()
        matching = [m for m in members if pattern_lc in Path(m).name.lower()]
        if not matching:
            available = ", ".join(members)
            raise SystemExit(
                f"Could not find a file containing '{pattern}' inside the archive. "
                f"Available members: {available}"
            )
        if len(matching) > 1:
            raise SystemExit(
                "Multiple files inside the archive matched the pattern. "
                "Please specify a more precise pattern via --library-pattern."
            )
        member = matching[0]
        target.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(member) as source, target.open("wb") as destination:
            shutil.copyfileobj(source, destination)
    return target


def move_or_copy(src: Path, dst: Path) -> Path:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return dst


def ensure_target(pattern: Optional[str], target: Optional[Path], default_name: str) -> Path:
    if target:
        return target
    if pattern:
        pattern_path = Path(pattern)
        if pattern_path.suffix:
            return Path(pattern_path.name)
        return Path(pattern)
    raise SystemExit("Unable to determine target filename. Provide --target or --library-pattern.")


def resolve_cache_dir(cache_dir: Optional[Path]) -> Path:
    if cache_dir:
        base = cache_dir
    else:
        env_value = os.environ.get("WTPKCS11_CACHE_DIR")
        base = Path(env_value) if env_value else DEFAULT_CACHE_DIR
    return base if base.is_absolute() else Path.cwd() / base


def main() -> None:
    parser = argparse.ArgumentParser(description="Download wtpkcs11ecp from GitHub release")
    parser.add_argument(
        "--repository",
        help="GitHub repository in owner/name format. Defaults to the GITHUB_REPOSITORY env var.",
    )
    parser.add_argument(
        "--tag",
        default=DEFAULT_RELEASE_TAG,
        help=f"Release tag to download (default: {DEFAULT_RELEASE_TAG}).",
    )
    parser.add_argument(
        "--asset-name",
        help="Exact asset name to download. Overrides pattern matching.",
    )
    parser.add_argument(
        "--pattern",
        action="append",
        default=[],
        help="Substring that must appear in the asset name. Can be specified multiple times.",
    )
    parser.add_argument(
        "--library-pattern",
        help="Substring used to locate the library file inside the archive.",
    )
    parser.add_argument(
        "--target",
        type=Path,
        help="Destination path for the library (relative paths are resolved against the current directory).",
    )
    parser.add_argument(
        "--checksum-file",
        type=Path,
        default=DEFAULT_CHECKSUM_FILE,
        help=(
            "File pinning the SHA-256 of each release asset, in sha256sum format "
            f"(default: {DEFAULT_CHECKSUM_FILE.name} next to this script)."
        ),
    )
    parser.add_argument(
        "--sha256",
        help=(
            "Expected SHA-256 of the asset. Overrides the checksum file; use it for a "
            "one-off download of an asset that is not pinned yet."
        ),
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        help=(
            "Directory where downloaded assets and extracted libraries are cached. "
            "Defaults to .cache/wtpkcs11ecp or the value of WTPKCS11_CACHE_DIR."
        ),
    )
    args = parser.parse_args()

    repository = args.repository or os.environ.get("GITHUB_REPOSITORY")
    if not repository:
        parser.error("--repository must be provided when GITHUB_REPOSITORY is not set")

    token = os.environ.get("GITHUB_TOKEN")
    release = fetch_release(repository, args.tag, token)

    assets = release.get("assets", [])
    if not assets:
        raise SystemExit(f"Release '{args.tag}' in repo '{repository}' does not contain any assets")

    asset = find_asset(assets, args.asset_name, args.pattern)
    download_url = asset.get("browser_download_url")
    if not download_url:
        raise SystemExit("Selected asset is missing download URL")

    asset_name = asset.get("name", "asset")
    asset_id = asset.get("id")
    if asset_id is None:
        raise SystemExit("Selected asset is missing an id required for caching")

    library_pattern = args.library_pattern
    target = ensure_target(library_pattern, args.target, asset_name)
    target = target if target.is_absolute() else Path.cwd() / target

    cache_dir = resolve_cache_dir(args.cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    asset_cache_dir = cache_dir / str(asset_id)
    asset_cache_dir.mkdir(parents=True, exist_ok=True)

    cached_asset_path = asset_cache_dir / asset_name
    cached_library_path = asset_cache_dir / target.name

    checksums = load_checksums(args.checksum_file)
    expected = resolve_expected_digest(
        asset_name, args.sha256, checksums, args.checksum_file
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_asset_path = Path(tmpdir) / asset_name
        if cached_asset_path.exists():
            print(f"Using cached asset {cached_asset_path}")
            shutil.copy2(cached_asset_path, tmp_asset_path)
        else:
            print(
                f"Downloading asset '{asset_name}' from release '{args.tag}' in repo '{repository}'..."
            )
            download_asset(download_url, token, tmp_asset_path)

        # Verified on every run, cache hit included: a cached asset is as
        # untrusted as a freshly downloaded one.
        verify_digest(tmp_asset_path, asset_name, expected)
        print(f"SHA-256 verified: {expected}")

        if not cached_asset_path.exists():
            move_or_copy(tmp_asset_path, cached_asset_path)

        suffix = tmp_asset_path.suffix.lower()

        if suffix == ".zip":
            extracted = extract_library_from_zip(
                tmp_asset_path,
                library_pattern or target.name,
                cached_library_path,
            )
        else:
            extracted = move_or_copy(tmp_asset_path, cached_library_path)

    extracted = move_or_copy(extracted, target)
    print(f"Library saved to {extracted}")


if __name__ == "__main__":
    main()
