#!/usr/bin/env python3
"""Verify SentinelGate's reviewed Superpowers gitlink and source metadata."""
from __future__ import annotations

import argparse
import configparser
import json
import re
import subprocess
import sys
from pathlib import Path

SOURCE = "https://github.com/obra/superpowers.git"
GITLINK_PATH = "tools/superpowers"
LOCK_NAME = "superpowers.lock.json"


def check_metadata(root: Path) -> str:
    """Check that checked-in metadata pins exactly one reviewed upstream source."""
    lock_path = root / LOCK_NAME
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"Cannot read {LOCK_NAME}: {exc}") from exc
    if not isinstance(lock, dict) or lock.get("repository") != SOURCE:
        raise ValueError("Lock file must name official obra/superpowers repository")
    revision = lock.get("revision")
    if not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ValueError("Lock file must pin a complete lowercase 40-character commit SHA")
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with (root / ".gitmodules").open(encoding="utf-8") as stream:
            parser.read_file(stream)
    except (OSError, configparser.Error) as exc:
        raise ValueError(f"Cannot read .gitmodules: {exc}") from exc
    section = 'submodule "tools/superpowers"'
    if section not in parser:
        raise ValueError("Missing tools/superpowers submodule declaration")
    if parser[section].get("path") != GITLINK_PATH or parser[section].get("url") != SOURCE:
        raise ValueError("Submodule must use the expected path and upstream URL")
    return revision


def git(cwd: Path, *args: str) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(cwd), *args],
            check=True, capture_output=True, text=True, timeout=20,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"git {' '.join(args)} failed in {cwd}: {exc}") from exc
    return proc.stdout.strip()


def check_checkout(root: Path, revision: str) -> None:
    """Validate the committed gitlink and initialized working-tree checkout."""
    tree = git(root, "ls-tree", "HEAD", "--", GITLINK_PATH)
    match = re.fullmatch(r"160000 commit ([0-9a-f]{40})\ttools/superpowers", tree)
    if match is None:
        raise ValueError("Git tree is missing tools/superpowers pinned submodule (mode 160000)")
    if match.group(1) != revision:
        raise ValueError("Committed submodule SHA differs from superpowers.lock.json")
    checkout = root / GITLINK_PATH
    if not checkout.is_dir():
        raise ValueError("Submodule missing. Run git submodule update --init --checkout tools/superpowers")
    if git(checkout, "rev-parse", "HEAD") != revision:
        raise ValueError("Submodule checkout differs from locked revision; update or reset it")
    if not (checkout / "skills" / "using-superpowers" / "SKILL.md").is_file():
        raise ValueError("Superpowers bootstrap skill missing in submodule checkout")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-checkout", action="store_true", help="Also verify Git gitlink and installed source directory")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        revision = check_metadata(root)
        if args.require_checkout:
            check_checkout(root, revision)
    except ValueError as exc:
        print(f"Superpowers verification FAILED: {exc}", file=sys.stderr)
        return 1
    print(f"Superpowers verified: {revision}" + (" (gitlink + checkout)" if args.require_checkout else " (metadata only)"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
