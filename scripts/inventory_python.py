#!/usr/bin/env python3
"""Statically inventory Python metadata and startup files in approved roots.

Use a trusted interpreter with -I -S. No network, subprocesses or package imports.
Approval is the agent's workflow responsibility; this helper is not a sandbox.
"""

import argparse
import datetime
import json
import os
from pathlib import Path
import stat
import sys


PROJECT_MARKERS = {".git", "pyproject.toml", "setup.py", "package.json", "Cargo.toml", "go.mod", "composer.json", "Gemfile", "pom.xml"}
INSTALL_DIRS = {"site-packages", "dist-packages", "node_modules"}
STARTUP_NAMES = {"sitecustomize", "usercustomize"}
MAX_METADATA = 1024 * 1024


def inside(path, parent):
    return path == parent or parent in path.parents


def startup_kind(path):
    if path.name.endswith(".pth"):
        return "pth-hook"
    suffix = path.suffix.lower()
    importable = suffix in {".py", ".pyc", ".so", ".pyd"}
    stem = path.name.split(".", 1)[0]
    package_parent = path.parent.parent if path.parent.name == "__pycache__" else path.parent
    if importable and (stem in STARTUP_NAMES or (stem == "__init__" and package_parent.name in STARTUP_NAMES)):
        return "startup-module"
    return None


def read_identity(path):
    mode = path.lstat().st_mode
    if not stat.S_ISREG(mode):
        raise ValueError("Skipped non-regular metadata file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_METADATA:
            raise ValueError("Skipped non-regular or oversized metadata")
        data = handle.read(MAX_METADATA + 1)
    if len(data) > MAX_METADATA:
        raise ValueError("Metadata exceeded read limit")
    headers = {}
    for line in data.decode("utf-8").splitlines():
        if not line:
            break
        key, sep, value = line.partition(":")
        key = key.lower()
        if sep and key in {"name", "version"}:
            if key in headers:
                raise ValueError("Duplicate singleton metadata header: " + key)
            value = value.strip()
            if not value or any(ord(char) < 32 for char in value):
                raise ValueError("Empty or invalid metadata header: " + key)
            headers[key] = value
    if "name" not in headers or "version" not in headers:
        raise ValueError("Missing distribution Name or Version header")
    return headers


def scan(roots, markers=(), excluded_roots=(), expected_roots=()):
    markers = set(markers)
    result = {
        "schema": 2,
        "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "roots": [],
        "root_identities": [],
        "indicator_filenames": sorted(markers),
        "distributions": [],
        "startup_files": [],
        "boundaries": [],
        "exclusions": [],
        "errors": [],
        "limits": [
            "Static metadata only; no installed packages imported or executed.",
            "Does not inspect archives, container layers, process memory, or remote assets.",
            "Git internals are excluded; directory symlinks are not followed and are reported.",
            "Nested project markers outside installed dependency trees require explicit approved roots.",
            "Startup names and supplied filename indicators are leads, not malware attribution.",
            "Permission is an agent workflow; this helper is not an authorization or adversarial-filesystem sandbox.",
            "Absence of matches does not establish absence of compromise.",
        ],
    }
    seen_dirs = set()
    seen_files = set()
    resolved = []
    excluded = []

    def error(path, message):
        result["errors"].append({"path": str(path), "error": str(message)})

    def walk_error(exc):
        error(exc.filename, exc.strerror)

    for raw in excluded_roots:
        try:
            excluded.append(Path(raw).expanduser().resolve())
        except (OSError, RuntimeError, ValueError) as exc:
            error(raw, "Cannot resolve exclusion: " + str(exc))
    if result["errors"]:
        # An unresolved denial/exclusion must never turn into broader scanning.
        result["coverage_complete"] = False
        return result

    for index, raw_root in enumerate(roots):
        try:
            root = Path(raw_root).expanduser().resolve()
            if expected_roots:
                expected = Path(expected_roots[index]).expanduser()
                if not expected.is_absolute() or str(expected) != str(root):
                    error(raw_root, "Resolved root differs from approved canonical --expected-root")
                    continue
            if not root.is_dir():
                error(root, "Not an accessible directory")
                continue
            info = root.stat()
            result["root_identities"].append({"requested": str(raw_root), "canonical": str(root), "device": info.st_dev, "inode": info.st_ino})
            if any(inside(root, denied) for denied in excluded):
                result["exclusions"].append({"path": str(root), "reason": "explicit-excluded-root"})
                continue
            resolved.append(root)
            result["roots"].append(str(root))
        except (OSError, RuntimeError, ValueError) as exc:
            error(raw_root, str(exc))

    approved = set(resolved)
    for root in resolved:
        for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
            current = Path(directory)
            if any(inside(current, denied) for denied in excluded):
                result["exclusions"].append({"path": directory, "reason": "explicit-excluded-root"})
                dirs[:] = []
                continue
            installed_tree = any(part in INSTALL_DIRS for part in current.parts)
            found_markers = PROJECT_MARKERS.intersection(dirs + files)
            if current != root and current not in approved and found_markers and not installed_tree:
                result["boundaries"].append({"path": directory, "markers": sorted(found_markers), "reason": "nested-project-requires-separate-approval"})
                dirs[:] = []
                continue
            if directory in seen_dirs:
                dirs[:] = []
                continue
            seen_dirs.add(directory)
            kept = []
            for name in sorted(dirs):
                child = current / name
                if name == ".git":
                    continue
                if child.is_symlink():
                    result["exclusions"].append({"path": str(child), "reason": "directory-symlink-not-followed"})
                else:
                    kept.append(name)
            dirs[:] = kept
            if current.name.endswith(".dist-info") and "METADATA" not in files:
                error(current, "Distribution directory lacks METADATA")
            if current.name.endswith(".egg-info") and "PKG-INFO" not in files:
                error(current, "Distribution directory lacks PKG-INFO")
            for filename in sorted(files):
                path = current / filename
                if str(path) in seen_files:
                    continue
                seen_files.add(str(path))
                kind = startup_kind(path)
                if kind or filename in markers:
                    result["startup_files"].append({"path": str(path), "kind": kind or "indicator-file", "matched_indicator": filename in markers})
                legacy_flat = filename.endswith(".egg-info")
                directory_metadata = filename in {"METADATA", "PKG-INFO"} and (current.name.endswith(".dist-info") or current.name.endswith(".egg-info"))
                if not (legacy_flat or directory_metadata):
                    continue
                try:
                    identity = read_identity(path)
                    result["distributions"].append({"name": identity["name"], "version": identity["version"], "metadata": str(path)})
                except (OSError, ValueError, UnicodeError) as exc:
                    error(path, str(exc))
    result["distributions"].sort(key=lambda item: (item["name"].lower(), item["metadata"]))
    result["startup_files"].sort(key=lambda item: item["path"])
    result["coverage_complete"] = not (result["errors"] or result["boundaries"] or result["exclusions"])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roots", nargs="+", help="Explicit approved filesystem roots")
    parser.add_argument("--marker", action="append", default=[], help="Verified incident indicator basename; repeatable")
    parser.add_argument("--exclude-root", action="append", default=[], help="Pending/denied path to exclude from parent recursion; repeatable")
    parser.add_argument("--expected-root", action="append", default=[], help="Approved canonical root in corresponding roots order; repeat for every root")
    args = parser.parse_args()
    if not sys.flags.isolated or not sys.flags.no_site:
        parser.error("Run with a trusted Python interpreter using -I -S")
    if any(not item or item in {".", ".."} or "/" in item or "\\" in item for item in args.marker):
        parser.error("Each --marker must be a nonempty basename, not a path")
    if args.expected_root and len(args.expected_root) != len(args.roots):
        parser.error("Supply one --expected-root for each root, in the same order")
    result = scan(args.roots, args.marker, args.exclude_root, args.expected_root)
    json.dump(result, sys.stdout, indent=2, ensure_ascii=True)
    sys.stdout.write("\n")
    return 0 if result["coverage_complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
