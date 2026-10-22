#!/usr/bin/env python3
"""Isolated stdlib regression tests for the static metadata helper.

Run with a trusted interpreter:
  python3 -I -S test_inventory_python.py /path/to/inventory_python.py
Optional: --receipt /path/to/local-results.json

Only temporary synthetic fixtures are scanned. No network or package installation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import py_compile
import subprocess
import sys
import tempfile
import unittest

SCANNER = None
RECEIPTS = []


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="metadata-inventory-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def write(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode() if isinstance(content, str) else content)
        return path

    def metadata(self, relative, name="synthetic", version="1.2.3"):
        return self.write(relative, f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\nSynthetic fixture only.\n")

    def scan(self, *roots, options=(), extra_env=None):
        command = [sys.executable, "-I", "-S", str(SCANNER), *map(str, options), *map(str, roots)]
        env = {key: value for key, value in os.environ.items()
               if key in {"PATH", "SYSTEMROOT", "WINDIR", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "HOME"}}
        env.update(extra_env or {})
        result = subprocess.run(command, capture_output=True, timeout=5, env=env, cwd=self.root)
        try:
            parsed = json.loads(result.stdout)
        except ValueError:
            self.fail(f"Scanner did not return JSON (exit {result.returncode}): {result.stderr!r}")
        RECEIPTS.append({"test": self.id(), "command": command, "returncode": result.returncode,
                         "stdout": parsed, "stderr": result.stderr.decode(errors="replace")})
        self.assertIn(result.returncode, (0, 2), result.stderr)
        self.assertEqual(parsed["coverage_complete"], result.returncode == 0)
        return result.returncode, parsed

    def test_documented_metadata_formats(self):
        self.metadata("site-packages/wheel.dist-info/METADATA", "wheel-eval")
        self.metadata("site-packages/egg.egg-info/PKG-INFO", "egg-eval")
        self.metadata("site-packages/flat.egg-info", "flat-eval")
        code, result = self.scan(self.root)
        self.assertEqual(code, 0)
        self.assertEqual({x["name"] for x in result["distributions"]}, {"wheel-eval", "egg-eval", "flat-eval"})

    def test_ordinary_install_targets_are_not_pruned(self):
        directories = ("target", "node_modules", ".next", ".nuxt", "__pycache__")
        for index, directory in enumerate(directories):
            self.metadata(f"{directory}/eval.dist-info/METADATA", f"eval-{index}")
            self.write(f"{directory}/incident.marker", "Synthetic filename indicator.\n")
        code, result = self.scan(self.root, options=("--marker", "incident.marker"))
        self.assertEqual(code, 0)
        self.assertEqual(len(result["distributions"]), len(directories))
        self.assertEqual(sum(x["matched_indicator"] for x in result["startup_files"]), len(directories))

    def test_customization_import_forms_are_static_leads(self):
        paths = ["site-packages/sitecustomize.py", "site-packages/sitecustomize/__init__.py",
                 "site-packages/usercustomize.cpython-test.so", "site-packages/usercustomize.pyd",
                 "site-packages/usercustomize/__pycache__/__init__.cpython-test.pyc"]
        for path in paths:
            self.write(path, "# Inert filename fixture; native-shaped files are not valid binaries.\n")
        source = self.write("compile-input/hook.py", "# Compile this source without executing it.\n")
        py_compile.compile(str(source), cfile=str(self.root / "site-packages/usercustomize.pyc"), doraise=True)
        code, result = self.scan(self.root)
        self.assertEqual(code, 0)
        expected = {str(self.root / path) for path in paths} | {str(self.root / "site-packages/usercustomize.pyc")}
        self.assertEqual({x["path"] for x in result["startup_files"]}, expected)
        self.assertTrue(all(x["kind"] == "startup-module" for x in result["startup_files"]))

    def test_bad_metadata_remains_unknown(self):
        cases = {"empty": b"Name: \nVersion: \n\n",
                 "duplicate": b"Name: first\nName: conflicting\nVersion: 1\n\n",
                 "invalid-utf8": b"Name: bad\xff\nVersion: 1\n\n",
                 "missing-header": b"Name: incomplete\n\n"}
        for name, content in cases.items():
            self.write(f"{name}.dist-info/METADATA", content)
        self.write("missing-file.dist-info/INSTALLER", "synthetic\n")
        code, result = self.scan(self.root)
        self.assertEqual(code, 2)
        self.assertFalse(result["distributions"])
        self.assertEqual(len(result["errors"]), 5)

    def test_special_metadata_cannot_block_or_follow_final_symlink(self):
        self.metadata("approved/good.dist-info/METADATA", "good")
        self.write("approved/huge.dist-info/METADATA", b"A" * (1024 * 1024 + 1))
        target = self.metadata("other/outside.dist-info/METADATA", "outside")
        link = self.root / "approved/link.dist-info/METADATA"
        link.parent.mkdir(parents=True)
        try:
            link.symlink_to(target)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"Symlinks unavailable: {exc}")
        if hasattr(os, "mkfifo"):
            fifo = self.root / "approved/fifo.dist-info/METADATA"
            fifo.parent.mkdir(parents=True)
            os.mkfifo(fifo)
        code, result = self.scan(self.root / "approved")
        self.assertEqual(code, 2)
        self.assertEqual([x["name"] for x in result["distributions"]], ["good"])
        self.assertEqual(len(result["errors"]), 3 if hasattr(os, "mkfifo") else 2)

    def test_nested_project_requires_independent_explicit_root(self):
        self.metadata("approved/site-packages/parent.dist-info/METADATA", "parent")
        self.write("approved/child/pyproject.toml", "# Do not execute or parse project config.\n")
        self.metadata("approved/child/env/child.dist-info/METADATA", "child")
        parent, child = self.root / "approved", self.root / "approved/child"
        code, result = self.scan(parent)
        self.assertEqual(code, 2)
        self.assertEqual([x["name"] for x in result["distributions"]], ["parent"])
        self.assertEqual([x["path"] for x in result["boundaries"]], [str(child)])
        code, result = self.scan(parent, child)
        self.assertEqual(code, 0)
        self.assertEqual({x["name"] for x in result["distributions"]}, {"parent", "child"})

    def test_installed_dependency_manifests_do_not_hide_packages(self):
        for directory in ("site-packages", "dist-packages", "node_modules"):
            self.write(f"{directory}/dependency/pyproject.toml", "# synthetic dependency manifest\n")
            self.metadata(f"{directory}/dependency/eval.dist-info/METADATA", directory)
        code, result = self.scan(self.root)
        self.assertEqual(code, 0)
        self.assertEqual(len(result["distributions"]), 3)

    def test_explicit_exclusion_covers_descendants_and_explicit_roots(self):
        self.metadata("approved/good.dist-info/METADATA", "good")
        self.metadata("approved/denied/deeper/hidden.dist-info/METADATA", "hidden")
        parent, denied = self.root / "approved", self.root / "approved/denied"
        code, result = self.scan(parent, denied, options=("--exclude-root", denied))
        self.assertEqual(code, 2)
        self.assertEqual([x["name"] for x in result["distributions"]], ["good"])
        self.assertTrue(result["exclusions"])
        self.assertFalse(result["errors"])

    def test_retargeted_root_is_rejected_before_metadata_reads(self):
        self.metadata("initial/a.dist-info/METADATA", "initial")
        self.metadata("replacement/b.dist-info/METADATA", "replacement")
        alias = self.root / "alias"
        try:
            alias.symlink_to(self.root / "initial", target_is_directory=True)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"Symlinks unavailable: {exc}")
        expected = alias.resolve()
        code, result = self.scan(alias, options=("--expected-root", expected))
        self.assertEqual(code, 0)
        self.assertEqual(result["root_identities"][0]["canonical"], str(expected))
        alias.unlink()
        alias.symlink_to(self.root / "replacement", target_is_directory=True)
        code, result = self.scan(alias, options=("--expected-root", expected))
        self.assertEqual(code, 2)
        self.assertFalse(result["distributions"])
        self.assertFalse(result["roots"])
        self.assertEqual(len(result["errors"]), 1)

    def test_directory_symlink_is_declared_incomplete(self):
        self.metadata("other/eval.dist-info/METADATA", "external")
        approved = self.root / "approved"
        approved.mkdir()
        try:
            (approved / "linked-env").symlink_to(self.root / "other", target_is_directory=True)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"Symlinks unavailable: {exc}")
        code, result = self.scan(approved)
        self.assertEqual(code, 2)
        self.assertFalse(result["distributions"])
        self.assertEqual(len(result["exclusions"]), 1)
        code, result = self.scan(approved / "linked-env")
        self.assertEqual(code, 0)
        self.assertEqual([x["name"] for x in result["distributions"]], ["external"])

    def test_missing_root_does_not_discard_independent_inventory(self):
        self.metadata("approved/eval.dist-info/METADATA", "present")
        code, result = self.scan(self.root / "absent", self.root / "approved")
        self.assertEqual(code, 2)
        self.assertEqual([x["name"] for x in result["distributions"]], ["present"])
        self.assertEqual(len(result["errors"]), 1)

    def test_sentinels_are_not_executed(self):
        sentinel = self.root / "EXECUTED"
        payload = "from pathlib import Path\nPath(" + repr(str(sentinel)) + ").write_text('executed')\n"
        self.write("sitecustomize.py", payload)
        self.write("usercustomize.py", payload)
        self.write("setup.py", payload)
        self.write("site-packages/exec.pth", "import pathlib; pathlib.Path(" + repr(str(sentinel)) + ").write_text('executed')\n")
        self.metadata("site-packages/eval.dist-info/METADATA", "present")
        code, result = self.scan(self.root, extra_env={"PYTHONPATH": str(self.root), "PYTHONSTARTUP": str(self.root / "setup.py")})
        self.assertEqual(code, 0)
        self.assertEqual(len(result["distributions"]), 1)
        self.assertFalse(sentinel.exists())


def main():
    global SCANNER
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scanner", type=Path)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    if not sys.flags.isolated or not sys.flags.no_site:
        parser.error("Run this evaluator with a trusted Python interpreter using -I -S")
    SCANNER = args.scanner.resolve(strict=True)
    before_hash = hashlib.sha256(SCANNER.read_bytes()).hexdigest()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(InventoryTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    after_hash = hashlib.sha256(SCANNER.read_bytes()).hexdigest()
    if args.receipt:
        args.receipt.write_text(json.dumps({"interpreter": sys.executable, "version": sys.version,
            "flags": repr(sys.flags), "scanner": str(SCANNER), "sha256_before": before_hash,
            "sha256_after": after_hash, "tests_run": result.testsRun, "failures": len(result.failures),
            "errors": len(result.errors), "skipped": len(result.skipped), "runs": RECEIPTS}, indent=2) + "\n")
    return 0 if result.wasSuccessful() and before_hash == after_hash else 1


if __name__ == "__main__":
    raise SystemExit(main())
