#!/usr/bin/env python3
"""Regression tests for the publication bug that excluded Rust src/bin sources."""
from contextlib import redirect_stdout
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import check_package
import verify_manifest


class RustSources(unittest.TestCase):
    def fixture(self, root):
        for component in ['zk-component','pq-identity']:
            host=root/component/'zk/host'
            (host/'src/bin').mkdir(parents=True)
            (host/'Cargo.toml').write_text('[[bin]]\nname="zkverify"\npath="src/bin/zkverify.rs"\n')
            (host/'src/bin/zkverify.rs').write_text('fn main() {}\n')

    def check(self, root):
        with patch.object(check_package,'ROOT',root), patch.object(verify_manifest,'ROOT',root), patch.object(sys,'argv',['check_package','--source-only']), redirect_stdout(io.StringIO()):
            return check_package.main()

    def test_complete_source_is_inventoried(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); self.fixture(root)
            self.assertFalse(self.check(root))

    def test_missing_declared_source_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); self.fixture(root)
            (root/'pq-identity/zk/host/src/bin/zkverify.rs').unlink()
            self.assertTrue(self.check(root))

    def test_broad_git_bin_ignore_fails_until_source_exception(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); self.fixture(root)
            subprocess.run(['git','init','--quiet',root],check=True)
            ignore=root/'.gitignore';ignore.write_text('**/bin/\n')
            self.assertTrue(self.check(root))
            ignore.write_text('**/bin/\n!**/src/bin/\n!**/src/bin/*.rs\n')
            self.assertFalse(self.check(root))


if __name__=='__main__':
    unittest.main()
