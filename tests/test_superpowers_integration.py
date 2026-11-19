"""Tests for the repository-pinned Superpowers developer-tool dependency."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from verify_superpowers import check_metadata

SOURCE = "https://github.com/obra/superpowers.git"
REVISION = "22f0b463e7a5e579904dd6211a520321035526f7"


class SubmoduleMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.modules = self.root / ".gitmodules"
        self.lock = self.root / "superpowers.lock.json"
        self.modules.write_text('[submodule "tools/superpowers"]\n\tpath = tools/superpowers\n\turl = ' + SOURCE + '\n', encoding="utf-8")
        self.lock.write_text(json.dumps({"repository": SOURCE, "revision": REVISION}), encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_accepts_official_pinned_submodule(self):
        self.assertEqual(check_metadata(self.root), REVISION)

    def test_rejects_untrusted_repository(self):
        self.lock.write_text(json.dumps({"repository": "https://example.invalid/mirror.git", "revision": REVISION}), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "official"):
            check_metadata(self.root)

    def test_rejects_unpinned_commit(self):
        self.lock.write_text(json.dumps({"repository": SOURCE, "revision": "main"}), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "40-character"):
            check_metadata(self.root)

    def test_rejects_submodule_url_mismatch(self):
        self.modules.write_text('[submodule "tools/superpowers"]\n\tpath = tools/superpowers\n\turl = https://example.invalid/evil.git\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "expected path and upstream"):
            check_metadata(self.root)


if __name__ == "__main__":
    unittest.main()
