import json
import tempfile
import unittest
from pathlib import Path

from demo_app.secrets import load_bundle, load_database


class SecretLoaderTests(unittest.TestCase):
    def test_json_bundle_and_directory_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = {
                "certificate": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
                "private_key": "secret-key",
                "issuing_ca": "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n",
            }
            (root / "tls.json").write_text(json.dumps(bundle), encoding="utf-8")
            loaded = load_bundle(root, "tls.json", "tls")
            self.assertEqual(loaded.data["private_key"], "secret-key")

            icp = root / "icp"
            icp.mkdir()
            (icp / "certificate").write_text(bundle["certificate"], encoding="utf-8")
            (icp / "private_key").write_text("dir-key", encoding="utf-8")
            fallback = load_bundle(root, "icp.json", "icp")
            self.assertEqual(fallback.data["private_key"], "dir-key")

    def test_database_directory_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / "db"
            db.mkdir()
            (db / "username").write_text("v-demo-app-aaaa\n", encoding="utf-8")
            (db / "password").write_text("s3cret\n", encoding="utf-8")
            loaded = load_database(root)
            self.assertEqual(loaded.data["username"], "v-demo-app-aaaa")
            self.assertEqual(loaded.data["password"], "s3cret")

    def test_incomplete_json_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "db.json").write_text("{", encoding="utf-8")
            loaded = load_database(root)
            self.assertIsNotNone(loaded.error)


if __name__ == "__main__":
    unittest.main()
