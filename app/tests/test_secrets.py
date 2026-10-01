import base64
import json
import tempfile
import unittest
from pathlib import Path

from demo_app.live_tls import certificate_text, database_text, lease_from_dynamic_secret, write_if_changed
from demo_app.secrets import lease_expires_epoch, load_bundle, load_database, load_preferred_bundle


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
            (icp / "public_key").write_text("dir-public", encoding="utf-8")
            fallback = load_bundle(root, "icp.json", "icp")
            self.assertEqual(fallback.data["private_key"], "dir-key")
            self.assertEqual(fallback.data["public_key"], "dir-public")

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

    def test_live_copy_wins_when_it_expires_later(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mounted = root / "mounted"
            live = root / "live"
            mounted.mkdir()
            live.mkdir()
            (mounted / "tls.json").write_text(
                json.dumps({"certificate": "-----BEGIN CERTIFICATE-----\nold\n-----END CERTIFICATE-----\n", "expiration": "100"}),
                encoding="utf-8",
            )
            (live / "tls.json").write_text(
                json.dumps({"certificate": "-----BEGIN CERTIFICATE-----\nnew\n-----END CERTIFICATE-----\n", "expiration": "200"}),
                encoding="utf-8",
            )
            loaded = load_preferred_bundle(mounted, "tls.json", "tls", live)
            self.assertIn("new", loaded.data["certificate"])

            (live / "tls.json").write_text(
                json.dumps({"certificate": "-----BEGIN CERTIFICATE-----\nstale\n-----END CERTIFICATE-----\n", "expiration": "50"}),
                encoding="utf-8",
            )
            loaded = load_preferred_bundle(mounted, "tls.json", "tls", live)
            self.assertIn("old", loaded.data["certificate"])

    def test_secret_payload_is_written_once(self):
        certificate = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
        payload = {
            "data": {
                "tls.json": base64.b64encode(
                    json.dumps({"certificate": certificate, "expiration": "10"}).encode("utf-8")
                ).decode("ascii")
            }
        }
        text = certificate_text(payload)
        self.assertIn("BEGIN CERTIFICATE", text)
        self.assertIsNone(certificate_text({"data": {}}))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tls.json"
            self.assertTrue(write_if_changed(path, text))
            self.assertFalse(write_if_changed(path, text))

    def test_live_database_lease_wins_when_it_ends_later(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mounted = root / "mounted"
            live = root / "live"
            mounted.mkdir()
            live.mkdir()
            (mounted / "db.json").write_text(
                json.dumps({"username": "old-role", "password": "one", "lease_duration": 30, "lease_renewed_at": 100}),
                encoding="utf-8",
            )
            (live / "db.json").write_text(
                json.dumps({"username": "new-role", "password": "two", "lease_duration": 120, "lease_renewed_at": 200}),
                encoding="utf-8",
            )
            loaded = load_database(mounted, live)
            self.assertEqual(loaded.data["username"], "new-role")
            self.assertEqual(lease_expires_epoch(loaded), 320)

    def test_database_secret_includes_the_lease_and_not_only_the_password(self):
        encoded = base64.b64encode(json.dumps({"username": "v-demo", "password": "secret"}).encode("utf-8")).decode("ascii")
        text = database_text(
            {"data": {"db.json": encoded}},
            {"id": "database/creds/demo-app/lease", "duration": 120, "renewed_at": 50},
        )
        parsed = json.loads(text)
        self.assertEqual(parsed["username"], "v-demo")
        self.assertEqual(parsed["lease_duration"], 120)
        self.assertEqual(parsed["lease_renewed_at"], 50)
        self.assertEqual(
            lease_from_dynamic_secret({"status": {"secretLease": {"id": "lease", "duration": 120}, "lastRenewalTime": 50}}),
            {"id": "lease", "duration": 120, "renewed_at": 50},
        )

    def test_incomplete_json_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "db.json").write_text("{", encoding="utf-8")
            loaded = load_database(root)
            self.assertIsNotNone(loaded.error)


if __name__ == "__main__":
    unittest.main()
