import json
import threading
import unittest
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from demo_app.database import fetch_rows
from demo_app.server import QuietHTTPServer, Settings, build_status, make_handler


def _server_pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "demo.vault.local")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Vault Demo Intermediate CA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=72))
        .add_extension(
            x509.KeyUsage(True, False, True, False, False, False, False, False, False),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("demo.vault.local")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM).decode(), key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


class FakeConnection:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def cursor(self):
        return self

    def execute(self, statement):
        self.calls.append(statement)

    def fetchone(self):
        return ("v-demo-app-test",)

    def fetchall(self):
        return [(1, "A1 profile", "row")]


class StatusTests(unittest.TestCase):
    def test_status_hides_the_database_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            password = "super-secret-password"
            (root / "db.json").write_text(
                json.dumps(
                    {
                        "username": "v-demo-app-test",
                        "password": password,
                        "lease_id": "database/creds/demo-app/abc",
                        "lease_duration": 3600,
                    }
                ),
                encoding="utf-8",
            )
            settings = Settings(
                secrets_dir=root,
                secrets_source="vault-agent",
                bind_host="127.0.0.1",
                http_port=0,
                tls_port=0,
                postgres_host="127.0.0.1",
                postgres_port=5432,
                postgres_database="demo",
                postgres_sslmode="disable",
                live_secrets_dir=root / "live",
            )

            def connect(**kwargs):
                self.assertEqual(kwargs["password"], password)
                return FakeConnection()

            status = build_status(settings, connect=connect)
            encoded = json.dumps(status)
            self.assertNotIn(password, encoded)
            self.assertEqual(status["database"]["current_user"], "v-demo-app-test")
            self.assertEqual(status["database"]["rows"][0]["titulo"], "A1 profile")
            self.assertFalse(status["icp"]["present"])

    def test_http_serves_a_rendered_certificate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            certificate, private_key = _server_pem()
            (root / "tls.json").write_text(
                json.dumps({"certificate": certificate, "private_key": private_key, "issuing_ca": certificate}),
                encoding="utf-8",
            )
            settings = Settings(
                secrets_dir=root,
                secrets_source="nomad",
                bind_host="127.0.0.1",
                http_port=0,
                tls_port=0,
                postgres_host="127.0.0.1",
                postgres_port=5432,
                postgres_database="demo",
                postgres_sslmode="disable",
                live_secrets_dir=root / "live",
            )
            server = QuietHTTPServer(("127.0.0.1", 0), make_handler(settings))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = server.server_address[1]
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz") as response:
                    self.assertEqual(response.status, 200)
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status") as response:
                    body = json.loads(response.read().decode())
                self.assertTrue(body["tls"]["present"])
                self.assertIn("serverAuth", json.dumps(body["tls"]["checks"]))
                self.assertNotIn(private_key, json.dumps(body))
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/tls") as response:
                    tls = json.loads(response.read().decode())
                self.assertEqual(tls["heading"], "Service PKI")
                self.assertTrue(tls["present"])
                self.assertNotIn(private_key, json.dumps(tls))
                self.assertNotIn("database", tls)
                (root / "db.json").write_text(
                    json.dumps({"username": "v-demo", "password": "db-secret", "lease_duration": 120, "lease_renewed_at": 1}),
                    encoding="utf-8",
                )
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/database") as response:
                    database = json.loads(response.read().decode())
                self.assertEqual(database["heading"], "Dynamic PostgreSQL")
                self.assertNotIn("db-secret", json.dumps(database))
                self.assertEqual(database["username"], "v-demo")
                self.assertTrue(database["lease_expires_at"])
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/") as response:
                    page = response.read().decode()
                self.assertIn("Laboratory only", page)
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

    def test_fetch_rows_uses_the_injected_connection(self):
        connection = FakeConnection()

        def connect(**kwargs):
            self.assertEqual(kwargs["user"], "v-demo")
            return connection

        result = fetch_rows(connect, "v-demo", "pw", "postgres", 5432, "demo", "disable")
        self.assertEqual(result["current_user"], "v-demo-app-test")
        self.assertEqual(len(result["rows"]), 1)


if __name__ == "__main__":
    unittest.main()
