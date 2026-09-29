"""HTTP UI for the three Vault-rendered secrets."""

from __future__ import annotations

import json
import logging
import os
import ssl
import tempfile
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from demo_app.certificates import missing_certificate, summarize_certificate, utc_now
from demo_app.database import connect_psycopg, fetch_rows
from demo_app.secrets import LoadedSecret, load_bundle, load_database


PACKAGE_DIR = Path(__file__).resolve().parent
STATIC_FILES = {
    "app.css": "text/css; charset=utf-8",
    "app.js": "text/javascript; charset=utf-8",
}

SOURCES = {
    "vault-agent": "Vault Agent is rendering these files onto a shared volume.",
    "vault-secrets-operator": "The Vault Secrets Operator is syncing these files into a Kubernetes Secret.",
    "nomad": "Nomad is rendering these files with its Vault template stanza.",
}

log = logging.getLogger("demo")


@dataclass(frozen=True)
class Settings:
    secrets_dir: Path
    secrets_source: str
    bind_host: str
    http_port: int
    tls_port: int
    postgres_host: str
    postgres_port: int
    postgres_database: str
    postgres_sslmode: str


def settings_from_env() -> Settings:
    return Settings(
        secrets_dir=Path(os.environ.get("SECRETS_DIR", "/vault/secrets")),
        secrets_source=os.environ.get("SECRETS_SOURCE", "vault-agent"),
        bind_host=os.environ.get("BIND_HOST", "0.0.0.0"),
        http_port=int(os.environ.get("PORT", "8080")),
        tls_port=int(os.environ.get("TLS_PORT", "8443")),
        postgres_host=os.environ.get("POSTGRES_HOST", "127.0.0.1"),
        postgres_port=int(os.environ.get("POSTGRES_PORT", "5432")),
        postgres_database=os.environ.get("POSTGRES_DB", "demo"),
        postgres_sslmode=os.environ.get("POSTGRES_SSLMODE", "disable"),
    )


def build_status(settings: Settings, connect=connect_psycopg) -> dict:
    source = settings.secrets_source
    return {
        "source": {
            "id": source,
            "label": SOURCES.get(source, f"Secrets are read from {settings.secrets_dir} ({source})."),
        },
        "secrets_dir": str(settings.secrets_dir),
        "checked_at": utc_now().isoformat(),
        "icp": _certificate_status(
            settings,
            filename="icp.json",
            fallback_dir="icp",
            profile="icp-a1",
            heading="ICP-Brasil A1 profile",
            ca_path="/ca/icp",
        ),
        "tls": _certificate_status(
            settings,
            filename="tls.json",
            fallback_dir="tls",
            profile="tls-server",
            heading="Service PKI",
            ca_path="/ca/tls",
        ),
        "database": _database_status(settings, connect),
    }


def issuing_ca(settings: Settings, filename: str, fallback_dir: str) -> str | None:
    loaded = load_bundle(settings.secrets_dir, filename, fallback_dir)
    if loaded is None or loaded.error:
        return None
    pem = loaded.data.get("issuing_ca") or ""
    if "BEGIN CERTIFICATE" not in pem:
        return None
    return pem


def _certificate_status(settings: Settings, filename: str, fallback_dir: str, profile: str, heading: str, ca_path: str) -> dict:
    try:
        loaded = load_bundle(settings.secrets_dir, filename, fallback_dir)
        if loaded is None:
            return missing_certificate(
                heading,
                f"Waiting for {settings.secrets_dir / filename}. The renderer has not written it yet.",
            )
        if loaded.error:
            return missing_certificate(heading, loaded.error)
        certificate = loaded.data.get("certificate") or ""
        if "BEGIN CERTIFICATE" not in certificate:
            return missing_certificate(heading, f"{filename} does not contain a certificate yet.")
        issuing = loaded.data.get("issuing_ca") or ""
        return summarize_certificate(
            certificate,
            profile=profile,
            private_key_present=bool(loaded.data.get("private_key")),
            issuing_ca_pem=issuing or None,
            ca_chain=loaded.data.get("ca_chain"),
            rendered_at=loaded.modified_at,
            ca_path=ca_path,
        )
    except Exception as exc:
        log.exception("could not read %s", filename)
        return missing_certificate(heading, str(exc))


def _database_status(settings: Settings, connect) -> dict:
    heading = "Dynamic PostgreSQL"
    try:
        loaded = load_database(settings.secrets_dir)
    except Exception as exc:
        log.exception("could not read database secret")
        return _database_view(present=False, message=str(exc))

    if loaded is None:
        return _database_view(
            present=False,
            message=f"Waiting for {settings.secrets_dir / 'db.json'}. The renderer has not written it yet.",
        )
    if loaded.error:
        return _database_view(present=False, message=loaded.error)

    username = str(loaded.data.get("username") or "")
    password = str(loaded.data.get("password") or "")
    view = _database_view(
        present=True,
        username=username,
        lease_id=str(loaded.data.get("lease_id") or ""),
        lease_duration_seconds=_as_int(loaded.data.get("lease_duration")),
        modified_at=loaded.modified_at,
        modified_epoch=loaded.modified_epoch,
    )
    if not username or not password:
        view["error"] = "The rendered secret has no username or password."
        return view

    try:
        result = fetch_rows(
            connect,
            username,
            password,
            settings.postgres_host,
            settings.postgres_port,
            settings.postgres_database,
            settings.postgres_sslmode,
        )
    except Exception as exc:
        log.warning("database login failed for %s", username)
        view["error"] = _redact(str(exc), password)
        return view

    view["current_user"] = result["current_user"]
    view["rows"] = result["rows"]
    return view


def _database_view(
    *,
    present: bool,
    message: str = "",
    username: str = "",
    lease_id: str = "",
    lease_duration_seconds: int | None = None,
    modified_at: str = "",
    modified_epoch: float | None = None,
) -> dict:
    remaining = None
    if lease_duration_seconds is not None and modified_epoch is not None:
        remaining = max(0, int(lease_duration_seconds - (time.time() - modified_epoch)))
    return {
        "present": present,
        "heading": "Dynamic PostgreSQL",
        "message": message,
        "username": username,
        "lease_id": lease_id,
        "lease_duration_seconds": lease_duration_seconds,
        "lease_remaining_seconds": remaining,
        "modified_at": modified_at,
        "current_user": "",
        "rows": [],
        "error": "",
    }


def _as_int(value) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _redact(message: str, secret: str) -> str:
    if secret and secret in message:
        return message.replace(secret, "***")
    return message


class TLSMaterial:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._marker: tuple | None = None
        self._context: ssl.SSLContext | None = None

    def context_for(self, settings: Settings) -> ssl.SSLContext | None:
        loaded = load_bundle(settings.secrets_dir, "tls.json", "tls")
        if loaded is None or loaded.error:
            return self._current()
        certificate = loaded.data.get("certificate") or ""
        private_key = loaded.data.get("private_key") or ""
        if "BEGIN CERTIFICATE" not in certificate or not private_key:
            return self._current()
        marker = (str(loaded.path), loaded.modified_epoch)
        with self._lock:
            if self._context is not None and self._marker == marker:
                return self._context
            try:
                context = _ssl_context(loaded)
            except Exception:
                log.exception("could not load the rendered TLS certificate")
                return self._context
            self._context = context
            self._marker = marker
            log.info("loaded TLS certificate rendered at %s", loaded.modified_at)
            return context

    def _current(self) -> ssl.SSLContext | None:
        with self._lock:
            return self._context


def _ssl_context(loaded: LoadedSecret) -> ssl.SSLContext:
    directory = Path(tempfile.gettempdir()) / "vault-pki-demo"
    directory.mkdir(parents=True, exist_ok=True)
    certificate = str(loaded.data.get("certificate") or "")
    private_key = str(loaded.data.get("private_key") or "")
    issuing = str(loaded.data.get("issuing_ca") or "")
    if certificate and not certificate.endswith("\n"):
        certificate += "\n"
    if issuing and "BEGIN CERTIFICATE" in issuing:
        if not issuing.endswith("\n"):
            issuing += "\n"
        certificate += issuing
    if private_key and not private_key.endswith("\n"):
        private_key += "\n"

    cert_path = directory / "tls.crt"
    key_path = directory / "tls.key"
    cert_path.write_text(certificate, encoding="utf-8")
    key_path.write_text(private_key, encoding="utf-8")
    key_path.chmod(0o600)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return context


class QuietHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class TLSServer(QuietHTTPServer):
    def __init__(self, address, handler, settings: Settings, material: TLSMaterial) -> None:
        super().__init__(address, handler)
        self.settings = settings
        self.material = material

    def get_request(self):
        sock, address = super().get_request()
        context = self.material.context_for(self.settings)
        if context is None:
            sock.close()
            raise OSError("TLS certificate is not loaded")
        try:
            return context.wrap_socket(sock, server_side=True), address
        except ssl.SSLError:
            sock.close()
            raise


def make_handler(settings: Settings):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args) -> None:
            return

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            if path == "/":
                self._send(200, (PACKAGE_DIR / "templates" / "index.html").read_bytes(), "text/html; charset=utf-8")
                return
            if path == "/healthz":
                self._send(200, b'{"status":"ok"}', "application/json")
                return
            if path == "/api/status":
                body = json.dumps(build_status(settings)).encode("utf-8")
                self._send(200, body, "application/json")
                return
            if path == "/ca/tls":
                self._send_ca("tls.json", "tls", "vault-demo-tls-ca.pem")
                return
            if path == "/ca/icp":
                self._send_ca("icp.json", "icp", "vault-demo-icp-ca.pem")
                return
            if path.startswith("/static/"):
                name = path.removeprefix("/static/")
                content_type = STATIC_FILES.get(name)
                if content_type is None:
                    self._send(404, b"not found", "text/plain; charset=utf-8")
                    return
                self._send(200, (PACKAGE_DIR / "static" / name).read_bytes(), content_type)
                return
            self._send(404, b"not found", "text/plain; charset=utf-8")

        def _send_ca(self, filename: str, fallback_dir: str, download_name: str) -> None:
            pem = issuing_ca(settings, filename, fallback_dir)
            if pem is None:
                self._send(404, b"issuing CA is not rendered yet", "text/plain; charset=utf-8")
                return
            data = pem.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/x-pem-file")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Disposition", f'attachment; filename="{download_name}"')
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    return Handler


def _serve_tls(settings: Settings) -> None:
    material = TLSMaterial()
    while material.context_for(settings) is None:
        time.sleep(1)
    try:
        server = TLSServer((settings.bind_host, settings.tls_port), make_handler(settings), settings, material)
    except OSError:
        log.exception("HTTPS listener did not start")
        return
    log.info("https://%s:%s", settings.bind_host, settings.tls_port)
    server.serve_forever()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    settings = settings_from_env()
    if settings.tls_port > 0:
        threading.Thread(target=_serve_tls, args=(settings,), name="https", daemon=True).start()
    server = QuietHTTPServer((settings.bind_host, settings.http_port), make_handler(settings))
    log.info("http://%s:%s", settings.bind_host, settings.http_port)
    server.serve_forever()
