"""Copy the service certificate from the Kubernetes API.

A projected Secret is refreshed on the kubelet sync period. That period is
longer than this certificate's one-minute lifetime, so the page can keep an
expired certificate and the card stays yellow. Reading the Secret object
picks up the operator's update within about a second.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import ssl
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

log = logging.getLogger("demo.live_tls")

TOKEN_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
NAMESPACE_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
CA_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")


def start(destination: Path) -> None:
    host = os.environ.get("KUBERNETES_SERVICE_HOST", "")
    if not host or not TOKEN_PATH.is_file() or not NAMESPACE_PATH.is_file():
        return
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    tls_secret = os.environ.get("TLS_SECRET_NAME", "tls-cert")
    db_secret = os.environ.get("DB_SECRET_NAME", "db-creds")
    threading.Thread(
        target=_poll_tls,
        args=(host, port, tls_secret, destination),
        name="live-tls",
        daemon=True,
    ).start()
    threading.Thread(
        target=_poll_database,
        args=(host, port, db_secret, destination),
        name="live-db",
        daemon=True,
    ).start()


def certificate_text(secret: dict) -> str | None:
    encoded = (secret.get("data") or {}).get("tls.json")
    if not encoded:
        return None
    try:
        text = base64.b64decode(encoded).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict) or "BEGIN CERTIFICATE" not in str(parsed.get("certificate") or ""):
        return None
    return text


def database_text(secret: dict, lease: dict | None) -> str | None:
    encoded = (secret.get("data") or {}).get("db.json")
    if not encoded:
        return None
    try:
        text = base64.b64decode(encoded).decode("utf-8")
        parsed = json.loads(text)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, dict) or not parsed.get("username"):
        return None
    if lease:
        if lease.get("id"):
            parsed["lease_id"] = lease["id"]
        if lease.get("duration") is not None:
            parsed["lease_duration"] = int(lease["duration"])
        if lease.get("renewed_at") is not None:
            parsed["lease_renewed_at"] = int(lease["renewed_at"])
    return json.dumps(parsed)


def lease_from_dynamic_secret(payload: dict) -> dict | None:
    status = payload.get("status") or {}
    lease = status.get("secretLease") or {}
    if not lease and status.get("lastRenewalTime") is None:
        return None
    return {
        "id": lease.get("id") or "",
        "duration": lease.get("duration"),
        "renewed_at": status.get("lastRenewalTime"),
    }


def write_if_changed(path: Path, content: str) -> bool:
    if path.is_file() and path.read_text(encoding="utf-8") == content:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)
    return True


def _poll_tls(host: str, port: str, secret_name: str, destination: Path) -> None:
    _poll(host, port, secret_name, destination, "tls.json", _fetch_tls, "service certificate")


def _poll_database(host: str, port: str, secret_name: str, destination: Path) -> None:
    _poll(host, port, secret_name, destination, "db.json", _fetch_database, "database credential")


def _poll(host: str, port: str, secret_name: str, destination: Path, filename: str, fetch, label: str) -> None:
    warned = False
    while True:
        try:
            text = fetch(host, port, secret_name)
            if text and write_if_changed(destination / filename, text):
                log.info("stored a newer %s from %s", label, secret_name)
        except Exception:
            if not warned:
                log.warning("could not read secret %s from the Kubernetes API", secret_name, exc_info=True)
                warned = True
        time.sleep(1)


def _fetch_tls(host: str, port: str, secret_name: str) -> str | None:
    payload = _get_json(host, port, f"/api/v1/namespaces/{{ns}}/secrets/{secret_name}")
    if payload is None:
        return None
    return certificate_text(payload)


def _fetch_database(host: str, port: str, secret_name: str) -> str | None:
    secret = _get_json(host, port, f"/api/v1/namespaces/{{ns}}/secrets/{secret_name}")
    if secret is None:
        return None
    lease = None
    try:
        dynamic = _get_json(
            host,
            port,
            f"/apis/secrets.hashicorp.com/v1beta1/namespaces/{{ns}}/vaultdynamicsecrets/{secret_name}",
        )
    except Exception:
        dynamic = None
    if dynamic is not None:
        lease = lease_from_dynamic_secret(dynamic)
    return database_text(secret, lease)


def _get_json(host: str, port: str, path_template: str) -> dict | None:
    namespace = NAMESPACE_PATH.read_text(encoding="utf-8").strip()
    token = TOKEN_PATH.read_text(encoding="utf-8").strip()
    address = f"[{host}]" if ":" in host else host
    path = path_template.format(ns=namespace)
    request = urllib.request.Request(
        f"https://{address}:{port}{path}",
        headers={"Authorization": f"Bearer {token}"},
    )
    context = ssl.create_default_context(cafile=str(CA_PATH)) if CA_PATH.is_file() else ssl.create_default_context()
    try:
        with urllib.request.urlopen(request, context=context, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise
    if not isinstance(payload, dict):
        return None
    return payload
