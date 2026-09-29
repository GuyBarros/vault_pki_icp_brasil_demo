"""Load secret files rendered by Vault Agent, Nomad, or the Vault Secrets Operator."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class LoadedSecret:
    path: Path
    modified_at: str
    modified_epoch: float
    data: dict
    error: str | None = None


def load_bundle(secrets_dir: Path, filename: str, fallback_dir: str) -> LoadedSecret | None:
    """Load a JSON bundle, or the same fields as separate files in a directory.

    Vault Agent and Nomad write one JSON file per secret so a single lease or
    certificate is rendered once. The Vault Secrets Operator can mount each
    Kubernetes Secret key as its own file; that layout is the fallback.
    """

    bundle = _safe(secrets_dir, filename)
    if bundle is not None and bundle.is_file():
        return _from_json(bundle)

    directory = _safe(secrets_dir, fallback_dir)
    if directory is None or not directory.is_dir():
        return None
    return _from_directory(directory)


def load_database(secrets_dir: Path) -> LoadedSecret | None:
    bundle = _safe(secrets_dir, "db.json")
    if bundle is not None and bundle.is_file():
        return _from_json(bundle)

    directory = _safe(secrets_dir, "db")
    if directory is None or not directory.is_dir():
        return None

    username = _read_text(directory / "username")
    password = _read_text(directory / "password")
    if username is None and password is None:
        return None

    data = {
        "username": username or "",
        "password": password or "",
        "lease_id": _read_text(directory / "lease_id") or "",
        "lease_duration": _read_text(directory / "lease_duration") or "",
    }
    stamp = directory / "username"
    if not stamp.is_file():
        stamp = directory
    modified_epoch = stamp.stat().st_mtime
    return LoadedSecret(
        path=directory,
        modified_at=_iso(modified_epoch),
        modified_epoch=modified_epoch,
        data=data,
    )


def _from_json(path: Path) -> LoadedSecret:
    modified_epoch = path.stat().st_mtime
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return LoadedSecret(
            path=path,
            modified_at=_iso(modified_epoch),
            modified_epoch=modified_epoch,
            data={},
            error=f"{path.name} is not valid JSON yet. The renderer may still be writing it.",
        )
    if not isinstance(parsed, dict):
        return LoadedSecret(
            path=path,
            modified_at=_iso(modified_epoch),
            modified_epoch=modified_epoch,
            data={},
            error=f"{path.name} must contain a JSON object.",
        )
    return LoadedSecret(
        path=path,
        modified_at=_iso(modified_epoch),
        modified_epoch=modified_epoch,
        data=parsed,
    )


def _from_directory(directory: Path) -> LoadedSecret | None:
    certificate = _read_text(directory / "certificate") or _read_text(directory / "tls.crt")
    private_key = _read_text(directory / "private_key") or _read_text(directory / "tls.key")
    issuing_ca = (
        _read_text(directory / "issuing_ca")
        or _read_text(directory / "ca.crt")
        or _read_text(directory / "ca_chain")
    )
    if certificate is None and private_key is None and issuing_ca is None:
        return None

    stamp = directory / "certificate"
    if not stamp.is_file():
        stamp = directory
    modified_epoch = stamp.stat().st_mtime
    return LoadedSecret(
        path=directory,
        modified_at=_iso(modified_epoch),
        modified_epoch=modified_epoch,
        data={
            "certificate": certificate or "",
            "private_key": private_key or "",
            "issuing_ca": issuing_ca or "",
            "serial_number": _read_text(directory / "serial_number") or "",
            "expiration": _read_text(directory / "expiration") or "",
        },
    )


def _read_text(path: Path) -> str | None:
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8").strip()


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def _safe(root: Path, relative: str) -> Path | None:
    root_resolved = root.resolve()
    path = (root_resolved / relative).resolve()
    if path != root_resolved and root_resolved not in path.parents:
        return None
    return path
