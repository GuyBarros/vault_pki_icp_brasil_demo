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


def load_preferred_bundle(
    secrets_dir: Path,
    filename: str,
    fallback_dir: str,
    live_dir: Path | None = None,
) -> LoadedSecret | None:
    """Prefer the rendered file whose certificate expires later.

    A projected Kubernetes Secret can lag behind the Secret object. A live copy
    written from the API should win when it is the newer certificate, and the
    mounted file should win when the live copy is older.
    """

    mounted = load_bundle(secrets_dir, filename, fallback_dir)
    if live_dir is None:
        return mounted
    live = load_bundle(live_dir, filename, fallback_dir)
    return _later_certificate(mounted, live)


def _later_certificate(first: LoadedSecret | None, second: LoadedSecret | None) -> LoadedSecret | None:
    if first is None or first.error:
        return second if second is not None else first
    if second is None or second.error:
        return first
    if _expiration(second) >= _expiration(first):
        return second
    return first


def _expiration(loaded: LoadedSecret) -> float:
    raw = loaded.data.get("expiration")
    try:
        return float(raw)
    except (TypeError, ValueError):
        return loaded.modified_epoch


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


def lease_expires_epoch(loaded: LoadedSecret) -> float | None:
    """Return the lease end as a Unix timestamp.

    ``lease_renewed_at`` plus ``lease_duration`` is the end recorded by Vault.
    A file that only has ``lease_duration`` expires that many seconds after it
    was rendered.
    """

    duration = _as_float(loaded.data.get("lease_duration"))
    if duration is None:
        return None
    renewed = _as_float(loaded.data.get("lease_renewed_at"))
    if renewed is None:
        renewed = loaded.modified_epoch
    return renewed + duration


def load_database(secrets_dir: Path, live_dir: Path | None = None) -> LoadedSecret | None:
    """Load db.json, preferring the copy whose lease ends later."""

    mounted = _load_database(secrets_dir)
    if live_dir is None:
        return mounted
    live = _load_database(live_dir)
    return _later_lease(mounted, live)


def _later_lease(first: LoadedSecret | None, second: LoadedSecret | None) -> LoadedSecret | None:
    if first is None or first.error:
        return second if second is not None else first
    if second is None or second.error:
        return first
    if _lease_rank(second) >= _lease_rank(first):
        return second
    return first


def _lease_rank(loaded: LoadedSecret) -> float:
    expires = lease_expires_epoch(loaded)
    if expires is None:
        return loaded.modified_epoch
    return expires


def _load_database(secrets_dir: Path) -> LoadedSecret | None:
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
    public_key = _read_text(directory / "public_key")
    ca_chain = _read_text(directory / "ca_chain")
    issuing_ca = _read_text(directory / "issuing_ca") or _read_text(directory / "ca.crt") or ca_chain
    if certificate is None and private_key is None and issuing_ca is None and public_key is None:
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
            "public_key": public_key or "",
            "issuing_ca": issuing_ca or "",
            "ca_chain": ca_chain or "",
            "serial_number": _read_text(directory / "serial_number") or "",
            "expiration": _read_text(directory / "expiration") or "",
        },
    )


def _read_text(path: Path) -> str | None:
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8").strip()


def _as_float(value) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def _safe(root: Path, relative: str) -> Path | None:
    root_resolved = root.resolve()
    path = (root_resolved / relative).resolve()
    if path != root_resolved and root_resolved not in path.parents:
        return None
    return path
