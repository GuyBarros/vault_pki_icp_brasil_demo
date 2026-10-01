#!/usr/bin/env python3
"""Print certificate inventory fields for Vault KV custom metadata.

Terraform's external data source writes a JSON object to stdin:
{"certificate": "/path/to/certificate.pem"}
Every value in the JSON object on stdout is a string. Private keys are not read.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone


def openssl(certificate: str, *args: str) -> str:
    result = subprocess.run(
        ["openssl", "x509", "-in", certificate, "-noout", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    line = result.stdout.strip().splitlines()[0]
    return line.split("=", 1)[1].strip()


def common_name(subject: str) -> str:
    for part in subject.split(","):
        key, separator, value = part.partition("=")
        if separator and key.strip().upper() == "CN":
            return value.strip()
    return ""


def iso_time(value: str) -> str:
    parsed = datetime.strptime(value.removesuffix(" GMT"), "%b %d %H:%M:%S %Y")
    return parsed.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def policy_oid(certificate: str) -> str:
    text = subprocess.run(
        ["openssl", "x509", "-in", certificate, "-noout", "-text"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Policy: "):
            return stripped.removeprefix("Policy: ").strip()
    return ""


def profile(oid: str) -> str:
    arcs = {
        "2.16.76.1.2.1.": "A1",
        "2.16.76.1.2.3.": "A3",
        "2.16.76.1.2.4.": "A4",
    }
    for prefix, name in arcs.items():
        if oid.startswith(prefix):
            return name
    return ""


def main() -> None:
    certificate = json.load(sys.stdin)["certificate"]
    subject = openssl(certificate, "-subject", "-nameopt", "RFC2253")
    oid = policy_oid(certificate)
    text = subprocess.run(
        ["openssl", "x509", "-in", certificate, "-noout", "-text"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    bits = ""
    for line in text.splitlines():
        if "Public-Key:" in line and "(" in line:
            bits = line.split("(", 1)[1].split(")", 1)[0].replace(" bit", "")
            break
    metadata = {
        "common_name": common_name(subject),
        "subject": subject,
        "issuer": openssl(certificate, "-issuer", "-nameopt", "RFC2253"),
        "serial_number": openssl(certificate, "-serial"),
        "not_before": iso_time(openssl(certificate, "-startdate")),
        "not_after": iso_time(openssl(certificate, "-enddate")),
        "sha256_fingerprint": openssl(certificate, "-fingerprint", "-sha256").replace(":", ""),
        "policy_oid": oid,
        "profile": profile(oid),
        "rsa_bits": bits,
    }
    json.dump(metadata, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
