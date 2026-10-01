"""Read X.509 certificates and compare them with the two lab profiles.

The ICP-Brasil view follows DOC-ICP-04 for a type A1 signature certificate:
RSA of at least 2048 bits, SHA-256, digitalSignature and contentCommitment,
clientAuth and emailProtection, country BR, and a policy OID under
2.16.76.1.2.1.n. It does not check the accredited binary layout of the CPF
otherName. The laboratory file stores that otherName as a UTF-8 string.
"""

from __future__ import annotations

from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier, SignatureAlgorithmOID


A1_ARC = ("2", "16", "76", "1", "2")
CPF_OID = "2.16.76.1.3.1"
CNPJ_OID = "2.16.76.1.3.3"
RESPONSIBLE_OID = "2.16.76.1.3.4"

OTHER_NAME_LABELS = {
    CPF_OID: "CPF (pessoa fisica)",
    CNPJ_OID: "CNPJ",
    RESPONSIBLE_OID: "Responsavel pelo certificado de pessoa juridica",
}

POLICY_TYPES = {
    "1": "A1",
    "2": "A2",
    "3": "A3",
    "4": "A4",
    "101": "S1",
    "102": "S2",
    "103": "S3",
    "104": "S4",
}

SIGNATURE_NAMES = {
    SignatureAlgorithmOID.RSA_WITH_SHA256: "sha256WithRSAEncryption",
    SignatureAlgorithmOID.RSA_WITH_SHA384: "sha384WithRSAEncryption",
    SignatureAlgorithmOID.RSA_WITH_SHA512: "sha512WithRSAEncryption",
    SignatureAlgorithmOID.ECDSA_WITH_SHA256: "ecdsa-with-SHA256",
}

EKU_NAMES = {
    ExtendedKeyUsageOID.SERVER_AUTH: "serverAuth",
    ExtendedKeyUsageOID.CLIENT_AUTH: "clientAuth",
    ExtendedKeyUsageOID.CODE_SIGNING: "codeSigning",
    ExtendedKeyUsageOID.EMAIL_PROTECTION: "emailProtection",
}

KEY_USAGE_BITS = (
    ("digital_signature", "digitalSignature"),
    ("content_commitment", "contentCommitment"),
    ("key_encipherment", "keyEncipherment"),
    ("data_encipherment", "dataEncipherment"),
    ("key_agreement", "keyAgreement"),
    ("key_cert_sign", "keyCertSign"),
    ("crl_sign", "cRLSign"),
)


def summarize_certificate(
    pem: str,
    *,
    profile: str,
    private_key_present: bool,
    issuing_ca_pem: str | None,
    ca_chain,
    rendered_at: str,
    ca_path: str | None,
    public_key_pem: str | None = None,
) -> dict:
    certificate = x509.load_pem_x509_certificate(_pem_bytes(pem))
    parsed = _parse(certificate)
    chain = _chain_subjects(certificate, issuing_ca_pem, ca_chain)
    public_key_matches = _public_key_matches(certificate, public_key_pem)
    if profile == "icp-a1":
        checks = _icp_checks(parsed, public_key_matches)
        heading = "ICP-Brasil A1 profile"
        summary = (
            "Stored in KV and rendered from there. Vault did not issue this certificate. "
            "The issuing CA in the chain is the authority that signed it."
        )
    elif profile == "tls-server":
        checks = _tls_checks(parsed)
        heading = "Service PKI"
        summary = "Short-lived server certificate from the Vault PKI secrets engine. This chain is separate from the A1 profile."
    else:
        raise ValueError(f"unknown certificate profile {profile}")

    fields = [
        _field("Common name", parsed["common_name"]),
        _field("Subject", parsed["subject"], mono=True),
        _field("Issuer", parsed["issuer"], mono=True),
        _field("Serial", parsed["serial"], mono=True),
        _field("Not before", parsed["not_before"]),
        _field("Not after", parsed["not_after"]),
        _field("Signature", parsed["signature"]),
        _field("Public key", parsed["public_key"]),
        _field("SHA-256", parsed["fingerprint"], mono=True),
        _field("Key usage", ", ".join(parsed["key_usage"]) or "none"),
        _field("Extended key usage", ", ".join(parsed["extended_key_usage"]) or "none"),
        _field("Policies", _policy_text(parsed["policies"])),
        _field("Subject alternative names", _san_text(parsed["sans"])),
        _field(
            "Private key",
            ("rendered from KV" if profile == "icp-a1" else "rendered next to the certificate")
            if private_key_present
            else "missing",
        ),
        _field("Rendered", rendered_at),
    ]
    if profile == "icp-a1":
        if public_key_matches is True:
            stored_public_key = "stored in KV and matches this certificate"
        elif public_key_matches is False:
            stored_public_key = "stored in KV but does not match this certificate"
        else:
            stored_public_key = "missing from the KV secret"
        fields.append(_field("Stored public key", stored_public_key))
        fields.append(
            _field(
                "CPF encoding",
                "UTF-8 laboratory value. DOC-ICP-04 defines OID 2.16.76.1.3.1 as a fixed octet string; an accredited issuer produces that layout.",
            )
        )

    return {
        "present": True,
        "heading": heading,
        "summary": summary,
        "checks": checks,
        "fields": fields,
        "chain": chain,
        "ca_path": ca_path if issuing_ca_pem else None,
        "message": "",
    }


def _parse(certificate: x509.Certificate) -> dict:
    key_usage, key_usage_critical = _key_usage(certificate)
    extended = _extended_key_usage(certificate)
    policies = _policies(certificate)
    sans = _sans(certificate)
    basic = _basic_constraints(certificate)
    public_key = certificate.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        key_description = f"RSA {public_key.key_size}"
        key_type = "rsa"
        key_bits = public_key.key_size
    else:
        key_description = type(public_key).__name__
        key_type = key_description
        key_bits = getattr(public_key, "key_size", 0) or 0

    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    signature = SIGNATURE_NAMES.get(
        certificate.signature_algorithm_oid,
        certificate.signature_algorithm_oid.dotted_string,
    )
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
    return {
        "common_name": _name_value(certificate.subject, NameOID.COMMON_NAME),
        "country": _name_value(certificate.subject, NameOID.COUNTRY_NAME),
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "serial": format(certificate.serial_number, "x"),
        "not_before": not_before.astimezone(timezone.utc).isoformat(),
        "not_after": not_after.astimezone(timezone.utc).isoformat(),
        "lifetime_days": (not_after - not_before).total_seconds() / 86400,
        "signature": signature,
        "public_key": key_description,
        "key_type": key_type,
        "key_bits": key_bits,
        "fingerprint": ":".join(fingerprint[index : index + 2] for index in range(0, len(fingerprint), 2)),
        "key_usage": key_usage,
        "key_usage_critical": key_usage_critical,
        "extended_key_usage": extended,
        "policies": policies,
        "sans": sans,
        "is_ca": basic["is_ca"],
        "basic_constraints_present": basic["present"],
    }


def _public_key_matches(certificate: x509.Certificate, public_key_pem: str | None) -> bool | None:
    if not public_key_pem or "BEGIN PUBLIC KEY" not in public_key_pem:
        return None

    loaded = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    return loaded.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ) == certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _icp_checks(parsed: dict, public_key_matches: bool | None) -> list[dict]:
    policy_oids = [item["oid"] for item in parsed["policies"]]
    other_oids = [item["oid"] for item in parsed["sans"]["other"]]
    usage = set(parsed["key_usage"])
    extended = set(parsed["extended_key_usage"])
    a1_policies = [oid for oid in policy_oids if policy_type(oid) == "A1"]
    return [
        _check(
            "rsa-2048",
            "RSA key of at least 2048 bits",
            parsed["key_type"] == "rsa" and parsed["key_bits"] >= 2048,
            parsed["public_key"],
        ),
        _check(
            "sha256",
            "SHA-256 signature",
            "sha256" in parsed["signature"].lower(),
            parsed["signature"],
        ),
        _check(
            "key-usage",
            "digitalSignature and contentCommitment",
            {"digitalSignature", "contentCommitment"} <= usage and "keyCertSign" not in usage,
            ", ".join(parsed["key_usage"]) or "none",
        ),
        _check(
            "eku",
            "clientAuth and emailProtection, and not serverAuth",
            {"clientAuth", "emailProtection"} <= extended and "serverAuth" not in extended,
            ", ".join(parsed["extended_key_usage"]) or "none",
        ),
        _check(
            "country",
            "Country BR",
            parsed["country"] == "BR",
            parsed["country"] or "missing",
        ),
        _check(
            "policy",
            "Certificate policy in the A1 arc 2.16.76.1.2.1.n",
            bool(a1_policies),
            ", ".join(a1_policies) or "none",
        ),
        _check(
            "cpf",
            "otherName CPF OID 2.16.76.1.3.1",
            CPF_OID in other_oids,
            ", ".join(other_oids) or "none",
        ),
        _check(
            "lifetime",
            "Validity of at most one year",
            parsed["lifetime_days"] <= 366,
            f"{parsed['lifetime_days']:.1f} days",
        ),
        _check(
            "basic",
            "basicConstraints present and CA is false",
            parsed["basic_constraints_present"] and not parsed["is_ca"],
            "CA true" if parsed["is_ca"] else "CA false" if parsed["basic_constraints_present"] else "extension missing",
        ),
        _check(
            "public-key",
            "KV public key matches the certificate",
            public_key_matches is True,
            "matches" if public_key_matches else "missing" if public_key_matches is None else "does not match",
        ),
    ]


def _tls_checks(parsed: dict) -> list[dict]:
    extended = set(parsed["extended_key_usage"])
    usage = set(parsed["key_usage"])
    icp_policies = [item["oid"] for item in parsed["policies"] if policy_type(item["oid"])]
    return [
        _check(
            "server-auth",
            "extended key usage includes serverAuth",
            "serverAuth" in extended,
            ", ".join(parsed["extended_key_usage"]) or "none",
        ),
        _check(
            "key-usage",
            "digitalSignature is set",
            "digitalSignature" in usage,
            ", ".join(parsed["key_usage"]) or "none",
        ),
        _check(
            "sha256",
            "SHA-256 signature",
            "sha256" in parsed["signature"].lower(),
            parsed["signature"],
        ),
        _check(
            "basic",
            "Not a certificate authority",
            parsed["basic_constraints_present"] and not parsed["is_ca"],
            "CA true" if parsed["is_ca"] else "CA false" if parsed["basic_constraints_present"] else "extension missing",
        ),
        _check(
            "separate-chain",
            "No ICP-Brasil end-entity policy",
            not icp_policies,
            ", ".join(icp_policies) or "none",
        ),
    ]


def policy_type(oid: str) -> str:
    parts = oid.split(".")
    if len(parts) < 7 or tuple(parts[:5]) != A1_ARC:
        return ""
    return POLICY_TYPES.get(parts[5], "")


def _key_usage(certificate: x509.Certificate) -> tuple[list[str], bool]:
    try:
        extension = certificate.extensions.get_extension_for_class(x509.KeyUsage)
    except x509.ExtensionNotFound:
        return [], False
    usage = extension.value
    names = [label for attribute, label in KEY_USAGE_BITS if getattr(usage, attribute)]
    return names, extension.critical


def _extended_key_usage(certificate: x509.Certificate) -> list[str]:
    try:
        extension = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound:
        return []
    names = []
    for oid in extension.value:
        names.append(EKU_NAMES.get(oid, oid.dotted_string))
    return names


def _policies(certificate: x509.Certificate) -> list[dict]:
    try:
        extension = certificate.extensions.get_extension_for_class(x509.CertificatePolicies)
    except x509.ExtensionNotFound:
        return []
    policies = []
    for policy in extension.value:
        notices = []
        cps = []
        for qualifier in policy.policy_qualifiers or []:
            if isinstance(qualifier, str):
                cps.append(qualifier)
            elif isinstance(qualifier, x509.UserNotice) and qualifier.explicit_text:
                notices.append(qualifier.explicit_text)
        policies.append(
            {
                "oid": policy.policy_identifier.dotted_string,
                "type": policy_type(policy.policy_identifier.dotted_string),
                "cps": cps,
                "notices": notices,
            }
        )
    return policies


def _sans(certificate: x509.Certificate) -> dict:
    result = {"dns": [], "email": [], "ip": [], "uri": [], "other": []}
    try:
        extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return result
    for name in extension.value:
        if isinstance(name, x509.DNSName):
            result["dns"].append(name.value)
        elif isinstance(name, x509.RFC822Name):
            result["email"].append(name.value)
        elif isinstance(name, x509.IPAddress):
            result["ip"].append(str(name.value))
        elif isinstance(name, x509.UniformResourceIdentifier):
            result["uri"].append(name.value)
        elif isinstance(name, x509.OtherName):
            oid = name.type_id.dotted_string
            result["other"].append(
                {
                    "oid": oid,
                    "label": OTHER_NAME_LABELS.get(oid, "otherName"),
                    "value": _decode_other_name(name.value),
                }
            )
    return result


def _basic_constraints(certificate: x509.Certificate) -> dict:
    try:
        extension = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        return {"present": False, "is_ca": False}
    return {"present": True, "is_ca": extension.value.ca}


def _chain_subjects(certificate: x509.Certificate, issuing_ca_pem: str | None, ca_chain) -> list[str]:
    subjects = [certificate.subject.rfc4514_string()]
    for pem in [issuing_ca_pem, *_pem_list(ca_chain)]:
        if not pem:
            continue
        for block in _split_pems(pem):
            try:
                subject = x509.load_pem_x509_certificate(_pem_bytes(block)).subject.rfc4514_string()
            except ValueError:
                continue
            if subject not in subjects:
                subjects.append(subject)
    return subjects


def _decode_other_name(value: bytes) -> str:
    if len(value) < 2:
        return value.hex()
    tag = value[0]
    length_byte = value[1]
    if length_byte < 0x80:
        start = 2
        length = length_byte
    elif length_byte == 0x81 and len(value) >= 3:
        start = 3
        length = value[2]
    else:
        return value.hex()
    raw = value[start : start + length]
    if tag in (0x0C, 0x13, 0x16, 0x12):
        return raw.decode("utf-8", errors="replace")
    if tag == 0x1E:
        return raw.decode("utf-16-be", errors="replace")
    return raw.hex()


def _policy_text(policies: list[dict]) -> str:
    if not policies:
        return "none"
    lines = []
    for policy in policies:
        label = policy["oid"]
        if policy["type"]:
            label = f"{label} ({policy['type']})"
        if policy["cps"]:
            label = f"{label}; CPS {', '.join(policy['cps'])}"
        if policy["notices"]:
            label = f"{label}; {policy['notices'][0]}"
        lines.append(label)
    return "\n".join(lines)


def _san_text(sans: dict) -> str:
    lines = []
    for name in sans["dns"]:
        lines.append(f"DNS {name}")
    for name in sans["email"]:
        lines.append(f"email {name}")
    for name in sans["ip"]:
        lines.append(f"IP {name}")
    for name in sans["uri"]:
        lines.append(f"URI {name}")
    for name in sans["other"]:
        lines.append(f"{name['label']} {name['oid']} = {name['value']}")
    return "\n".join(lines) or "none"


def _name_value(name: x509.Name, oid: ObjectIdentifier) -> str:
    values = name.get_attributes_for_oid(oid)
    if not values:
        return ""
    return values[0].value


def _pem_bytes(pem: str) -> bytes:
    return pem.encode("utf-8")


def _pem_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if isinstance(value, str):
        return [value]
    return []


def _split_pems(pem: str) -> list[str]:
    blocks = []
    current: list[str] = []
    for line in pem.splitlines(keepends=True):
        current.append(line)
        if "END CERTIFICATE" in line:
            blocks.append("".join(current))
            current = []
    return blocks


def _field(label: str, value: str, mono: bool = False) -> dict:
    return {"label": label, "value": value, "mono": mono}


def _check(check_id: str, label: str, passed: bool, detail: str) -> dict:
    return {"id": check_id, "label": label, "passed": passed, "detail": detail}


def missing_certificate(heading: str, message: str) -> dict:
    return {
        "present": False,
        "heading": heading,
        "summary": "",
        "checks": [],
        "fields": [],
        "chain": [],
        "ca_path": None,
        "message": message,
    }


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
