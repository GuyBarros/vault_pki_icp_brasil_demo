#!/usr/bin/env python3
"""Write the laboratory ICP-Brasil files that Terraform loads into KV.

The intermediate and root private keys are used only to sign, then discarded.
KV receives the leaf certificate, the leaf public key, the leaf private key,
the issuing CA certificate, and the root certificate.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

OUT = Path(__file__).resolve().parent
NOTICE = "Laboratory stand-in. Not an accredited ICP-Brasil certificate.\n"


def _name(*pairs: tuple[NameOID, str]) -> x509.Name:
    return x509.Name([x509.NameAttribute(oid, value) for oid, value in pairs])


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _sign(builder: x509.CertificateBuilder, key: rsa.RSAPrivateKey) -> x509.Certificate:
    return builder.sign(key, hashes.SHA256())


def _pem_cert(certificate: x509.Certificate) -> str:
    body = certificate.public_bytes(serialization.Encoding.PEM).decode()
    return NOTICE + body


def _pem_private(key: rsa.RSAPrivateKey) -> str:
    body = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return NOTICE + body


def _pem_public(key: rsa.RSAPrivateKey) -> str:
    body = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return NOTICE + body


def main() -> None:
    now = datetime.now(timezone.utc)
    root_key = _key()
    root_name = _name(
        (NameOID.COUNTRY_NAME, "BR"),
        (NameOID.ORGANIZATION_NAME, "AC Demonstracao Vault"),
        (NameOID.ORGANIZATIONAL_UNIT_NAME, "Laboratorio ICP-Brasil"),
        (NameOID.COMMON_NAME, "AC Raiz Demonstracao Vault"),
    )
    root = _sign(
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ),
        root_key,
    )

    issuer_key = _key()
    issuer_name = _name(
        (NameOID.COUNTRY_NAME, "BR"),
        (NameOID.ORGANIZATION_NAME, "AC Demonstracao Vault"),
        (NameOID.ORGANIZATIONAL_UNIT_NAME, "Perfil A1"),
        (NameOID.COMMON_NAME, "AC Demonstracao Vault"),
    )
    issuer = _sign(
        x509.CertificateBuilder()
        .subject_name(issuer_name)
        .issuer_name(root_name)
        .public_key(issuer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ),
        root_key,
    )

    leaf_key = _key()
    leaf_name = _name(
        (NameOID.COUNTRY_NAME, "BR"),
        (NameOID.ORGANIZATION_NAME, "ICP-Brasil"),
        (NameOID.ORGANIZATIONAL_UNIT_NAME, "AC Demonstracao Vault"),
        (NameOID.COMMON_NAME, "MARIA OLIVEIRA DEMO"),
    )
    leaf = _sign(
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(issuer_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(hours=1))
        .not_valid_after(now + timedelta(days=300))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.EMAIL_PROTECTION]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.CertificatePolicies(
                [
                    x509.PolicyInformation(
                        ObjectIdentifier("2.16.76.1.2.1.99999"),
                        [
                            x509.UserNotice(
                                None,
                                "Politica de Certificado de Assinatura Digital tipo A1 da AC Demonstracao Vault. Laboratorio, sem credenciamento na ICP-Brasil.",
                            ),
                            "http://demo.vault.local/dpc",
                        ],
                    )
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.RFC822Name("maria.oliveira@demo.vault.local"),
                    x509.OtherName(ObjectIdentifier("2.16.76.1.3.1"), b"\x0c\x0b11144477735"),
                ]
            ),
            critical=False,
        ),
        issuer_key,
    )

    (OUT / "certificate.pem").write_text(_pem_cert(leaf), encoding="utf-8")
    (OUT / "private_key.pem").write_text(_pem_private(leaf_key), encoding="utf-8")
    (OUT / "public_key.pem").write_text(_pem_public(leaf_key), encoding="utf-8")
    (OUT / "issuing_ca.pem").write_text(_pem_cert(issuer), encoding="utf-8")
    (OUT / "ca_chain.pem").write_text(_pem_cert(root), encoding="utf-8")


if __name__ == "__main__":
    main()
