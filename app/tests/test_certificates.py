import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from demo_app.certificates import policy_type, summarize_certificate

LAB_ICP = Path(__file__).resolve().parents[2] / "deploy" / "icp"


def _certificate(builder):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    certificate = (
        builder.public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=72))
        .sign(key, hashes.SHA256())
    )
    pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return pem, public_pem


def _name(*attributes):
    return x509.Name(list(attributes))


class CertificateProfileTests(unittest.TestCase):
    def test_policy_type_reads_the_a1_arc(self):
        self.assertEqual(policy_type("2.16.76.1.2.1.99999"), "A1")
        self.assertEqual(policy_type("2.16.76.1.2.3.12"), "A3")
        self.assertEqual(policy_type("2.16.76.1.2.101.4"), "S1")
        self.assertEqual(policy_type("1.2.3.4"), "")

    def test_a1_profile_passes_and_decodes_the_cpf(self):
        subject = _name(
            x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ICP-Brasil"),
            x509.NameAttribute(NameOID.COMMON_NAME, "MARIA OLIVEIRA DEMO"),
        )
        issuer = _name(x509.NameAttribute(NameOID.COMMON_NAME, "AC Demonstracao Vault"))
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
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
                            [x509.UserNotice(None, "laboratorio"), "http://demo.vault.local/dpc"],
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
            )
        )
        pem, public_pem = _certificate(builder)
        view = summarize_certificate(
            pem,
            profile="icp-a1",
            private_key_present=True,
            issuing_ca_pem=None,
            ca_chain=None,
            rendered_at="2026-09-29T00:00:00+00:00",
            ca_path="/ca/icp",
            public_key_pem=public_pem,
        )

        self.assertTrue(all(check["passed"] for check in view["checks"]), view["checks"])
        sans = next(field["value"] for field in view["fields"] if field["label"] == "Subject alternative names")
        self.assertIn("11144477735", sans)
        self.assertIn("2.16.76.1.2.1.99999 (A1)", next(
            field["value"] for field in view["fields"] if field["label"] == "Policies"
        ))
        encoded = json.dumps(view)
        self.assertNotIn("BEGIN PRIVATE", encoded)

    def test_server_certificate_is_not_an_a1_profile(self):
        subject = _name(x509.NameAttribute(NameOID.COMMON_NAME, "demo.vault.local"))
        issuer = _name(x509.NameAttribute(NameOID.COMMON_NAME, "Vault Demo Intermediate CA"))
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("demo.vault.local"), x509.DNSName("localhost")]),
                critical=False,
            )
        )
        pem, public_pem = _certificate(builder)
        tls_view = summarize_certificate(
            pem,
            profile="tls-server",
            private_key_present=True,
            issuing_ca_pem=None,
            ca_chain=None,
            rendered_at="2026-09-29T00:00:00+00:00",
            ca_path="/ca/tls",
        )
        icp_view = summarize_certificate(
            pem,
            profile="icp-a1",
            private_key_present=True,
            issuing_ca_pem=None,
            ca_chain=None,
            rendered_at="2026-09-29T00:00:00+00:00",
            ca_path="/ca/icp",
        )
        self.assertTrue(all(check["passed"] for check in tls_view["checks"]), tls_view["checks"])
        failed = [check["id"] for check in icp_view["checks"] if not check["passed"]]
        self.assertIn("policy", failed)
        self.assertIn("cpf", failed)
        self.assertIn("country", failed)
        self.assertIn("public-key", failed)

    def test_stored_public_key_must_match_the_certificate(self):
        subject = _name(x509.NameAttribute(NameOID.COMMON_NAME, "MARIA OLIVEIRA DEMO"))
        builder = x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        pem, public_pem = _certificate(builder)
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_pem = other.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        matched = summarize_certificate(
            pem,
            profile="icp-a1",
            private_key_present=True,
            issuing_ca_pem=None,
            ca_chain=None,
            rendered_at="2026-09-29T00:00:00+00:00",
            ca_path="/ca/icp",
            public_key_pem=public_pem,
        )
        mismatched = summarize_certificate(
            pem,
            profile="icp-a1",
            private_key_present=True,
            issuing_ca_pem=None,
            ca_chain=None,
            rendered_at="2026-09-29T00:00:00+00:00",
            ca_path="/ca/icp",
            public_key_pem=other_pem,
        )
        self.assertTrue(next(check["passed"] for check in matched["checks"] if check["id"] == "public-key"))
        self.assertFalse(next(check["passed"] for check in mismatched["checks"] if check["id"] == "public-key"))

    def test_laboratory_files_pass_the_a1_profile(self):
        view = summarize_certificate(
            (LAB_ICP / "certificate.pem").read_text(encoding="utf-8"),
            profile="icp-a1",
            private_key_present=True,
            issuing_ca_pem=(LAB_ICP / "issuing_ca.pem").read_text(encoding="utf-8"),
            ca_chain=(LAB_ICP / "ca_chain.pem").read_text(encoding="utf-8"),
            rendered_at="2026-09-29T00:00:00+00:00",
            ca_path="/ca/icp",
            public_key_pem=(LAB_ICP / "public_key.pem").read_text(encoding="utf-8"),
        )
        self.assertTrue(all(check["passed"] for check in view["checks"]), view["checks"])
        self.assertEqual(len(view["chain"]), 3)
        self.assertIn("11144477735", next(
            field["value"] for field in view["fields"] if field["label"] == "Subject alternative names"
        ))


if __name__ == "__main__":
    unittest.main()
