import json
import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from demo_app.certificates import policy_type, summarize_certificate


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
    return pem


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
        view = summarize_certificate(
            _certificate(builder),
            profile="icp-a1",
            private_key_present=True,
            issuing_ca_pem=None,
            ca_chain=None,
            rendered_at="2026-09-29T00:00:00+00:00",
            ca_path="/ca/icp",
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
        pem = _certificate(builder)
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


if __name__ == "__main__":
    unittest.main()
