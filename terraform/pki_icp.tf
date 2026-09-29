# Laboratory PKI that follows the shape of an ICP-Brasil type A1 signature
# certificate (DOC-ICP-04): RSA 2048, SHA-256, digitalSignature and
# contentCommitment, clientAuth and emailProtection, C=BR, and a policy OID
# in the 2.16.76.1.2.1 arc.
#
# This is not an accredited authority. The common names say "Demonstracao"
# on purpose, and the policy id 99999 is not an ITI assignment. A1 is the
# software profile: Vault returns the private key in the issue response.
# A3 and A4 keys live on a cryptographic device, which this engine does not model.

resource "vault_mount" "icp_root" {
  path                      = local.icp_root_path
  type                      = "pki"
  description               = "Laboratory root for the ICP-Brasil A1 profile. Not AC Raiz da ICP-Brasil."
  default_lease_ttl_seconds = var.icp_certificate_ttl_seconds
  max_lease_ttl_seconds     = local.root_ttl_seconds
}

resource "vault_pki_secret_backend_root_cert" "icp" {
  backend              = vault_mount.icp_root.path
  type                 = "internal"
  common_name          = "AC Raiz Demonstracao Vault"
  ttl                  = local.root_ttl
  format               = "pem"
  private_key_format   = "pkcs8"
  key_type             = "rsa"
  key_bits             = 4096
  country              = "BR"
  organization         = "AC Demonstracao Vault"
  ou                   = "Laboratorio ICP-Brasil"
  exclude_cn_from_sans = true
  issuer_name          = "root"
}

resource "vault_mount" "icp_int" {
  path                      = local.icp_int_path
  type                      = "pki"
  description               = "Laboratory intermediate that issues A1-profile certificates. Not accredited by ITI."
  default_lease_ttl_seconds = var.icp_certificate_ttl_seconds
  max_lease_ttl_seconds     = local.intermediate_ttl_seconds
}

resource "vault_pki_secret_backend_intermediate_cert_request" "icp" {
  backend      = vault_mount.icp_int.path
  type         = "internal"
  common_name  = "AC Demonstracao Vault"
  key_type     = "rsa"
  key_bits     = 4096
  country      = "BR"
  organization = "AC Demonstracao Vault"
  ou           = "Perfil A1"
}

resource "vault_pki_secret_backend_root_sign_intermediate" "icp" {
  backend              = vault_mount.icp_root.path
  csr                  = vault_pki_secret_backend_intermediate_cert_request.icp.csr
  common_name          = "AC Demonstracao Vault"
  ttl                  = local.intermediate_ttl
  format               = "pem"
  country              = "BR"
  organization         = "AC Demonstracao Vault"
  ou                   = "Perfil A1"
  exclude_cn_from_sans = true
}

resource "vault_pki_secret_backend_intermediate_set_signed" "icp" {
  backend = vault_mount.icp_int.path
  certificate = join("\n", [
    vault_pki_secret_backend_root_sign_intermediate.icp.certificate,
    vault_pki_secret_backend_root_cert.icp.certificate,
  ])
}

resource "vault_pki_secret_backend_config_urls" "icp" {
  backend = vault_mount.icp_int.path
  issuing_certificates = [
    "${var.vault_address}/v1/${local.icp_int_path}/ca",
  ]
  crl_distribution_points = [
    "${var.vault_address}/v1/${local.icp_int_path}/crl",
  ]

  depends_on = [vault_pki_secret_backend_intermediate_set_signed.icp]
}

resource "vault_pki_secret_backend_role" "a1_pessoa_fisica" {
  backend               = vault_mount.icp_int.path
  name                  = local.icp_role_name
  ttl                   = var.icp_certificate_ttl_seconds
  max_ttl               = 31536000
  allow_any_name        = true
  enforce_hostnames     = false
  allow_ip_sans         = false
  allow_localhost       = false
  require_cn            = true
  cn_validations        = ["disabled"]
  server_flag           = false
  client_flag           = true
  code_signing_flag     = false
  email_protection_flag = true
  key_type              = "rsa"
  key_bits              = 2048
  signature_bits        = 256
  use_pss               = false
  key_usage             = ["DigitalSignature", "ContentCommitment"]
  ext_key_usage         = ["ClientAuth", "EmailProtection"]
  country               = ["BR"]
  organization          = ["ICP-Brasil"]
  ou                    = ["AC Demonstracao Vault", "Assinatura Tipo A1"]
  allowed_other_sans = [
    "2.16.76.1.3.1;utf8:*",
    "2.16.76.1.3.3;utf8:*",
    "2.16.76.1.3.4;utf8:*",
  ]
  generate_lease                     = true
  not_before_duration                = "30s"
  basic_constraints_valid_for_non_ca = true

  policy_identifier {
    oid    = var.icp_policy_oid
    cps    = var.icp_cps_url
    notice = var.icp_policy_notice
  }

  depends_on = [vault_pki_secret_backend_intermediate_set_signed.icp]
}
