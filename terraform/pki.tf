resource "vault_mount" "tls_root" {
  path                      = local.tls_root_path
  type                      = "pki"
  description               = "Laboratory root CA for service TLS. Not an ICP-Brasil authority."
  default_lease_ttl_seconds = var.tls_certificate_ttl_seconds
  max_lease_ttl_seconds     = local.root_ttl_seconds
}

resource "vault_pki_secret_backend_root_cert" "tls" {
  backend              = vault_mount.tls_root.path
  type                 = "internal"
  common_name          = "Vault Demo Root CA"
  ttl                  = local.root_ttl
  format               = "pem"
  private_key_format   = "pkcs8"
  key_type             = "rsa"
  key_bits             = 4096
  country              = "BR"
  organization         = "Vault Demo"
  ou                   = "Laboratory"
  exclude_cn_from_sans = true
  issuer_name          = "root"
}

resource "vault_mount" "tls_int" {
  path                      = local.tls_int_path
  type                      = "pki"
  description               = "Laboratory intermediate CA for service TLS."
  default_lease_ttl_seconds = var.tls_certificate_ttl_seconds
  max_lease_ttl_seconds     = local.intermediate_ttl_seconds
}

resource "vault_pki_secret_backend_intermediate_cert_request" "tls" {
  backend      = vault_mount.tls_int.path
  type         = "internal"
  common_name  = "Vault Demo Intermediate CA"
  key_type     = "rsa"
  key_bits     = 4096
  country      = "BR"
  organization = "Vault Demo"
  ou           = "Laboratory"
}

resource "vault_pki_secret_backend_root_sign_intermediate" "tls" {
  backend              = vault_mount.tls_root.path
  csr                  = vault_pki_secret_backend_intermediate_cert_request.tls.csr
  common_name          = "Vault Demo Intermediate CA"
  ttl                  = local.intermediate_ttl
  format               = "pem"
  country              = "BR"
  organization         = "Vault Demo"
  ou                   = "Laboratory"
  exclude_cn_from_sans = true
}

resource "vault_pki_secret_backend_intermediate_set_signed" "tls" {
  backend = vault_mount.tls_int.path
  certificate = join("\n", [
    vault_pki_secret_backend_root_sign_intermediate.tls.certificate,
    vault_pki_secret_backend_root_cert.tls.certificate,
  ])
}

resource "vault_pki_secret_backend_config_urls" "tls" {
  backend = vault_mount.tls_int.path
  issuing_certificates = [
    "${var.vault_address}/v1/${local.tls_int_path}/ca",
  ]
  crl_distribution_points = [
    "${var.vault_address}/v1/${local.tls_int_path}/crl",
  ]

  depends_on = [vault_pki_secret_backend_intermediate_set_signed.tls]
}

resource "vault_pki_secret_backend_role" "demo_server" {
  backend                            = vault_mount.tls_int.path
  name                               = local.tls_role_name
  ttl                                = var.tls_certificate_ttl_seconds
  max_ttl                            = 2592000
  allow_localhost                    = true
  allow_any_name                     = false
  allow_bare_domains                 = true
  allow_subdomains                   = true
  allow_ip_sans                      = true
  allowed_domains                    = var.tls_allowed_domains
  server_flag                        = true
  client_flag                        = false
  key_type                           = "rsa"
  key_bits                           = 2048
  signature_bits                     = 256
  key_usage                          = ["DigitalSignature", "KeyEncipherment"]
  ext_key_usage                      = ["ServerAuth"]
  organization                       = ["Vault Demo"]
  country                            = ["BR"]
  generate_lease                     = true
  not_before_duration                = "30s"
  basic_constraints_valid_for_non_ca = true

  depends_on = [vault_pki_secret_backend_intermediate_set_signed.tls]
}
