output "approle_role_id" {
  description = "AppRole role id for Vault Agent."
  value       = vault_approle_auth_backend_role.demo_app.role_id
}

output "approle_secret_id" {
  description = "AppRole secret id for Vault Agent. Written to deploy/podman/secrets by scripts/write-approle-files.sh."
  value       = vault_approle_auth_backend_role_secret_id.demo_app.secret_id
  sensitive   = true
}

output "database_credentials_path" {
  description = "Vault path that issues a dynamic PostgreSQL credential."
  value       = "${local.database_path}/creds/${local.database_role}"
}

output "icp_metadata_path" {
  description = "KV v2 metadata path for the ICP-Brasil certificate. The icp-metadata-reader policy can read this path and cannot read the secret data."
  value       = "${local.kv_path}/metadata/${local.icp_secret_name}"
}

output "icp_metadata_policy" {
  description = "Policy that can list KV metadata and read the ICP-Brasil certificate metadata, including expiry, and cannot read the private key."
  value       = vault_policy.icp_metadata_reader.name
}

output "icp_secret_path" {
  description = "KV v2 path of the stored ICP-Brasil certificate, public key, private key, and issuing CA."
  value       = "${local.kv_path}/data/${local.icp_secret_name}"
}

output "kubernetes_auth_path" {
  description = "Kubernetes auth mount path, or null when that auth method is disabled."
  value       = var.enable_kubernetes_auth ? local.kubernetes_path : null
}

output "tls_issue_path" {
  description = "Vault path that issues a service certificate."
  value       = "${local.tls_int_path}/issue/${local.tls_role_name}"
}

output "tls_root_certificate" {
  description = "PEM of the laboratory service-TLS root CA."
  value       = vault_pki_secret_backend_root_cert.tls.certificate
}

output "vault_namespace" {
  description = "Fully qualified Vault namespace that holds the laboratory mounts, policies, and auth methods."
  value       = local.namespace_path
}
