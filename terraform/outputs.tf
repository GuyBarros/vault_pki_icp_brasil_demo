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

output "icp_issue_path" {
  description = "Vault path that issues an A1-profile certificate."
  value       = "${local.icp_int_path}/issue/${local.icp_role_name}"
}

output "icp_root_certificate" {
  description = "PEM of the laboratory ICP-Brasil-profile root. This is not AC Raiz da ICP-Brasil."
  value       = vault_pki_secret_backend_root_cert.icp.certificate
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
