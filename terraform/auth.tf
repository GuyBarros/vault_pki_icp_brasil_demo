resource "vault_auth_backend" "approle" {
  type        = "approle"
  path        = local.approle_auth_path
  description = "AppRole for Vault Agent on Podman and for other clients that present a role id and secret id."
}

resource "vault_approle_auth_backend_role" "demo_app" {
  backend        = vault_auth_backend.approle.path
  role_name      = local.approle_name
  token_policies = [vault_policy.demo_app.name]
  token_ttl      = 3600
  token_max_ttl  = 14400
}

resource "vault_approle_auth_backend_role_secret_id" "demo_app" {
  backend   = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.demo_app.role_name
}

resource "vault_auth_backend" "kubernetes" {
  count = var.enable_kubernetes_auth ? 1 : 0

  type        = "kubernetes"
  path        = local.kubernetes_path
  description = "Kubernetes auth for the Vault Secrets Operator."
}

resource "vault_kubernetes_auth_backend_config" "demo" {
  count = var.enable_kubernetes_auth ? 1 : 0

  backend                = vault_auth_backend.kubernetes[0].path
  kubernetes_host        = var.kubernetes_host
  kubernetes_ca_cert     = var.kubernetes_ca_cert
  token_reviewer_jwt     = var.kubernetes_token_reviewer_jwt
  disable_iss_validation = var.kubernetes_disable_iss_validation

  lifecycle {
    precondition {
      condition     = var.kubernetes_host != null && var.kubernetes_ca_cert != null && var.kubernetes_token_reviewer_jwt != null
      error_message = "kubernetes_host, kubernetes_ca_cert, and kubernetes_token_reviewer_jwt are required when enable_kubernetes_auth is true."
    }
  }
}

resource "vault_kubernetes_auth_backend_role" "demo_app" {
  count = var.enable_kubernetes_auth ? 1 : 0

  backend                          = vault_auth_backend.kubernetes[0].path
  role_name                        = local.kubernetes_role
  bound_service_account_names      = ["demo-app"]
  bound_service_account_namespaces = ["vault-demo"]
  audience                         = "vault"
  token_policies                   = [vault_policy.demo_app.name]
  token_ttl                        = 3600
}
