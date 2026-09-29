provider "vault" {
  # Address and token come from VAULT_ADDR and VAULT_TOKEN.
  namespace = var.vault_namespace
}
