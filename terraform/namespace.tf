resource "vault_namespace" "demo" {
  provider = vault.admin
  path     = var.vault_namespace
}
