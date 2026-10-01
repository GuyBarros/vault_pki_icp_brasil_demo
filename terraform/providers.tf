# The admin provider creates the namespace. Address, token, and TLS verification
# come from VAULT_ADDR, VAULT_TOKEN, and VAULT_SKIP_VERIFY. VAULT_NAMESPACE, when
# set, is the parent of the namespace this configuration creates.
provider "vault" {
  alias = "admin"
}

# Every other resource uses this provider and is configured inside the new namespace.
provider "vault" {
  namespace = trimsuffix(vault_namespace.demo.path_fq, "/")
}
