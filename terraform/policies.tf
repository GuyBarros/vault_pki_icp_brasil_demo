resource "vault_policy" "demo_app" {
  name   = local.policy_name
  policy = <<EOT
path "${local.tls_int_path}/issue/${local.tls_role_name}" {
  capabilities = ["create", "update"]
}

path "${local.icp_int_path}/issue/${local.icp_role_name}" {
  capabilities = ["create", "update"]
}

path "${local.database_path}/creds/${local.database_role}" {
  capabilities = ["read"]
}

path "sys/leases/renew" {
  capabilities = ["update"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}
EOT
}
