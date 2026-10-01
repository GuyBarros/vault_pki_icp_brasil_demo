resource "vault_policy" "demo_app" {
  name   = local.policy_name
  policy = <<EOT
path "${local.tls_int_path}/issue/${local.tls_role_name}" {
  capabilities = ["create", "update"]
}

path "${local.kv_path}/data/${local.icp_secret_name}" {
  capabilities = ["read"]
}

path "${local.kv_path}/metadata/${local.icp_secret_name}" {
  capabilities = ["read"]
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

resource "vault_policy" "icp_metadata_reader" {
  name   = local.icp_metadata_policy_name
  policy = <<EOT
path "${local.kv_path}/metadata/" {
  capabilities = ["list"]
}

path "${local.kv_path}/metadata/${local.icp_secret_name}" {
  capabilities = ["read"]
}
EOT
}
