resource "vault_mount" "database" {
  path        = local.database_path
  type        = "database"
  description = "Dynamic PostgreSQL credentials for the demo application."
}

resource "vault_database_secret_backend_connection" "postgres" {
  backend       = vault_mount.database.path
  name          = "postgres"
  allowed_roles = [local.database_role]

  postgresql {
    connection_url       = "postgresql://{{username}}:{{password}}@${var.postgres_host}:${var.postgres_port}/${var.postgres_database}?sslmode=disable"
    username             = var.postgres_admin_username
    password             = var.postgres_admin_password
    username_template    = "v-{{.RoleName}}-{{unix_time}}-{{random 4}}"
    max_open_connections = 4
  }

  verify_connection = true
}

# Destroyed before the database connection. Vault cannot disable the database
# mount while credential leases still name a connection that has been removed.
resource "terraform_data" "database_lease_cleanup" {
  input = local.namespace_path

  depends_on = [vault_database_secret_backend_connection.postgres]

  provisioner "local-exec" {
    when    = destroy
    command = "vault lease revoke -force -prefix database/creds"

    environment = {
      VAULT_NAMESPACE = self.output
    }
  }
}

resource "vault_database_secret_backend_role" "demo_app" {
  backend     = vault_mount.database.path
  name        = local.database_role
  db_name     = vault_database_secret_backend_connection.postgres.name
  default_ttl = var.database_default_ttl_seconds
  max_ttl     = var.database_max_ttl_seconds

  creation_statements = [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
    "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";",
  ]

  revocation_statements = [
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{{name}}';",
    "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"{{name}}\";",
    "DROP ROLE IF EXISTS \"{{name}}\";",
  ]

  lifecycle {
    precondition {
      condition     = var.database_default_ttl_seconds <= var.database_max_ttl_seconds
      error_message = "database_default_ttl_seconds must be less than or equal to database_max_ttl_seconds."
    }
  }
}
