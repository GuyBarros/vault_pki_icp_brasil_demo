# Laboratory PostgreSQL for the Nomad demo.
# The password default matches deploy/podman/lab.env and the Terraform default.
# Run this job, then apply Terraform with postgres_host set to an address Vault can reach.

variable "postgres_password" {
  type    = string
  default = "vault-lab-password"
}

job "vault-pki-demo-db" {
  datacenters = ["dc1"]
  type        = "service"

  group "postgres" {
    network {
      mode = "host"

      port "db" {
        static = 5432
      }
    }

    task "postgres" {
      driver = "docker"

      config {
        image        = "docker.io/library/postgres:16-alpine"
        network_mode = "host"
        ports        = ["db"]

        mount {
          type     = "bind"
          target   = "/docker-entrypoint-initdb.d/01-registros.sql"
          source   = "local/init.sql"
          readonly = true
        }
      }

      env {
        POSTGRES_USER     = "vault"
        POSTGRES_PASSWORD = var.postgres_password
        POSTGRES_DB       = "demo"
      }

      # Same rows as deploy/postgres/init.sql.
      template {
        destination = "local/init.sql"
        change_mode = "noop"
        data        = <<-EOT
          CREATE TABLE IF NOT EXISTS registros (
              id integer PRIMARY KEY,
              titulo text NOT NULL,
              detalhe text NOT NULL
          );

          INSERT INTO registros (id, titulo, detalhe) VALUES
              (1, 'A1 profile', 'Signature certificate shaped like ICP-Brasil A1.'),
              (2, 'Service TLS', 'Short-lived certificate from the PKI secrets engine.'),
              (3, 'Dynamic credential', 'Read with a PostgreSQL role that Vault created for this lease.')
          ON CONFLICT (id) DO NOTHING;
        EOT
      }

      resources {
        cpu    = 200
        memory = 256
      }
    }
  }
}
