# The application task uses Nomad's Vault integration. The template stanzas are
# the same renderer Vault Agent uses. The Nomad client needs a vault stanza,
# and its token must be allowed to create a child token with the demo-app policy.
# On a cluster that only accepts workload identity, replace the vault block
# with `role = "demo-app"` and bind that role to the job's identity.

variable "image" {
  type    = string
  default = "vault-pki-icp-brasil-demo:local"
}

job "vault-pki-demo" {
  datacenters = ["dc1"]
  type        = "service"

  group "app" {
    network {
      mode = "host"

      port "http" {
        static = 8080
      }

      port "https" {
        static = 8443
      }
    }

    vault {
      policies  = ["demo-app"]
      namespace = "demo"
    }

    task "demo" {
      driver = "docker"

      config {
        image        = var.image
        network_mode = "host"
        ports        = ["http", "https"]
      }

      env {
        SECRETS_DIR    = "${NOMAD_SECRETS_DIR}"
        SECRETS_SOURCE = "nomad"
        POSTGRES_HOST  = "127.0.0.1"
        POSTGRES_PORT  = "5432"
        POSTGRES_DB    = "demo"
        PORT           = "${NOMAD_PORT_http}"
        TLS_PORT       = "${NOMAD_PORT_https}"
      }

      template {
        destination = "secrets/db.json"
        change_mode = "noop"
        perms       = "0644"
        data        = <<-EOT
          {{- with secret "database/creds/demo-app" -}}
          {
            "username": {{ .Data.username | toJSON }},
            "password": {{ .Data.password | toJSON }},
            "lease_id": {{ .LeaseID | toJSON }},
            "lease_duration": {{ .LeaseDuration }}
          }
          {{- end -}}
        EOT
      }

      template {
        destination = "secrets/tls.json"
        change_mode = "noop"
        perms       = "0644"
        data        = <<-EOT
          {{- with secret "pki_int/issue/demo-server" "common_name=demo.vault.local" "alt_names=localhost" "ip_sans=127.0.0.1" "ttl=1m" -}}
          {
            "certificate": {{ .Data.certificate | toJSON }},
            "private_key": {{ .Data.private_key | toJSON }},
            "issuing_ca": {{ .Data.issuing_ca | toJSON }},
            "ca_chain": {{ if .Data.ca_chain }}{{ .Data.ca_chain | toJSON }}{{ else }}null{{ end }},
            "serial_number": {{ .Data.serial_number | toJSON }},
            "expiration": {{ .Data.expiration }}
          }
          {{- end -}}
        EOT
      }

      template {
        destination = "secrets/icp.json"
        change_mode = "noop"
        perms       = "0644"
        data        = <<-EOT
          {{- with secret "kv/data/icp-brasil" -}}
          {
            "certificate": {{ .Data.data.certificate | toJSON }},
            "private_key": {{ .Data.data.private_key | toJSON }},
            "public_key": {{ .Data.data.public_key | toJSON }},
            "issuing_ca": {{ .Data.data.issuing_ca | toJSON }},
            "ca_chain": {{ .Data.data.ca_chain | toJSON }}
          }
          {{- end -}}
        EOT
      }

      resources {
        cpu    = 200
        memory = 128
      }
    }
  }
}
