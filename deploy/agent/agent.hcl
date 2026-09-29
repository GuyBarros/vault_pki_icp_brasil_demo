pid_file = "/tmp/vault-agent.pid"

vault {
  address = "http://vault:8200"
}

auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path                   = "/vault/approle/role_id"
      secret_id_file_path                 = "/vault/approle/secret_id"
      remove_secret_id_file_after_reading = false
    }
  }

  sink "file" {
    config = {
      path = "/tmp/vault-token"
      mode = 0640
    }
  }
}

template_config {
  exit_on_retry_failure         = false
  static_secret_render_interval = "5m"
}

template {
  source      = "/vault/config/templates/db.json.tpl"
  destination = "/vault/secrets/db.json"
  perms       = "0644"

  wait {
    min = "2s"
    max = "10s"
  }
}

template {
  source      = "/vault/config/templates/tls.json.tpl"
  destination = "/vault/secrets/tls.json"
  perms       = "0644"
}

template {
  source      = "/vault/config/templates/icp.json.tpl"
  destination = "/vault/secrets/icp.json"
  perms       = "0644"
}
