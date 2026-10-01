#!/usr/bin/env bash
# Start the local laboratory: PostgreSQL, Terraform, Vault Agent, and the UI.
# When VAULT_ADDR and VAULT_TOKEN are set, Terraform and Vault Agent use that
# Vault and this script does not start one. VAULT_SKIP_VERIFY=true skips TLS
# verification for curl, Terraform, and Vault Agent.
# When those variables are unset, the script starts a dev-mode Vault on
# http://127.0.0.1:8200 with the token from deploy/podman/lab.env.

set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
compose_file="$root/deploy/podman/compose.yaml"
secrets_dir="$root/deploy/podman/secrets"

if podman compose version >/dev/null 2>&1; then
  compose=(podman compose)
  agent_host="host.containers.internal"
elif docker compose version >/dev/null 2>&1; then
  compose=(docker compose)
  agent_host="host.docker.internal"
else
  echo "podman compose or docker compose is required." >&2
  exit 1
fi

for tool in curl terraform python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool is required." >&2
    exit 1
  fi
done

set -a
# shellcheck disable=SC1091
source "$root/deploy/podman/lab.env"
set +a

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-vault-pki-demo}"
compose_cmd=("${compose[@]}" --project-name "$COMPOSE_PROJECT_NAME" -f "$compose_file")

if [[ -n "${VAULT_ADDR:-}" || -n "${VAULT_TOKEN:-}" ]]; then
  if [[ -z "${VAULT_ADDR:-}" || -z "${VAULT_TOKEN:-}" ]]; then
    echo "Set both VAULT_ADDR and VAULT_TOKEN, or neither to start the local dev Vault." >&2
    exit 1
  fi
  external_vault=1
else
  external_vault=0
  export VAULT_ADDR="http://127.0.0.1:8200"
  export VAULT_TOKEN="$VAULT_DEV_ROOT_TOKEN_ID"
fi

export VAULT_SKIP_VERIFY="${VAULT_SKIP_VERIFY:-false}"
export TF_VAR_postgres_admin_username="$POSTGRES_USER"
export TF_VAR_postgres_admin_password="$POSTGRES_PASSWORD"
export TF_VAR_postgres_database="$POSTGRES_DB"
export TF_VAR_vault_address="${TF_VAR_vault_address:-$VAULT_ADDR}"

# The Compose name postgres resolves only on the lab network. A Vault reached
# through localhost is on this machine, so it uses the published port instead.
if [[ "$external_vault" -eq 1 && -z "${TF_VAR_postgres_host:-}" ]]; then
  vault_db_host="$(python3 - "$VAULT_ADDR" <<'PY'
import sys
from urllib.parse import urlparse

host = urlparse(sys.argv[1]).hostname or ""
print("127.0.0.1" if host in {"127.0.0.1", "localhost", "::1"} else "")
PY
)"
  if [[ -z "$vault_db_host" ]]; then
    echo "Set TF_VAR_postgres_host to a PostgreSQL address that ${VAULT_ADDR} can open." >&2
    exit 1
  fi
  export TF_VAR_postgres_host="$vault_db_host"
else
  export TF_VAR_postgres_host="${TF_VAR_postgres_host:-postgres}"
fi

curl_vault=(curl -sf)
case "$VAULT_SKIP_VERIFY" in
  true|TRUE|1) curl_vault=(curl -sfk) ;;
esac

agent_vault_addr="$(python3 - "$VAULT_ADDR" "$agent_host" <<'PY'
import sys
from urllib.parse import urlparse, urlunparse

url, alias = sys.argv[1], sys.argv[2]
parts = urlparse(url)
if parts.hostname in {"127.0.0.1", "localhost", "::1"}:
    netloc = alias
    if parts.port:
        netloc = f"{alias}:{parts.port}"
    parts = parts._replace(netloc=netloc)
print(urlunparse(parts))
PY
)"

write_agent_vault_config() {
  local skip="false"
  case "$VAULT_SKIP_VERIFY" in
    true|TRUE|1) skip="true" ;;
  esac
  lab_namespace="$(terraform -chdir="$root/terraform" output -raw vault_namespace)"
  mkdir -p "$secrets_dir"
  cat >"$secrets_dir/agent-vault.hcl" <<EOF
vault {
  address         = "${agent_vault_addr}"
  tls_skip_verify = ${skip}
  namespace       = "${lab_namespace}"
}
EOF
}

if [[ "$external_vault" -eq 1 ]]; then
  echo "Using Vault at ${VAULT_ADDR}."
  echo "Starting PostgreSQL. Vault must reach it at ${TF_VAR_postgres_host}:${TF_VAR_postgres_port:-5432}."
  "${compose_cmd[@]}" up -d postgres
else
  echo "VAULT_ADDR is unset. Starting the lab Vault and PostgreSQL."
  agent_vault_addr="http://vault:8200"
  "${compose_cmd[@]}" --profile local-vault up -d vault postgres

  echo "Waiting for Vault inside the lab container."
  ready=0
  for _ in $(seq 1 40); do
    if "${compose_cmd[@]}" exec -T vault vault status -address=http://127.0.0.1:8200 >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 2
  done
  if [[ "$ready" -ne 1 ]]; then
    echo "The lab Vault did not become ready." >&2
    exit 1
  fi
fi

accessor_of() {
  python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["accessor"])'
}

token_headers=(-H "X-Vault-Token: $VAULT_TOKEN")
if [[ -n "${VAULT_NAMESPACE:-}" ]]; then
  token_headers+=(-H "X-Vault-Namespace: ${VAULT_NAMESPACE}")
fi

echo "Checking the token at ${VAULT_ADDR}."
ready=0
for _ in $(seq 1 15); do
  if host_lookup="$("${curl_vault[@]}" "${token_headers[@]}" "$VAULT_ADDR/v1/auth/token/lookup-self")"; then
    ready=1
    break
  fi
  sleep 2
done
if [[ "$ready" -ne 1 ]]; then
  echo "Could not call ${VAULT_ADDR} with VAULT_TOKEN." >&2
  exit 1
fi

if [[ "$external_vault" -eq 0 ]]; then
  host_accessor="$(accessor_of <<<"$host_lookup")"
  container_accessor="$("${compose_cmd[@]}" exec -T \
    -e VAULT_ADDR=http://127.0.0.1:8200 \
    -e VAULT_TOKEN="$VAULT_TOKEN" \
    vault vault token lookup -format=json | accessor_of)"

  if [[ "$host_accessor" != "$container_accessor" ]]; then
    echo "http://127.0.0.1:8200 is not the lab Vault this script just started. Refusing to apply Terraform." >&2
    exit 1
  fi
fi

echo "Waiting for PostgreSQL."
ready=0
for _ in $(seq 1 40); do
  if "${compose_cmd[@]}" exec -T postgres pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 2
done
if [[ "$ready" -ne 1 ]]; then
  echo "PostgreSQL did not become ready." >&2
  exit 1
fi

mount_headers=("${token_headers[@]}")
if [[ -s "$root/terraform/terraform.tfstate" ]]; then
  terraform -chdir="$root/terraform" init -input=false
  if stored_namespace="$(terraform -chdir="$root/terraform" output -raw vault_namespace 2>/dev/null)"; then
    mount_headers=(-H "X-Vault-Token: $VAULT_TOKEN" -H "X-Vault-Namespace: ${stored_namespace}")
  fi
fi
mounts="$("${curl_vault[@]}" "${mount_headers[@]}" "$VAULT_ADDR/v1/sys/mounts")"
if [[ -s "$root/terraform/terraform.tfstate" ]] && ! grep -q 'pki_int/' <<<"$mounts"; then
  echo "terraform/terraform.tfstate describes a Vault that does not have these mounts." >&2
  echo "Run ./scripts/podman-teardown.sh, or delete that state file, then run this script again." >&2
  exit 1
fi

echo "Applying Terraform to ${VAULT_ADDR} in a new Vault namespace."
terraform -chdir="$root/terraform" init -input=false
terraform -chdir="$root/terraform" apply -input=false -auto-approve

"$root/scripts/write-approle-files.sh"
write_agent_vault_config

echo "Starting Vault Agent and the demo application."
"${compose_cmd[@]}" up -d --build vault-agent app

ready=0
for _ in $(seq 1 40); do
  if curl -sf "http://127.0.0.1:8080/healthz" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 2
done
if [[ "$ready" -ne 1 ]]; then
  echo "The application did not become ready. Check: ${compose[*]} -f $compose_file logs app vault-agent" >&2
  exit 1
fi

if [[ "$external_vault" -eq 1 ]]; then
  token_line="Vault:    ${VAULT_ADDR}"
else
  token_line="Vault UI: ${VAULT_ADDR}  (token: ${VAULT_TOKEN})"
fi

cat <<EOF

Lab is up.
  UI:       http://127.0.0.1:8080
  HTTPS:    https://127.0.0.1:8443
  ${token_line}
  Namespace: ${lab_namespace}

EOF
