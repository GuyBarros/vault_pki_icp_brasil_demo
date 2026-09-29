#!/usr/bin/env bash
# Start the local laboratory: dev Vault, PostgreSQL, Terraform, Vault Agent, and the UI.
# This script always talks to http://127.0.0.1:8200. It will not use VAULT_ADDR from the environment.

set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
compose_file="$root/deploy/podman/compose.yaml"
vault_addr="http://127.0.0.1:8200"

if podman compose version >/dev/null 2>&1; then
  compose=(podman compose)
elif docker compose version >/dev/null 2>&1; then
  compose=(docker compose)
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

export VAULT_ADDR="$vault_addr"
export VAULT_TOKEN="$VAULT_DEV_ROOT_TOKEN_ID"
export TF_VAR_postgres_admin_username="$POSTGRES_USER"
export TF_VAR_postgres_admin_password="$POSTGRES_PASSWORD"
export TF_VAR_postgres_database="$POSTGRES_DB"
export TF_VAR_postgres_host="${TF_VAR_postgres_host:-postgres}"
export TF_VAR_vault_address="${TF_VAR_vault_address:-$vault_addr}"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-vault-pki-demo}"

compose_cmd=("${compose[@]}" --project-name "$COMPOSE_PROJECT_NAME" -f "$compose_file")

echo "Starting the lab Vault and PostgreSQL."
"${compose_cmd[@]}" up -d vault postgres

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

accessor_of() {
  python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["accessor"])'
}

host_accessor="$(curl -sf -H "X-Vault-Token: $VAULT_TOKEN" "$VAULT_ADDR/v1/auth/token/lookup-self" | accessor_of)"
container_accessor="$("${compose_cmd[@]}" exec -T \
  -e VAULT_ADDR=http://127.0.0.1:8200 \
  -e VAULT_TOKEN="$VAULT_TOKEN" \
  vault vault token lookup -format=json | accessor_of)"

if [[ "$host_accessor" != "$container_accessor" ]]; then
  echo "http://127.0.0.1:8200 is not the lab Vault this script just started. Refusing to apply Terraform." >&2
  exit 1
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

mounts="$(curl -sf -H "X-Vault-Token: $VAULT_TOKEN" "$VAULT_ADDR/v1/sys/mounts")"
if [[ -s "$root/terraform/terraform.tfstate" ]] && ! grep -q 'pki_int/' <<<"$mounts"; then
  echo "The lab Vault is empty, but terraform/terraform.tfstate still describes a previous server." >&2
  echo "Delete that state file and run this script again. Dev-mode Vault does not keep data across restarts." >&2
  exit 1
fi

echo "Applying Terraform to the lab Vault at $VAULT_ADDR."
terraform -chdir="$root/terraform" init -input=false
terraform -chdir="$root/terraform" apply -input=false -auto-approve

"$root/scripts/write-approle-files.sh"

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

cat <<EOF

Lab is up.
  UI:       http://127.0.0.1:8080
  HTTPS:    https://127.0.0.1:8443
  Vault UI: ${VAULT_ADDR}  (token: ${VAULT_TOKEN})

EOF
