#!/usr/bin/env bash
# Deploy the laboratory on Nomad and configure the existing Vault.
# Requires VAULT_ADDR and VAULT_TOKEN. VAULT_SKIP_VERIFY=true skips TLS
# verification for Terraform. The Nomad client must already be able to create
# a child token with the demo-app policy in Vault namespace demo.
# Both jobs use host networking and datacenter dc1.

set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
image="vault-pki-icp-brasil-demo:local"

for tool in nomad terraform python3 curl openssl; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool is required." >&2
    exit 1
  fi
done

if [[ -z "${VAULT_ADDR:-}" || -z "${VAULT_TOKEN:-}" ]]; then
  echo "Set VAULT_ADDR and VAULT_TOKEN. This script configures the Vault you already have." >&2
  exit 1
fi

if [[ "${TF_VAR_vault_namespace:-demo}" != "demo" ]]; then
  echo "The Nomad job uses Vault namespace demo. Set TF_VAR_vault_namespace=demo." >&2
  exit 1
fi

set -a
# shellcheck disable=SC1091
source "$root/deploy/podman/lab.env"
set +a

export VAULT_SKIP_VERIFY="${VAULT_SKIP_VERIFY:-false}"
export TF_VAR_vault_namespace=demo
export TF_VAR_vault_address="${TF_VAR_vault_address:-$VAULT_ADDR}"
export TF_VAR_postgres_admin_username="$POSTGRES_USER"
export TF_VAR_postgres_admin_password="$POSTGRES_PASSWORD"
export TF_VAR_postgres_database="$POSTGRES_DB"

if command -v podman >/dev/null 2>&1; then
  echo "Building ${image} with podman."
  podman build -t "$image" "$root/app"
elif command -v docker >/dev/null 2>&1; then
  echo "Building ${image} with docker."
  docker build -t "$image" "$root/app"
else
  echo "podman or docker is required to build ${image}." >&2
  exit 1
fi

echo "Starting PostgreSQL on the Nomad client."
nomad job run -var "postgres_password=${POSTGRES_PASSWORD}" "$root/deploy/nomad/postgres.nomad.hcl"

if [[ -z "${TF_VAR_postgres_host:-}" ]]; then
  vault_is_local="$(python3 - "$VAULT_ADDR" <<'PY'
import sys
from urllib.parse import urlparse
host = urlparse(sys.argv[1]).hostname or ""
print("yes" if host in {"127.0.0.1", "localhost", "::1"} else "no")
PY
)"
  if [[ "$vault_is_local" != "yes" ]]; then
    echo "Set TF_VAR_postgres_host to the Nomad client address Vault can use to open PostgreSQL." >&2
    exit 1
  fi
  export TF_VAR_postgres_host="127.0.0.1"
fi

echo "Waiting for PostgreSQL at ${TF_VAR_postgres_host}:${TF_VAR_postgres_port:-5432}."
python3 - "$TF_VAR_postgres_host" "${TF_VAR_postgres_port:-5432}" <<'PY'
import socket, sys, time
host, port = sys.argv[1], int(sys.argv[2])
for _ in range(40):
    try:
        with socket.create_connection((host, port), 2):
            raise SystemExit(0)
    except OSError:
        time.sleep(2)
raise SystemExit(f"PostgreSQL did not accept connections on {host}:{port}")
PY

echo "Applying Terraform to ${VAULT_ADDR} in namespace demo."
terraform -chdir="$root/terraform" init -input=false
terraform -chdir="$root/terraform" apply -input=false -auto-approve

echo "Starting the demo job."
nomad job run -var "image=${image}" "$root/deploy/nomad/demo.nomad.hcl"

cat <<EOF

Nomad lab is up.
  UI, on the Nomad client: http://127.0.0.1:8080
  HTTPS: https://127.0.0.1:8443
  Vault: ${VAULT_ADDR}
  Vault namespace: demo
  The client must already hold ${image} and a Vault token that can create
  child tokens with the demo-app policy in namespace demo.

EOF
