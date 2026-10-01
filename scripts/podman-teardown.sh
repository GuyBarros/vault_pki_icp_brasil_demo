#!/usr/bin/env bash
# Stop the laboratory started by scripts/podman-lab.sh.
# When VAULT_ADDR and VAULT_TOKEN are set, Terraform destroy runs against that
# Vault first and uses VAULT_SKIP_VERIFY. The Vault server itself is left running.
# Then this removes the Compose project, the rendered volume, the locally built
# app image, the AppRole files, and the Terraform state.

set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
compose_file="$root/deploy/podman/compose.yaml"
secrets_dir="$root/deploy/podman/secrets"
state_file="$root/terraform/terraform.tfstate"

if podman compose version >/dev/null 2>&1; then
  compose=(podman compose)
elif docker compose version >/dev/null 2>&1; then
  compose=(docker compose)
else
  echo "podman compose or docker compose is required." >&2
  exit 1
fi

if [[ -n "${VAULT_ADDR:-}" || -n "${VAULT_TOKEN:-}" ]]; then
  if [[ -z "${VAULT_ADDR:-}" || -z "${VAULT_TOKEN:-}" ]]; then
    echo "Set both VAULT_ADDR and VAULT_TOKEN so Terraform can destroy resources in Vault." >&2
    exit 1
  fi
fi

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-vault-pki-demo}"
export VAULT_SKIP_VERIFY="${VAULT_SKIP_VERIFY:-false}"
compose_cmd=("${compose[@]}" --project-name "$COMPOSE_PROJECT_NAME" --profile local-vault -f "$compose_file")
destroy_ok=1

if [[ -n "${VAULT_ADDR:-}" && -s "$state_file" ]]; then
  if ! command -v terraform >/dev/null 2>&1; then
    echo "terraform is required to destroy resources in ${VAULT_ADDR}." >&2
    exit 1
  fi
  if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required to revoke database leases in ${VAULT_ADDR}." >&2
    exit 1
  fi
  terraform -chdir="$root/terraform" init -input=false
  lab_namespace="$(terraform -chdir="$root/terraform" output -raw vault_namespace 2>/dev/null || true)"
  if [[ -z "$lab_namespace" ]]; then
    lab_namespace="${TF_VAR_vault_namespace:-demo}"
  fi

  # The database connection is removed before the mount. Vault then refuses to
  # delete the mount while dynamic-credential leases still name that connection.
  echo "Force-revoking dynamic database leases in namespace ${lab_namespace}."
  if command -v vault >/dev/null 2>&1; then
    VAULT_NAMESPACE="$lab_namespace" vault lease revoke -force -prefix database/creds || true
  else
    curl_args=(-sS -o /dev/null -w "%{http_code}" -X PUT)
    case "$VAULT_SKIP_VERIFY" in
      true|TRUE|1) curl_args+=(-k) ;;
    esac
    revoke_code="$(
      curl "${curl_args[@]}" \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "X-Vault-Namespace: ${lab_namespace}" \
        "${VAULT_ADDR}/v1/sys/leases/revoke-force/database/creds" || true
    )"
    echo "Lease revoke returned HTTP ${revoke_code}."
  fi

  echo "Destroying the lab namespace and its configuration in ${VAULT_ADDR}."
  if ! terraform -chdir="$root/terraform" destroy -input=false -auto-approve; then
    destroy_ok=0
    echo "Terraform destroy failed. The local containers will still be stopped, and Terraform state will be kept." >&2
  fi
elif [[ -s "$state_file" ]]; then
  echo "VAULT_ADDR is unset, so Terraform state will be deleted with the local dev Vault."
fi

echo "Stopping project ${COMPOSE_PROJECT_NAME}."
"${compose_cmd[@]}" down --volumes --remove-orphans --rmi local

for name in role_id secret_id agent-vault.hcl; do
  if [[ -f "$secrets_dir/$name" ]]; then
    rm -f "$secrets_dir/$name"
    echo "Removed ${secrets_dir}/${name}"
  fi
done

if [[ "$destroy_ok" -eq 1 ]]; then
  for state in \
    "$state_file" \
    "$root/terraform/terraform.tfstate.backup"; do
    if [[ -f "$state" ]]; then
      rm -f "$state"
      echo "Removed ${state}"
    fi
  done
fi

cat <<EOF

Lab is down.
  Use the same VAULT_ADDR, VAULT_TOKEN, and COMPOSE_PROJECT_NAME you used to start it.
  Run ./scripts/podman-lab.sh to bring the laboratory back.

EOF

if [[ "$destroy_ok" -ne 1 ]]; then
  exit 1
fi
