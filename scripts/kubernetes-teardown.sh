#!/usr/bin/env bash
# Remove the Kubernetes laboratory started by scripts/kubernetes-lab.sh.
# When VAULT_ADDR and VAULT_TOKEN are set, Terraform destroy runs against that
# Vault first. The Vault server and the Vault Secrets Operator stay installed.

set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
state_file="$root/terraform/terraform.tfstate"

if ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl is required." >&2
  exit 1
fi

if [[ -n "${VAULT_ADDR:-}" || -n "${VAULT_TOKEN:-}" ]]; then
  if [[ -z "${VAULT_ADDR:-}" || -z "${VAULT_TOKEN:-}" ]]; then
    echo "Set both VAULT_ADDR and VAULT_TOKEN so Terraform can destroy resources in Vault." >&2
    exit 1
  fi
fi

export VAULT_SKIP_VERIFY="${VAULT_SKIP_VERIFY:-false}"
destroy_ok=1

if [[ -n "${VAULT_ADDR:-}" && -s "$state_file" ]]; then
  if ! command -v terraform >/dev/null 2>&1; then
    echo "terraform is required to destroy resources in ${VAULT_ADDR}." >&2
    exit 1
  fi
  terraform -chdir="$root/terraform" init -input=false
  lab_namespace="$(terraform -chdir="$root/terraform" output -raw vault_namespace 2>/dev/null || true)"
  if [[ -z "$lab_namespace" ]]; then
    lab_namespace="${TF_VAR_vault_namespace:-demo}"
  fi

  echo "Force-revoking dynamic database leases in namespace ${lab_namespace}."
  if command -v vault >/dev/null 2>&1; then
    VAULT_NAMESPACE="$lab_namespace" vault lease revoke -force -prefix database/creds || true
  elif command -v curl >/dev/null 2>&1; then
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
    echo "Terraform destroy failed. The Kubernetes lab will still be removed, and Terraform state will be kept." >&2
  fi
elif [[ -s "$state_file" ]]; then
  echo "VAULT_ADDR is unset, so Terraform state will be kept. Set VAULT_ADDR and VAULT_TOKEN to destroy the Vault configuration."
  destroy_ok=0
fi

pid_file="$root/deploy/kubernetes/.postgres-port-forward.pid"
if [[ -f "$pid_file" ]]; then
  echo "Stopping the PostgreSQL port-forward."
  kill "$(cat "$pid_file")" >/dev/null 2>&1 || true
  rm -f "$pid_file" "$root/deploy/kubernetes/.postgres-port-forward.log"
fi

if command -v podman >/dev/null 2>&1; then
  podman rm -f vault-pki-demo-publish >/dev/null 2>&1 || true
fi
if command -v docker >/dev/null 2>&1; then
  docker rm -f vault-pki-demo-publish >/dev/null 2>&1 || true
fi

echo "Deleting the vault-demo Kubernetes resources."
kubectl delete -k "$root/deploy/kubernetes" --ignore-not-found --wait=true

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

Kubernetes lab is down.
  The Vault server and the Vault Secrets Operator were left in place.
  Run ./scripts/kubernetes-lab.sh to deploy it again.

EOF

if [[ "$destroy_ok" -ne 1 ]]; then
  exit 1
fi
