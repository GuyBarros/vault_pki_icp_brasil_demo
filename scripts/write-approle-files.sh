#!/usr/bin/env bash
# Write the Terraform AppRole outputs into the files Vault Agent reads.
# Usage: scripts/write-approle-files.sh [output-directory]

set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="${1:-$root/deploy/podman/secrets}"

mkdir -p "$out"
terraform -chdir="$root/terraform" output -raw approle_role_id >"$out/role_id"
terraform -chdir="$root/terraform" output -raw approle_secret_id >"$out/secret_id"
# The Vault image drops to the vault user after start. On a Podman machine
# that user is not the file owner, so mode 600 leaves the agent unable to log in.
chmod 644 "$out/role_id" "$out/secret_id"

echo "Wrote ${out}/role_id and ${out}/secret_id"
