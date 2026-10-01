#!/usr/bin/env bash
# Deploy the laboratory on Kubernetes and configure the existing Vault.
# Requires VAULT_ADDR and VAULT_TOKEN. VAULT_SKIP_VERIFY=true skips TLS
# verification for Terraform. The Vault Secrets Operator uses the same address,
# with a loopback host rewritten to host.docker.internal.
# Manifests expect Vault namespace demo.

set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
namespace="vault-demo"
image="vault-pki-icp-brasil-demo:local"

for tool in kubectl terraform python3 curl openssl; do
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
  echo "The Kubernetes manifests use Vault namespace demo. Set TF_VAR_vault_namespace=demo." >&2
  exit 1
fi

set -a
# shellcheck disable=SC1091
source "$root/deploy/podman/lab.env"
set +a

export VAULT_SKIP_VERIFY="${VAULT_SKIP_VERIFY:-true}"
export TF_VAR_vault_namespace=demo
export TF_VAR_vault_address="${TF_VAR_vault_address:-$VAULT_ADDR}"
export TF_VAR_enable_kubernetes_auth=true
export TF_VAR_postgres_admin_username="$POSTGRES_USER"
export TF_VAR_postgres_admin_password="$POSTGRES_PASSWORD"
export TF_VAR_postgres_database="$POSTGRES_DB"

builder=""
if command -v podman >/dev/null 2>&1; then
  builder="podman"
elif command -v docker >/dev/null 2>&1; then
  builder="docker"
else
  echo "podman or docker is required to build ${image}." >&2
  exit 1
fi
echo "Building ${image} with ${builder}."
"$builder" build -t "$image" "$root/app"

context="$(kubectl config current-context)"
if [[ "$context" == kind-* ]] && command -v kind >/dev/null 2>&1; then
  echo "Loading ${image} into kind cluster ${context#kind-}."
  if [[ "$builder" == "podman" ]]; then
    "$builder" save "$image" | kind load image-archive /dev/stdin --name "${context#kind-}"
  else
    kind load docker-image "$image" --name "${context#kind-}"
  fi
elif command -v minikube >/dev/null 2>&1 && minikube -p "$context" status >/dev/null 2>&1; then
  echo "Loading ${image} into minikube profile ${context}."
  if [[ "$builder" == "podman" ]]; then
    archive="$(mktemp -t demo-app.XXXXXX.tar)"
    podman save -o "$archive" "$image"
    minikube -p "$context" image load "$archive"
    rm -f "$archive"
    # Podman save records the image as localhost/<name>. The kubelet looks up
    # docker.io/library/<name> for a short image reference.
    minikube -p "$context" ssh -- sudo ctr -n k8s.io images tag \
      "localhost/${image}" "docker.io/library/${image}"
  else
    minikube -p "$context" image load "$image"
  fi
fi

if ! kubectl get crd vaultconnections.secrets.hashicorp.com >/dev/null 2>&1; then
  if ! command -v helm >/dev/null 2>&1; then
    echo "The Vault Secrets Operator is not installed, and helm is not available." >&2
    exit 1
  fi
  echo "Installing the Vault Secrets Operator."
  helm repo add hashicorp https://helm.releases.hashicorp.com || true
  helm repo update hashicorp
  helm upgrade --install vault-secrets-operator hashicorp/vault-secrets-operator \
    --namespace vault-secrets-operator-system --create-namespace
fi

echo "Starting PostgreSQL and the token reviewer in ${namespace}."
kubectl apply -f "$root/deploy/kubernetes/namespace.yaml"
kubectl apply -f "$root/deploy/kubernetes/postgres.yaml"
kubectl apply -f "$root/deploy/kubernetes/vault-reviewer.yaml"
kubectl -n "$namespace" rollout status deploy/postgres --timeout=180s

kubernetes_host_from_user="${TF_VAR_kubernetes_host:-}"
if [[ -z "$kubernetes_host_from_user" ]]; then
  TF_VAR_kubernetes_host="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
fi
export TF_VAR_kubernetes_host

ca_b64="$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' || true)"
if [[ -n "$ca_b64" ]]; then
  TF_VAR_kubernetes_ca_cert="$(printf '%s' "$ca_b64" | base64 -d)"
else
  ca_file="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.certificate-authority}')"
  TF_VAR_kubernetes_ca_cert="$(cat "$ca_file")"
fi
export TF_VAR_kubernetes_ca_cert

echo "Creating a reviewer token for Vault."
export TF_VAR_kubernetes_token_reviewer_jwt
TF_VAR_kubernetes_token_reviewer_jwt="$(kubectl -n "$namespace" create token vault-auth --duration=24h)"

# cluster: Vault is a pod, published through a node container (minikube, kind).
# host: the vault binary is listening on this machine.
# remote: VAULT_ADDR is not a loopback address.
# The second field is an in-cluster Vault URL when one can be derived.
vault_placement="$(python3 - "$VAULT_ADDR" <<'PY'
import json, re, subprocess, sys
from urllib.parse import urlparse

url = urlparse(sys.argv[1])
host = url.hostname or ""
port = url.port or (443 if url.scheme == "https" else 80)
if host not in {"127.0.0.1", "localhost", "::1"}:
    print("remote")
    raise SystemExit(0)

def run(cmd):
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""

def container_port(ports, wanted):
    for match in re.finditer(r":(\d+)(?:-(\d+))?->(\d+)(?:-(\d+))?", ports):
        start = int(match.group(1))
        end = int(match.group(2) or start)
        dest = int(match.group(3))
        if start <= wanted <= end:
            return dest + (wanted - start)
    return None

nodes = set(run(["kubectl", "get", "nodes", "-o", "jsonpath={range .items[*]}{.metadata.name}{\"\\n\"}{end}"]).split())
published = None
for tool in ("podman", "docker"):
    for line in run([tool, "ps", "--format", "{{.Names}}|{{.Ports}}"]).splitlines():
        if "|" not in line:
            continue
        name, ports = line.split("|", 1)
        mapped = container_port(ports, port)
        if name in nodes and mapped is not None:
            published = mapped
            break
    if published is not None:
        break

if published is None:
    listeners = run(["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-Fc"])
    commands = [line[1:] for line in listeners.splitlines() if line.startswith("c")]
    print("host" if "vault" in commands else "unknown")
    raise SystemExit(0)

operator = ""
raw = run(["kubectl", "get", "svc", "-A", "-o", "json"])
if raw:
    for item in json.loads(raw).get("items", []):
        for spec in item.get("spec", {}).get("ports", []):
            if spec.get("nodePort") != published:
                continue
            name = item["metadata"]["name"]
            namespace = item["metadata"]["namespace"]
            scheme = url.scheme or "https"
            operator = f"{scheme}://{name}.{namespace}.svc.cluster.local:{spec['port']}"
            break
        if operator:
            break
print(f"cluster {operator}".rstrip())
PY
)"
vault_mode="${vault_placement%% *}"
operator_in_cluster="${vault_placement#* }"
if [[ "$operator_in_cluster" == "$vault_placement" ]]; then
  operator_in_cluster=""
fi

stop_postgres_forward() {
  pid_file="$root/deploy/kubernetes/.postgres-port-forward.pid"
  if [[ -f "$pid_file" ]]; then
    kill "$(cat "$pid_file")" >/dev/null 2>&1 || true
    rm -f "$pid_file" "$root/deploy/kubernetes/.postgres-port-forward.log"
  fi
}

if [[ -z "${TF_VAR_postgres_host:-}" ]]; then
  case "$vault_mode" in
    cluster|remote)
      stop_postgres_forward
      export TF_VAR_postgres_host="postgres.${namespace}.svc.cluster.local"
      export TF_VAR_postgres_port="5432"
      echo "Vault will open PostgreSQL at ${TF_VAR_postgres_host}."
      ;;
    host)
      # The vault process is on this machine, so a Service NodePort inside a
      # cluster VM is not enough. Forward the Service to localhost.
      kubectl -n "$namespace" patch svc postgres --type merge -p '{"spec":{"type":"ClusterIP"}}' >/dev/null
      export TF_VAR_postgres_host="127.0.0.1"
      export TF_VAR_postgres_port="${KUBERNETES_POSTGRES_PORT:-15432}"
      pid_file="$root/deploy/kubernetes/.postgres-port-forward.pid"
      log_file="$root/deploy/kubernetes/.postgres-port-forward.log"
      stop_postgres_forward
      nohup kubectl -n "$namespace" port-forward --address 127.0.0.1 \
        "svc/postgres" "${TF_VAR_postgres_port}:5432" >"$log_file" 2>&1 &
      echo $! >"$pid_file"
      if ! python3 - "$TF_VAR_postgres_host" "$TF_VAR_postgres_port" <<'PY'
import socket, sys, time
host, port = sys.argv[1], int(sys.argv[2])
for _ in range(30):
    try:
        with socket.create_connection((host, port), 2):
            raise SystemExit(0)
    except OSError:
        time.sleep(1)
raise SystemExit(1)
PY
      then
        echo "PostgreSQL port-forward did not accept connections on ${TF_VAR_postgres_host}:${TF_VAR_postgres_port}." >&2
        cat "$log_file" >&2 || true
        exit 1
      fi
      echo "PostgreSQL is forwarded to ${TF_VAR_postgres_host}:${TF_VAR_postgres_port} for the Vault process on this machine."
      ;;
    *)
      echo "Vault's localhost is not this machine, and it is not published by a node in the current cluster. Set TF_VAR_postgres_host to an address that ${VAULT_ADDR} can open." >&2
      exit 1
      ;;
  esac
fi

operator_vault_addr="$(python3 - "$VAULT_ADDR" <<'PY'
import sys
from urllib.parse import urlparse, urlunparse
url = sys.argv[1]
parts = urlparse(url)
if parts.hostname in {"127.0.0.1", "localhost", "::1"}:
    netloc = "host.docker.internal"
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    parts = parts._replace(netloc=netloc)
print(urlunparse(parts))
PY
)"
if [[ -n "$operator_in_cluster" ]]; then
  operator_vault_addr="$operator_in_cluster"
fi
if [[ -n "${KUBERNETES_VAULT_ADDRESS:-}" ]]; then
  operator_vault_addr="$KUBERNETES_VAULT_ADDRESS"
fi

if [[ -z "$kubernetes_host_from_user" && "$vault_mode" == "cluster" ]]; then
  # kubeconfig points at this machine. Vault is a pod, so 127.0.0.1 is the
  # pod and TokenReview fails. Use the in-cluster API.
  export TF_VAR_kubernetes_host="https://kubernetes.default.svc"
  in_cluster_ca="$(kubectl -n "$namespace" exec deploy/postgres -- cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt 2>/dev/null || true)"
  if [[ -n "$in_cluster_ca" ]]; then
    export TF_VAR_kubernetes_ca_cert="$in_cluster_ca"
  fi
  echo "Vault is inside the cluster. Kubernetes auth will call ${TF_VAR_kubernetes_host}."
fi

echo "Applying Terraform to ${VAULT_ADDR} in namespace demo."
terraform -chdir="$root/terraform" init -input=false
terraform -chdir="$root/terraform" apply -input=false -auto-approve

app_port="${APP_PORT:-8085}"
app_node_port="${APP_NODE_PORT:-30085}"
if [[ ! "$app_port" =~ ^[0-9]+$ || ! "$app_node_port" =~ ^[0-9]+$ ]]; then
  echo "APP_PORT and APP_NODE_PORT must be numbers." >&2
  exit 1
fi
echo "Applying the Vault Secrets Operator resources and the application on port ${app_port}."
render_dir="$(mktemp -d)"
cp -R "$root/deploy/kubernetes/." "$render_dir/"
python3 - "$render_dir/demo-app.yaml" "$app_port" "$app_node_port" <<'PY'
import pathlib, sys
path, port, node_port = sys.argv[1:]
file = pathlib.Path(path)
text = file.read_text()
text = text.replace("containerPort: 8085", f"containerPort: {port}")
text = text.replace('value: "8085"', f'value: "{port}"')
text = text.replace("port: 8085", f"port: {port}")
text = text.replace("nodePort: 30085", f"nodePort: {node_port}")
file.write_text(text)
PY
kubectl apply -k "$render_dir"
rm -rf "$render_dir"
skip="false"
case "$VAULT_SKIP_VERIFY" in
  true|TRUE|1) skip="true" ;;
esac
kubectl -n "$namespace" patch vaultconnection vault --type merge \
  -p "{\"spec\":{\"address\":\"${operator_vault_addr}\",\"skipTLSVerify\":${skip}}}"

kubectl -n "$namespace" rollout status deploy/demo-app --timeout=180s

echo "Waiting for the ICP-Brasil secret."
for _ in $(seq 1 30); do
  if kubectl -n "$namespace" get secret icp-cert >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
if ! kubectl -n "$namespace" exec deploy/demo-app -- test -f /vault/secrets/icp.json >/dev/null 2>&1; then
  echo "Restarting the application so it mounts icp.json."
  kubectl -n "$namespace" rollout restart deploy/demo-app
  kubectl -n "$namespace" rollout status deploy/demo-app --timeout=180s
fi

node_ip="$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')"
app_url="http://${node_ip}:${app_node_port}"
if ! python3 - "$node_ip" "$app_node_port" <<'PY'
import socket, sys
sock = socket.socket()
sock.settimeout(2)
try:
    sock.connect((sys.argv[1], int(sys.argv[2])))
except OSError:
    raise SystemExit(1)
finally:
    sock.close()
PY
then
  publish_runtime=""
  if command -v podman >/dev/null 2>&1 && podman network inspect "$context" >/dev/null 2>&1; then
    publish_runtime="podman"
  elif command -v docker >/dev/null 2>&1 && docker network inspect "$context" >/dev/null 2>&1; then
    publish_runtime="docker"
  else
    echo "The node address ${node_ip} is not reachable from this machine, so the NodePort cannot be opened on the host." >&2
    exit 1
  fi
  echo "Publishing NodePort ${app_node_port} on http://127.0.0.1:${app_port}."
  "$publish_runtime" rm -f vault-pki-demo-publish >/dev/null 2>&1 || true
  "$publish_runtime" run -d \
    --name vault-pki-demo-publish \
    --restart unless-stopped \
    --network "$context" \
    --publish "127.0.0.1:${app_port}:8085" \
    --env "NODE_IP=${node_ip}" \
    --env "NODE_PORT=${app_node_port}" \
    --volume "${root}/deploy/kubernetes/host-publish.py:/publish.py:ro" \
    docker.io/library/python:3.12-slim \
    python /publish.py
  app_url="http://127.0.0.1:${app_port}"
fi

cat <<EOF

Kubernetes lab is up.
  UI: ${app_url}
  Vault: ${VAULT_ADDR}
  Operator Vault address: ${operator_vault_addr}
  Vault namespace: demo
  PostgreSQL, from Vault: ${TF_VAR_postgres_host}:${TF_VAR_postgres_port:-5432}

EOF
