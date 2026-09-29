# Vault laboratory: ICP-Brasil, PKI, and dynamic credentials

A small web application that shows three Vault workflows side by side:

- an **ICP-Brasil type A1 profile** issued by the PKI secrets engine
- a separate **service TLS certificate**, also from the PKI secrets engine
- a **dynamic PostgreSQL role** from the database secrets engine

The application never logs in to Vault. Something else renders the secrets into files, and the process re-reads those files on each refresh.

| Runtime | How secrets arrive |
| --- | --- |
| Podman | Vault Agent, AppRole, shared volume |
| Nomad | Nomad's Vault template stanza (the same renderer as Vault Agent) |
| Kubernetes | Vault Secrets Operator and the Kubernetes auth method |

Vault itself is configured with Terraform.

## Laboratory boundary

This is not an accredited ICP-Brasil hierarchy.

DOC-ICP-04 type A1 is a software signature certificate: RSA of at least 2048 bits, SHA-256, `digitalSignature` and `contentCommitment`, `clientAuth` and `emailProtection`, country `BR`, and a policy OID under `2.16.76.1.2.1.n`. The lab role follows that shape. The issuer common names say **Demonstracao**. The policy id `2.16.76.1.2.1.99999` sits in the A1 arc so the profile is recognizable; `99999` is not an assignment from ITI. Do not install these CAs in a production trust store.

A3 and A4 keys are held on a cryptographic device. Vault returns the private key in the issue response, so this demo is the A1 (software) profile only.

The CPF otherName uses OID `2.16.76.1.3.1`, which is the right identifier, but the value is a UTF-8 string. An accredited certificate encodes that attribute as the fixed octet string defined in DOC-ICP-04. The person and the CPF `111.444.777-35` are fictitious.

The Podman stack runs Vault in dev mode with the root token `root`. Terraform state for this lab contains the CA private keys, the AppRole secret id, and the database password. State is gitignored. Do not point the lab script at a production Vault.

## Layout

```text
app/                  Python UI and Containerfile
terraform/            Vault PKI, ICP-Brasil profile, database engine, AppRole, optional Kubernetes auth
deploy/agent/         Vault Agent configuration and templates
deploy/podman/        Compose lab, including a dev-mode Vault
deploy/nomad/         PostgreSQL job and application job
deploy/kubernetes/    Namespace, PostgreSQL, and Vault Secrets Operator resources
deploy/postgres/      Demo table
scripts/podman-lab.sh Starts the Podman lab, then applies Terraform
```

The rendered files, on every runtime, are:

```text
db.json     username, password, and (from Agent or Nomad) the lease
tls.json    service certificate, private key, and issuing CA
icp.json    A1-profile certificate, private key, and issuing CA
```

## Podman

Requires Podman (or Docker Compose), Terraform 1.10 or newer, curl, and Python 3.

```bash
./scripts/podman-lab.sh
```

The script starts Vault and PostgreSQL, checks that port 8200 is that lab Vault, applies `terraform/`, writes the AppRole files, then starts Vault Agent and the application.

- UI: http://127.0.0.1:8080
- HTTPS, using the rendered service certificate: https://127.0.0.1:8443
- Vault UI: http://127.0.0.1:8200 (token `root`)

The browser will warn about the lab CA. The service card has a link to download the issuing CA. Trust it only in a lab profile if you want the warning to go away. `localhost` is on the certificate.

Dev-mode Vault keeps nothing on disk. If you recreate that container, delete `terraform/terraform.tfstate` and run the script again.

To do the same steps by hand:

```bash
podman compose -f deploy/podman/compose.yaml up -d vault postgres
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root
terraform -chdir=terraform init
terraform -chdir=terraform apply
./scripts/write-approle-files.sh
podman compose -f deploy/podman/compose.yaml up -d --build vault-agent app
```

`deploy/podman/lab.env` and the Terraform defaults use the database user `vault` and the password `vault-lab-password`. Vault reaches PostgreSQL at the compose name `postgres`. The application does too. Those are not the dynamic credentials; Vault creates those on request.

## What the page is showing

The A1 card is a checklist against the profile above: key size, signature, key usage, extended key usage, country, policy arc, CPF OID, one-year maximum, and `CA:FALSE`. The service card is a different chain (`Vault Demo Root CA` / `Vault Demo Intermediate CA`) with `serverAuth`. The database card logs in with the rendered role and reads `registros`. The password is not included in `/api/status`.

To show rotation, revoke the lease printed on the database card:

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root
vault lease revoke database/creds/demo-app/<lease-id>
```

Vault Agent renders a new role within a few seconds. The username on the page changes without a restart. Certificates are issued for 72 hours and carry a lease, so the agent renews them and replaces the files before they expire. The A1 role refuses a lifetime longer than one year.

## Terraform

`terraform/` expects `VAULT_ADDR` and `VAULT_TOKEN`. It creates:

- `pki_root` and `pki_int`, role `demo-server`, for service TLS
- `pki_icp_root` and `pki_icp`, role `a1-pessoa-fisica`, for the A1 profile
- a database mount, a PostgreSQL connection, and the role `demo-app`
- the policy `demo-app` and an AppRole of the same name
- the Kubernetes auth method only when `enable_kubernetes_auth` is true

`postgres_host` is the address **Vault** uses to open PostgreSQL, which is not always the address the application uses.

```bash
export VAULT_ADDR=https://vault.example:8200
export VAULT_TOKEN=...
terraform -chdir=terraform apply \
  -var='postgres_host=postgres.example' \
  -var='vault_address=https://vault.example:8200'
```

See `terraform/terraform.tfvars.example`. An existing `auth/approle` mount can be imported instead of created:

```bash
terraform -chdir=terraform import vault_auth_backend.approle auth/approle
```

State holds the lab CA private keys. Keep it accordingly.

## Nomad

Build the image where the Nomad client can run it:

```bash
podman build -t vault-pki-icp-brasil-demo:local app
```

The Nomad client needs a `vault` stanza whose token can create a child token with the `demo-app` policy. On a cluster that only accepts workload identity, change the job's `vault` block to `role = "demo-app"` and bind that role to the job identity.

Both jobs use host networking and expect to land on the same client, so the application can open PostgreSQL at `127.0.0.1:5432`. Apply Terraform only after PostgreSQL is up, and set `postgres_host` to an address the Vault server can reach (a host address, not `127.0.0.1` inside the Vault container).

```bash
nomad job run deploy/nomad/postgres.nomad.hcl
terraform -chdir=terraform apply -var='postgres_host=<host reachable from Vault>'
nomad job run deploy/nomad/demo.nomad.hcl
```

The database password in the Nomad job defaults to the same lab value. Templates use `change_mode = "noop"` because the application re-reads the files.

## Kubernetes and the Vault Secrets Operator

Install the operator first:

```bash
helm repo add hashicorp https://helm.releases.hashicorp.com
helm upgrade --install vault-secrets-operator hashicorp/vault-secrets-operator \
  --namespace vault-secrets-operator-system --create-namespace
```

Load the image into the cluster, edit `deploy/kubernetes/vault-connection.yaml` so `spec.address` is a Vault URL the operator pods can reach, then apply the manifests:

```bash
kubectl apply -k deploy/kubernetes
```

Create a reviewer token and copy the cluster CA, then put them in a tfvars file (see `terraform/terraform.tfvars.example`):

```bash
kubectl -n vault-demo create token vault-auth --duration=24h
```

Apply with `enable_kubernetes_auth = true`, `kubernetes_host` set to an API address Vault can reach, `kubernetes_ca_cert`, `kubernetes_token_reviewer_jwt`, and `postgres_host`. Use `postgres.vault-demo.svc.cluster.local` when Vault is inside the cluster. When Vault is outside, publish PostgreSQL and use that address instead. The application itself uses the short name `postgres`.

The operator writes `db.json`, `tls.json`, and `icp.json` into Kubernetes Secrets. The pod mounts them at `/vault/secrets`. The Vault role audience and the `VaultAuth` audience are both `vault`.

Open the UI with:

```bash
kubectl -n vault-demo port-forward svc/demo-app 8080:8080
```

## Tests

```bash
python3 -m venv .venv
.venv/bin/pip install -r app/requirements.txt
PYTHONPATH=app .venv/bin/python -m unittest discover -s app/tests
terraform -chdir=terraform fmt -check -recursive
terraform -chdir=terraform init -backend=false
terraform -chdir=terraform validate
```

`validate` does not need a running Vault. `apply` does, and the database connection is verified against PostgreSQL.
