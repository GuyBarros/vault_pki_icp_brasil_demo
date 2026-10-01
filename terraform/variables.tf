variable "database_default_ttl_seconds" {
  description = "Lifetime of a dynamic PostgreSQL credential. The lab default is 2 minutes, and the role max TTL matches it so the next render is a new role."
  type        = number
  default     = 120

  validation {
    condition     = var.database_default_ttl_seconds >= 60
    error_message = "database_default_ttl_seconds must be at least 60."
  }
}

variable "database_max_ttl_seconds" {
  description = "Maximum lifetime of a dynamic PostgreSQL credential, including renewals. The lab default matches the 2 minute lifetime so Vault cannot extend the role."
  type        = number
  default     = 120

  validation {
    condition     = var.database_max_ttl_seconds >= 60
    error_message = "database_max_ttl_seconds must be at least 60."
  }
}

variable "enable_kubernetes_auth" {
  description = "Configure the Kubernetes auth method used by the Vault Secrets Operator."
  type        = bool
  default     = false
}

variable "icp_ca_chain_file" {
  description = "PEM file of the CA certificates above the ICP-Brasil issuer. Empty uses the laboratory root certificate in deploy/icp."
  type        = string
  default     = ""
}

variable "icp_certificate_file" {
  description = "PEM file of the ICP-Brasil end-entity certificate stored in KV. Empty uses the laboratory certificate in deploy/icp."
  type        = string
  default     = ""
}

variable "icp_issuing_ca_file" {
  description = "PEM file of the intermediate CA that issued the ICP-Brasil certificate. Empty uses the laboratory issuing CA in deploy/icp."
  type        = string
  default     = ""
}

variable "icp_private_key_file" {
  description = "PEM file of the ICP-Brasil end-entity private key stored in KV. Empty uses the laboratory key in deploy/icp."
  type        = string
  default     = ""
}

variable "icp_public_key_file" {
  description = "PEM file of the ICP-Brasil end-entity public key stored in KV. Empty uses the laboratory key in deploy/icp."
  type        = string
  default     = ""
}

variable "kubernetes_ca_cert" {
  description = "PEM CA bundle Vault uses to call the Kubernetes TokenReview API. Required when enable_kubernetes_auth is true."
  type        = string
  default     = null
}

variable "kubernetes_disable_iss_validation" {
  description = "Skip issuer validation on the Kubernetes auth method. Useful for kind, k3s, and other clusters whose issuer URL is not reachable from Vault."
  type        = bool
  default     = true
}

variable "kubernetes_host" {
  description = "Kubernetes API address reachable from Vault. Required when enable_kubernetes_auth is true."
  type        = string
  default     = null
}

variable "kubernetes_token_reviewer_jwt" {
  description = "JWT of the vault-auth service account. Vault uses it to call the TokenReview API. Required when enable_kubernetes_auth is true."
  type        = string
  default     = null
  sensitive   = true
}

variable "postgres_admin_password" {
  description = "Password of the PostgreSQL user Vault uses to create dynamic roles. The default matches deploy/podman/lab.env and is for the local laboratory only."
  type        = string
  default     = "vault-lab-password"
  sensitive   = true
}

variable "postgres_admin_username" {
  description = "PostgreSQL user Vault uses to create and revoke dynamic roles."
  type        = string
  default     = "vault"
}

variable "postgres_database" {
  description = "PostgreSQL database that holds the demo table."
  type        = string
  default     = "demo"
}

variable "postgres_host" {
  description = "Hostname where the Vault server can reach PostgreSQL. The Podman lab uses the compose service name postgres. The application may use a different hostname."
  type        = string
  default     = "postgres"
}

variable "postgres_port" {
  description = "PostgreSQL port reachable from the Vault server."
  type        = number
  default     = 5432
}

variable "tls_allowed_domains" {
  description = "DNS domains the service PKI role may issue."
  type        = list(string)
  default     = ["vault.local", "svc.cluster.local", "service.consul"]
}

variable "tls_certificate_ttl_seconds" {
  description = "Lifetime of a service certificate. The lab default is 1 minute, and the role max TTL matches it so the next render is a new certificate."
  type        = number
  default     = 60

  validation {
    condition     = var.tls_certificate_ttl_seconds >= 60 && var.tls_certificate_ttl_seconds <= 2592000
    error_message = "tls_certificate_ttl_seconds must be between 60 seconds and 30 days."
  }
}

variable "vault_address" {
  description = "Vault API address written into certificate AIA and CRL URLs."
  type        = string
  default     = "http://127.0.0.1:8200"
}

variable "vault_namespace" {
  description = "Vault Enterprise namespace this configuration creates. Mounts, policies, and auth methods are configured inside it. A single path segment; a parent in VAULT_NAMESPACE is kept."
  type        = string
  default     = "demo"

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]+$", var.vault_namespace))
    error_message = "vault_namespace must be one path segment of letters, numbers, underscores, or hyphens."
  }
}
