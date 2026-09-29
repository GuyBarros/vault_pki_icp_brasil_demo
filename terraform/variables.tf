variable "database_default_ttl_seconds" {
  description = "Lifetime of a dynamic PostgreSQL credential before Vault Agent or the Secrets Operator must renew it."
  type        = number
  default     = 3600

  validation {
    condition     = var.database_default_ttl_seconds >= 60
    error_message = "database_default_ttl_seconds must be at least 60."
  }
}

variable "database_max_ttl_seconds" {
  description = "Maximum lifetime of a dynamic PostgreSQL credential, including renewals."
  type        = number
  default     = 14400

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

variable "icp_certificate_ttl_seconds" {
  description = "Default lifetime of an A1-profile certificate. DOC-ICP-04 limits type A1 to one year; the lab default is 72 hours."
  type        = number
  default     = 259200

  validation {
    condition     = var.icp_certificate_ttl_seconds >= 60 && var.icp_certificate_ttl_seconds <= 31536000
    error_message = "icp_certificate_ttl_seconds must be between 60 seconds and one year."
  }
}

variable "icp_cps_url" {
  description = "Certificate practice statement URL stamped on A1-profile certificates. This lab URL is not a published DPC."
  type        = string
  default     = "http://demo.vault.local/dpc"
}

variable "icp_policy_notice" {
  description = "User notice placed on the laboratory A1 certificate policy."
  type        = string
  default     = "Politica de Certificado de Assinatura Digital tipo A1 da AC Demonstracao Vault. Laboratorio, sem credenciamento na ICP-Brasil."
}

variable "icp_policy_oid" {
  description = "Policy OID placed on A1-profile certificates. 2.16.76.1.2.1.n is the A1 arc; 99999 is a laboratory id, not an ITI assignment."
  type        = string
  default     = "2.16.76.1.2.1.99999"

  validation {
    condition     = can(regex("^([0-9]+\\.)+[0-9]+$", var.icp_policy_oid))
    error_message = "icp_policy_oid must be a dotted numeric OID."
  }
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
  description = "Default lifetime of a service certificate. The lab default is 72 hours."
  type        = number
  default     = 259200

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
  description = "Vault Enterprise namespace. Leave null for Vault OSS or the root namespace."
  type        = string
  default     = null
}
