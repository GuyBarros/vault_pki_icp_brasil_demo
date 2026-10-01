terraform {
  required_version = ">= 1.10"

  required_providers {
    external = {
      source  = "hashicorp/external"
      version = "~> 2.3"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "~> 5.0"
    }
  }
}
