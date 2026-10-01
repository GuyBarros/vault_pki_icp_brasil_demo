locals {
  tls_root_path = "pki_root"
  tls_int_path  = "pki_int"
  kv_path       = "kv"

  tls_role_name            = "demo-server"
  icp_secret_name          = "icp-brasil"
  database_path            = "database"
  database_role            = "demo-app"
  policy_name              = "demo-app"
  icp_metadata_policy_name = "icp-metadata-reader"
  approle_name             = "demo-app"
  kubernetes_role          = "demo-app"
  approle_auth_path        = "approle"
  kubernetes_path          = "kubernetes"

  icp_certificate_file = var.icp_certificate_file != "" ? var.icp_certificate_file : "${path.module}/../deploy/icp/certificate.pem"
  icp_private_key_file = var.icp_private_key_file != "" ? var.icp_private_key_file : "${path.module}/../deploy/icp/private_key.pem"
  icp_public_key_file  = var.icp_public_key_file != "" ? var.icp_public_key_file : "${path.module}/../deploy/icp/public_key.pem"
  icp_issuing_ca_file  = var.icp_issuing_ca_file != "" ? var.icp_issuing_ca_file : "${path.module}/../deploy/icp/issuing_ca.pem"
  icp_ca_chain_file    = var.icp_ca_chain_file != "" ? var.icp_ca_chain_file : "${path.module}/../deploy/icp/ca_chain.pem"
  namespace_path       = trimsuffix(vault_namespace.demo.path_fq, "/")

  # 365-day years. The root must outlive the intermediate it signs.
  root_ttl_seconds         = 315360000
  root_ttl                 = "87600h"
  intermediate_ttl_seconds = 157680000
  intermediate_ttl         = "43800h"
}
