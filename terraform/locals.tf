locals {
  tls_root_path = "pki_root"
  tls_int_path  = "pki_int"
  icp_root_path = "pki_icp_root"
  icp_int_path  = "pki_icp"

  tls_role_name     = "demo-server"
  icp_role_name     = "a1-pessoa-fisica"
  database_path     = "database"
  database_role     = "demo-app"
  policy_name       = "demo-app"
  approle_name      = "demo-app"
  kubernetes_role   = "demo-app"
  approle_auth_path = "approle"
  kubernetes_path   = "kubernetes"

  # 365-day years. The root must outlive the intermediate it signs.
  root_ttl_seconds         = 315360000
  root_ttl                 = "87600h"
  intermediate_ttl_seconds = 157680000
  intermediate_ttl         = "43800h"
}
