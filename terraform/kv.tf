# The ICP-Brasil certificate is stored, not issued. An accredited AC signs the
# leaf. Vault keeps the leaf certificate, its public key, its private key, and
# the issuing CA certificate so the application can build the chain. The
# issuing CA private key is not here.

resource "vault_mount" "kv" {
  path        = local.kv_path
  type        = "kv-v2"
  description = "Stored ICP-Brasil certificate material. Vault does not issue this certificate."
}

data "external" "icp_metadata" {
  program = ["python3", "${path.module}/../deploy/icp/metadata.py"]

  query = {
    certificate = local.icp_certificate_file
  }
}

resource "vault_kv_secret_v2" "icp_brasil" {
  mount               = vault_mount.kv.path
  name                = local.icp_secret_name
  delete_all_versions = true
  data_json = jsonencode({
    certificate = file(local.icp_certificate_file)
    private_key = file(local.icp_private_key_file)
    public_key  = file(local.icp_public_key_file)
    issuing_ca  = file(local.icp_issuing_ca_file)
    ca_chain    = file(local.icp_ca_chain_file)
  })

  # Inventory fields only. The icp-metadata-reader policy can read these
  # and cannot read data_json, where the private key lives.
  custom_metadata {
    data = data.external.icp_metadata.result
  }
}
