{{- /* Lab identity. Keep this request aligned with deploy/nomad/demo.nomad.hcl and deploy/kubernetes/secrets.yaml. */ -}}
{{- with secret "pki_icp/issue/a1-pessoa-fisica" "common_name=MARIA OLIVEIRA DEMO" "alt_names=maria.oliveira@demo.vault.local" "other_sans=2.16.76.1.3.1;utf8:11144477735" "exclude_cn_from_sans=true" "ttl=72h" -}}
{
  "certificate": {{ .Data.certificate | toJSON }},
  "private_key": {{ .Data.private_key | toJSON }},
  "issuing_ca": {{ .Data.issuing_ca | toJSON }},
  "ca_chain": {{ if .Data.ca_chain }}{{ .Data.ca_chain | toJSON }}{{ else }}null{{ end }},
  "serial_number": {{ .Data.serial_number | toJSON }},
  "expiration": {{ .Data.expiration }}
}
{{- end -}}
