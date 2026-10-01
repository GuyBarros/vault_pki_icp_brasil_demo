{{- with secret "kv/data/icp-brasil" -}}
{
  "certificate": {{ .Data.data.certificate | toJSON }},
  "private_key": {{ .Data.data.private_key | toJSON }},
  "public_key": {{ .Data.data.public_key | toJSON }},
  "issuing_ca": {{ .Data.data.issuing_ca | toJSON }},
  "ca_chain": {{ .Data.data.ca_chain | toJSON }}
}
{{- end -}}
