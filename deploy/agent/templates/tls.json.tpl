{{- with secret "pki_int/issue/demo-server" "common_name=demo.vault.local" "alt_names=localhost" "ip_sans=127.0.0.1" "ttl=72h" -}}
{
  "certificate": {{ .Data.certificate | toJSON }},
  "private_key": {{ .Data.private_key | toJSON }},
  "issuing_ca": {{ .Data.issuing_ca | toJSON }},
  "ca_chain": {{ if .Data.ca_chain }}{{ .Data.ca_chain | toJSON }}{{ else }}null{{ end }},
  "serial_number": {{ .Data.serial_number | toJSON }},
  "expiration": {{ .Data.expiration }}
}
{{- end -}}
