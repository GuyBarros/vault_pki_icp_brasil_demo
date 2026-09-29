{{- with secret "database/creds/demo-app" -}}
{
  "username": {{ .Data.username | toJSON }},
  "password": {{ .Data.password | toJSON }},
  "lease_id": {{ .LeaseID | toJSON }},
  "lease_duration": {{ .LeaseDuration }}
}
{{- end -}}
