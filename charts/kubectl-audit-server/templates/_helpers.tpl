{{- define "kubectl-audit-server.name" -}}
{{- .Chart.Name -}}
{{- end -}}

{{- define "kubectl-audit-server.fullname" -}}
{{- .Release.Name -}}
{{- end -}}

{{- define "kubectl-audit-server.labels" -}}
app.kubernetes.io/name: {{ include "kubectl-audit-server.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "kubectl-audit-server.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kubectl-audit-server.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "kubectl-audit-server.cnpgClusterName" -}}
{{- printf "%s-postgres" (include "kubectl-audit-server.fullname" .) -}}
{{- end -}}

{{/*
adminTokenSecretName is this chart's own generated Secret name — only
relevant when adminToken.existingSecretName is unset.
*/}}
{{- define "kubectl-audit-server.adminTokenSecretName" -}}
{{- printf "%s-admin-token" (include "kubectl-audit-server.fullname" .) -}}
{{- end -}}

{{/*
databaseURLSecretRef renders a secretKeyRef pointing at whichever Secret
actually holds the DATABASE_URL-shaped value — CNPG's own "<name>-app"
Secret (its `uri` key) by default, or postgres.existingSecretName/
existingSecretKey when CNPG is disabled. externalDSN (a plain value, not a
secretKeyRef) is handled separately by the caller — see deployment.yaml.
*/}}
{{- define "kubectl-audit-server.databaseURLSecretRef" -}}
{{- if .Values.postgres.cnpg.enabled -}}
name: {{ printf "%s-app" (include "kubectl-audit-server.cnpgClusterName" .) }}
key: uri
{{- else -}}
name: {{ .Values.postgres.existingSecretName }}
key: {{ .Values.postgres.existingSecretKey }}
{{- end -}}
{{- end -}}
