{{/*
Common labels applied to every resource in the chart.
*/}}
{{- define "jso-protector.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Name of the Secret holding JSO_API_KEY / JSO_API_PASSWORD. When the user
points us at an existing Secret we reuse it; otherwise we create one
named after the release.
*/}}
{{- define "jso-protector.secretName" -}}
{{- if .Values.credentials.existingSecret -}}
{{ .Values.credentials.existingSecret }}
{{- else -}}
{{ .Release.Name }}-credentials
{{- end -}}
{{- end }}
