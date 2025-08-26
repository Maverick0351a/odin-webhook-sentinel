{{- define "sentinel.name" -}}
{{ .Chart.Name }}
{{- end -}}

{{- define "sentinel.fullname" -}}
{{ .Release.Name | default .Chart.Name }}
{{- end -}}

{{- define "sentinel.chart" -}}
{{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}
