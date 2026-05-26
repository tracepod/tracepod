{{- define "tracepod.sensorName" -}}{{ .Release.Name }}-sensor{{- end -}}

{{- define "tracepod.sensorLabels" -}}
app.kubernetes.io/name: tracepod-sensor
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
