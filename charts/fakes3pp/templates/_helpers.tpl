{{/*
Expand the name of the chart.
*/}}
{{- define "fakes3pp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "fakes3pp.fullnameS3" -}}
{{- if .Values.fullnameOverrideS3 }}
  {{- .Values.fullnameOverrideS3 | trunc 63 | trimSuffix "-" }}
{{- else }}
  {{- $name := default .Chart.Name .Values.s3.nameOverride }}
  {{- printf "s3-%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "fakes3pp.fullnameSTS" -}}
{{- if .Values.fullnameOverrideSTS }}
  {{- .Values.fullnameOverrideSTS | trunc 63 | trimSuffix "-" }}
{{- else }}
  {{- $name := default .Chart.Name .Values.sts.nameOverride }}
  {{- if contains $name .Release.Name }}
    {{- .Release.Name | trunc 63 | trimSuffix "-" }}
  {{- else }}
    {{- printf "sts-%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
  {{- end }}
{{- end }}
{{- end }}


{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "fakes3pp.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}

{{- define "fakes3pp.labelsShared" -}}
helm.sh/chart: {{ include "fakes3pp.chart" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "fakes3pp.labelsS3" -}}
{{ include "fakes3pp.labelsShared" . }}
{{ include "fakes3pp.selectorLabelsS3" . }}
{{- end }}


{{- define "fakes3pp.labelsSTS" -}}
{{ include "fakes3pp.labelsShared" . }}
{{ include "fakes3pp.selectorLabelsSTS" . }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "fakes3pp.selectorLabelsS3" -}}
app.kubernetes.io/name: {{ include "fakes3pp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
awsComponent: "s3"
{{- end }}
{{- define "fakes3pp.selectorLabelsSTS" -}}
app.kubernetes.io/name: {{ include "fakes3pp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
awsComponent: "sts"
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "fakes3pp.serviceAccountNameSTS" -}}
{{- if .Values.sts.serviceAccount.create }}
{{- default (include "fakes3pp.fullnameSTS" .) .Values.sts.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.sts.serviceAccount.name }}
{{- end }}
{{- end }}
{{/*
Create the name of the service account to use
*/}}
{{- define "fakes3pp.serviceAccountNameS3" -}}
{{- if .Values.s3.serviceAccount.create }}
{{- default (include "fakes3pp.fullnameS3" .) .Values.s3.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.s3.serviceAccount.name }}
{{- end }}
{{- end }}
