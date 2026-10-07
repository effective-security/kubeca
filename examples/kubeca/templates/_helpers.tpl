{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "kubeca.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "kubeca.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "kubeca.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Selector labels
*/}}
{{- define "kubeca.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kubeca.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: {{ include "kubeca.name" . }}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "kubeca.labels" -}}
helm.sh/chart: {{ include "kubeca.chart" . }}
{{ include "kubeca.selectorLabels" . }}
{{- if .Values.image.tag }}
app.kubernetes.io/version: {{ .Values.image.tag | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Create the name of the service account to use
*/}}
{{- define "kubeca.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
    {{ default (include "kubeca.fullname" .) .Values.serviceAccount.name }}
{{- else -}}
    {{ default "default" .Values.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{/*
Name of the Secret with the issuing CA files
*/}}
{{- define "kubeca.certsSecretName" -}}
{{- default (printf "%s-certs-secret-tf" (include "kubeca.fullname" .)) .Values.certs.secretName -}}
{{- end -}}

{{/*
Name of the MutatingWebhookConfiguration the operator patches (cluster-scoped,
so it carries the release name)
*/}}
{{- define "kubeca.webhookConfigName" -}}
{{- printf "%s-pod-injector" (include "kubeca.fullname" .) -}}
{{- end -}}
