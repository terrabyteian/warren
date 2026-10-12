{{- define "warren.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* The release's base name; each role's objects add -control-plane, -relay or -connector. */}}
{{- define "warren.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 45 | trimSuffix "-" }}
{{- else if contains (include "warren.name" .) .Release.Name }}
{{- .Release.Name | trunc 45 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "warren.name" .) | trunc 45 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "warren.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "warren.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: warren
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/* Selector labels for one role: (dict "root" $ "role" "relay"). */}}
{{- define "warren.selectorLabels" -}}
app.kubernetes.io/name: {{ include "warren.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .role }}
{{- end }}

{{/*
A role's pod template labels, each key once: (dict "root" $ "role" "relay"
"podLabels" .Values.relay.podLabels). The selector labels win over podLabels,
and podLabels over the common labels.
*/}}
{{- define "warren.podLabels" -}}
{{- $selector := include "warren.selectorLabels" (dict "root" .root "role" .role) | fromYaml }}
{{- $common := include "warren.labels" .root | fromYaml }}
{{- toYaml (merge $selector (.podLabels | default dict) $common) }}
{{- end }}

{{/* An image reference: (dict "image" .Values.image "root" $). */}}
{{- define "warren.image" -}}
{{- $tag := default .root.Chart.AppVersion .image.tag -}}
{{- if .image.digest -}}
{{ .image.repository }}@{{ .image.digest }}
{{- else -}}
{{ .image.repository }}:{{ $tag }}
{{- end -}}
{{- end }}

{{- define "warren.bundleConfigMap" -}}
{{- printf "%s-bundle" (include "warren.fullname" .) }}
{{- end }}

{{/* Fails the render unless what relays and connectors need is set. */}}
{{- define "warren.requireBundle" -}}
{{- if not .Values.nodes.bundle }}
{{- fail "nodes.bundle is required when a relay or connector is enabled" }}
{{- end }}
{{- end }}

{{/* A restricted container security context for the nonroot roles. */}}
{{- define "warren.restrictedContainer" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
capabilities:
  drop: [ALL]
{{- end }}

{{- define "warren.restrictedPod" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
fsGroup: 65532
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{/* A volume's claim template or claim spec: (dict "p" .Values.relay.persistence). */}}
{{- define "warren.claimSpec" -}}
accessModes:
{{- toYaml .p.accessModes | nindent 2 }}
{{- with .p.storageClass }}
storageClassName: {{ if eq . "-" }}""{{ else }}{{ . }}{{ end }}
{{- end }}
resources:
  requests:
    storage: {{ .p.size }}
{{- end }}

{{/* Scheduling and pod metadata shared by every role: (dict "v" .Values.relay). */}}
{{- define "warren.scheduling" -}}
{{- with .v.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .v.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .v.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}
