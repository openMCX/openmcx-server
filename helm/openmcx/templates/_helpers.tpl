{{/*
OpenMCX chart helpers.

The Services keep the names of the Docker Compose services (sip-core, idms, mcptt-server, ...): the generated
configuration (certificates, server and Kamailio configuration) names its peers by them. One release per namespace.
*/}}

{{- define "openmcx.labels" -}}
app.kubernetes.io/name: openmcx
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end }}

{{/* Selector labels of one component: (dict "root" $ "name" "idms") */}}
{{- define "openmcx.selector" -}}
app.kubernetes.io/name: openmcx
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .name }}
{{- end }}

{{/* Pod and object labels of one component; edge components (reached by the phones) carry openmcx.org/edge. */}}
{{- define "openmcx.componentLabels" -}}
{{ include "openmcx.labels" .root }}
app.kubernetes.io/component: {{ .name }}
{{- if .edge }}
openmcx.org/edge: "true"
{{- end }}
{{- end }}

{{- define "openmcx.serviceAccountName" -}}
{{- default (printf "%s-openmcx" .Release.Name) .Values.serviceAccount.name }}
{{- end }}

{{- define "openmcx.configSecret" -}}
{{- .Values.config.secretName }}
{{- end }}

{{/* The external address the phones and the browser use (HOST_IP of the tutorial). */}}
{{- define "openmcx.externalAddress" -}}
{{- required "externalAddress is required: the IPv4 address the phones reach the system on (HOST_IP)" .Values.externalAddress }}
{{- end }}

{{/*
Image of an OpenMCX program: (dict "root" $ "program" "openmcx-common" "tag" "1.0.0").
images.overrides.<program> replaces the whole reference.
*/}}
{{- define "openmcx.image" -}}
{{- $images := .root.Values.images -}}
{{- $override := get ($images.overrides | default dict) .program -}}
{{- if $override -}}
{{- $override -}}
{{- else -}}
{{- printf "%s%s:%s" $images.prefix .program (.tag | default $images.tag) -}}
{{- end -}}
{{- end }}

{{/* A Service's or pod's annotations from a map. */}}
{{- define "openmcx.annotations" -}}
{{- with . }}
annotations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}

{{/*
The parts every pod shares: service account, pull secrets, security context, placement.
(dict "root" $ "name" "sip-core" "edge" true "with" "credentials")
"edge": the pod is reached by the phones (co-located on one node, expose.nodeSelector);
"with": the component whose ReadWriteOnce volume this pod shares (scheduled on the same node).
*/}}
{{- define "openmcx.podSpec" -}}
{{- $v := .root.Values -}}
serviceAccountName: {{ include "openmcx.serviceAccountName" .root }}
enableServiceLinks: false
{{- with $v.images.pullSecrets }}
imagePullSecrets:
  {{- range . }}
  - name: {{ . }}
  {{- end }}
{{- end }}
{{- with $v.podSecurityContext }}
securityContext:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- $nodeSelector := $v.nodeSelector | default dict -}}
{{- if .edge }}
{{- $nodeSelector = merge (deepCopy ($v.expose.nodeSelector | default dict)) $nodeSelector -}}
{{- end }}
{{- with $nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with $v.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- $terms := list -}}
{{- if and .edge $v.expose.colocate (ne $v.expose.type "none") -}}
{{- $terms = append $terms (dict "labelSelector" (dict "matchLabels" (dict "app.kubernetes.io/instance" .root.Release.Name "openmcx.org/edge" "true")) "topologyKey" "kubernetes.io/hostname") -}}
{{- end -}}
{{- if and .with (eq $v.persistence.sharedAccessMode "ReadWriteOnce") -}}
{{- $terms = append $terms (dict "labelSelector" (dict "matchLabels" (dict "app.kubernetes.io/instance" .root.Release.Name "app.kubernetes.io/component" .with)) "topologyKey" "kubernetes.io/hostname") -}}
{{- end -}}
{{- if $terms }}
affinity:
  podAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      {{- toYaml $terms | nindent 6 }}
{{- else }}
{{- with $v.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}
{{- end }}

{{/* The container security context and resources of a component: (dict "root" $ "name" "idms") */}}
{{- define "openmcx.containerExtras" -}}
{{- with .root.Values.securityContext }}
securityContext:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with (get (.root.Values.resources | default dict) .name) }}
resources:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Init container waiting for TCP peers, as depends_on does in the Compose file: (dict "root" $ "peers" (list "sip-db:3306")).
The Services are headless: a name resolves once its pod is ready (or, for the SIP and Diameter peers, once it runs).
*/}}
{{- define "openmcx.waitFor" -}}
{{- if .peers }}
- name: wait-for-peers
  image: {{ .root.Values.images.wait }}
  imagePullPolicy: {{ .root.Values.images.pullPolicy }}
  command:
    - sh
    - -c
    - |
      for peer in {{ join " " .peers }}; do
        host=${peer%:*}; port=${peer##*:}
        until nc -z -w 2 "$host" "$port"; do echo "waiting for $peer"; sleep 2; done
      done
  {{- with .root.Values.securityContext }}
  securityContext:
    {{- toYaml . | nindent 4 }}
  {{- end }}
{{- end }}
{{- end }}

{{/*
A volume of the configuration Secret holding only the given keys: (dict "root" $ "name" "config" "items" (dict "key" "path")).
*/}}
{{- define "openmcx.configVolume" -}}
- name: {{ .name }}
  secret:
    secretName: {{ include "openmcx.configSecret" .root }}
    defaultMode: 0444
    items:
      {{- range $key, $path := .items }}
      - key: {{ $key }}
        path: {{ $path }}
      {{- end }}
{{- end }}

{{/* A data volume: a PersistentVolumeClaim, or an emptyDir with persistence off: (dict "root" $ "name" "gms") */}}
{{- define "openmcx.dataVolume" -}}
- name: data
  {{- if .root.Values.persistence.enabled }}
  persistentVolumeClaim:
    claimName: {{ printf "%s-%s" .root.Release.Name .name }}
  {{- else }}
  emptyDir: {}
  {{- end }}
{{- end }}

{{/* A PersistentVolumeClaim: (dict "root" $ "name" "gms" "size" "1Gi" "accessMode" "ReadWriteOnce") */}}
{{- define "openmcx.pvc" -}}
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: {{ printf "%s-%s" .root.Release.Name .name }}
  labels:
    {{- include "openmcx.labels" .root | nindent 4 }}
  {{- if .root.Values.persistence.keep }}
  annotations:
    helm.sh/resource-policy: keep
  {{- end }}
spec:
  accessModes: [{{ .accessMode | default .root.Values.persistence.accessMode }}]
  {{- with .root.Values.persistence.storageClass }}
  storageClassName: {{ if eq . "-" }}""{{ else }}{{ . }}{{ end }}
  {{- end }}
  resources:
    requests:
      storage: {{ .size }}
{{- end }}

{{/*
A headless Service named as in the Compose file: (dict "root" $ "name" "gms" "ports" (list (dict "name" "https" "port" 8443))
"notReady" true). Headless, so that the name resolves to the pod's own address: the SIP core and the MC servers
compare a peer's source address with the address its name resolves to.
*/}}
{{- define "openmcx.service" -}}
apiVersion: v1
kind: Service
metadata:
  name: {{ .name }}
  labels:
    {{- include "openmcx.componentLabels" (dict "root" .root "name" .name) | nindent 4 }}
spec:
  clusterIP: None
  publishNotReadyAddresses: {{ .notReady | default false }}
  selector:
    {{- include "openmcx.selector" (dict "root" .root "name" .name) | nindent 4 }}
  ports:
    {{- range .ports }}
    - name: {{ .name }}
      port: {{ .port }}
      targetPort: {{ .port }}
      protocol: {{ .protocol | default "TCP" }}
    {{- end }}
{{- end }}

{{/*
The edge ports of a component, reached by the phones: container ports with a name unique in the release, so that
one external Service can carry them all; with expose.type hostPort also bound on the node.
(dict "root" $ "ports" (list (dict "name" "ext-idms" "containerPort" 8443 "external" 8443 "protocol" "TCP")))
*/}}
{{- define "openmcx.edgePorts" -}}
{{- $hostPort := eq .root.Values.expose.type "hostPort" -}}
{{- range .ports }}
- name: {{ .name }}
  containerPort: {{ .containerPort }}
  protocol: {{ .protocol | default "TCP" }}
  {{- if $hostPort }}
  hostPort: {{ .external }}
  {{- end }}
{{- end }}
{{- end }}

{{/* The media ports of an MC server: (dict "base" 4000 "protocol" "UDP"), media.portsPerBase of them. */}}
{{- define "openmcx.mediaPorts" -}}
{{- $ports := list -}}
{{- range $i := until (int .count) -}}
{{- $port := add $.base $i -}}
{{- $ports = append $ports (dict "name" (printf "m%d" (int $port)) "containerPort" $port "external" $port "protocol" "UDP") -}}
{{- end -}}
{{- toYaml $ports -}}
{{- end }}
