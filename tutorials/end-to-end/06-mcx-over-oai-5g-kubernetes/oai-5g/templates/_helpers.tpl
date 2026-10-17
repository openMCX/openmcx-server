{{/*
Tutorial 6's 5G network: helpers. The Services keep the names of tutorial 3's Compose services (oai-amf, oai-pcf,
...), which the OAI configuration and the OpenMCX configuration use.
*/}}

{{- define "oai5g.labels" -}}
app.kubernetes.io/name: oai-5g
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
app.kubernetes.io/component: {{ .name }}
helm.sh/chart: {{ printf "%s-%s" .root.Chart.Name .root.Chart.Version }}
{{- end }}

{{- define "oai5g.selector" -}}
app.kubernetes.io/name: oai-5g
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .name }}
{{- end }}

{{- define "oai5g.externalAddress" -}}
{{- required "externalAddress is required: HOST_IP, the openmcx chart's externalAddress" .Values.externalAddress }}
{{- end }}

{{/*
A headless Service: the name resolves to the pod's address, as a Compose service name does.
(dict "root" $ "name" "oai-amf" "notReady" true "ports" (list (dict "name" "sbi" "port" 8080)))
*/}}
{{- define "oai5g.service" -}}
apiVersion: v1
kind: Service
metadata:
  name: {{ .name }}
  labels:
    {{- include "oai5g.labels" . | nindent 4 }}
spec:
  clusterIP: None
  publishNotReadyAddresses: {{ .notReady | default false }}
  selector:
    {{- include "oai5g.selector" . | nindent 4 }}
  ports:
    {{- range .ports }}
    - name: {{ .name }}
      port: {{ .port }}
      targetPort: {{ .port }}
      protocol: {{ .protocol | default "TCP" }}
    {{- end }}
{{- end }}

{{/* Init container waiting for TCP peers, as depends_on in the Compose file: (dict "root" $ "peers" (list "oai-nrf:8080")) */}}
{{- define "oai5g.waitFor" -}}
{{- if .peers }}
- name: wait-for-peers
  image: {{ .root.Values.images.tools }}
  imagePullPolicy: {{ .root.Values.images.pullPolicy }}
  command:
    - sh
    - -c
    - |
      for peer in {{ join " " .peers }}; do
        host=${peer%:*}; port=${peer##*:}
        until nc -z -w 2 "$host" "$port"; do echo "waiting for $peer"; sleep 2; done
      done
{{- end }}
{{- end }}
