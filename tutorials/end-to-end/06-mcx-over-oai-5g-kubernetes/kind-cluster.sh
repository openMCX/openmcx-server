#!/bin/sh
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

# Tutorial 6: the one-node kind cluster (Kubernetes in Docker) the tutorial runs on.
#
#   ./kind-cluster.sh create     a cluster "openmcx" whose node publishes the phones' ports on this computer
#   ./kind-cluster.sh delete     the cluster and everything in it
#
# The node publishes the ports the phones use on HOST_IP, as tutorial 3's Compose file does: SIP over TLS (5061),
# IdMS, HTTP proxy, KMS, MCX Admin and Credential Service (8443-8447), and the MCPTT and MCVideo servers' media
# (UDP 4000-4099, 5000-5099, 7000-7099, 7200-7299, 7400-7499). The OpenMCX chart binds them in the node (hostPort).
set -eu
NAME=openmcx
NODE_IMAGE=kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5

config() {
  echo 'kind: Cluster'
  echo 'apiVersion: kind.x-k8s.io/v1alpha4'
  echo 'nodes:'
  echo '- role: control-plane'
  echo '  extraPortMappings:'
  for port in 5061 8443 8444 8445 8446 8447; do
    echo "  - {containerPort: $port, hostPort: $port, protocol: TCP}"
  done
  for base in 4000 5000 7000 7200 7400; do
    port=$base
    while [ "$port" -lt $((base + 100)) ]; do
      echo "  - {containerPort: $port, hostPort: $port, protocol: UDP}"
      port=$((port + 1))
    done
  done
}

case "${1:-}" in
  create) config | kind create cluster --name "$NAME" --image "$NODE_IMAGE" --config - ;;
  delete) kind delete cluster --name "$NAME" ;;
  config) config ;;
  *) sed -n '6,14p' "$0"; exit 1 ;;
esac
