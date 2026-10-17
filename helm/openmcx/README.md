# Helm chart: OpenMCX on Kubernetes and OpenShift

The chart deploys a complete OpenMCX system: the MCPTT, MCData and MCVideo servers, the common services, the SIP
core and MCX Admin. It runs what
[tutorial 1](../../tutorials/end-to-end/01-mcx-over-wlan-android/README.md)'s Compose file runs, one pod per
Compose service, from the same images and with the same configuration. Android phones (the OpenMCX app) and a browser
reach it on one address, `externalAddress`, the tutorial's `HOST_IP`.

> **Status: experimental** (in release 1.0.0 as such). [Tutorial 6](../../tutorials/end-to-end/06-mcx-over-oai-5g-kubernetes/README.md)
> installs it on a one-node kind cluster (Kubernetes 1.37, Helm 4), with the OAI 5G core next to it: the
> configuration Job, the hostPorts, the SIP core's address checks and N5 work there. It has not yet run on a cluster of
> several nodes, with `LoadBalancer` or `NodePort`, or on OpenShift.

## What it deploys

| Pod (and Service name) | Image | Reached by the phones on `externalAddress` |
|---|---|---|
| `sip-db` (StatefulSet) | `mysql` (digest of the Compose file) | |
| `sip-core` | `openmcx-kamailio` | 5061/tcp (SIP over TLS) |
| `idms`, `gms`, `cms`, `kms`, `lms`, `credentials`, `content-server`, `message-store`, `notification-server` | `openmcx-common` | `idms` 8443, `kms` 8445, `credentials` 8447 (tcp) |
| `http-proxy` | `openmcx-http-proxy` | 8444/tcp |
| `mcx-user-db` | `openmcx-user-db` | |
| `mcptt-server` | `openmcx-mcptt-server` | 4000-4099/udp (speech), 5000-5099/udp (floor control) |
| `mcdata-server` (`mcdata.enabled`) | `openmcx-mcdata-server` | |
| `mcvideo-server` (`mcvideo.enabled`) | `openmcx-mcvideo-server` | 7000-7099, 7200-7299, 7400-7499/udp |
| `mcxadmin` | `openmcx-admin` | 8446/tcp (console and activation) |

Images: `<images.prefix>openmcx-<program>:<images.tag>` (default `openmcx/…:1.0.0` from Docker Hub, MCX Admin and Kamailio included);
`images.overrides` replaces single references.

The Services keep the Compose names, because the generated configuration (certificates, server, Kamailio and
Diameter configuration) names the peers by them. Therefore: **one release per namespace**. The Services are headless:
the SIP core and the MC servers compare a peer's source address with the address its name resolves to, which with a
ClusterIP would be the Service's address, not the pod's.

Each MC server uses 100 ports from each media base (50 pairs, `src/server/server.hpp`); the Compose file publishes 200.
The chart exposes 100 (`expose.media.portsPerBase`).

## Requirements

- Kubernetes 1.26 or later (one Service with TCP and UDP ports), or OpenShift 4.
- Helm 3.
- **SCTP** on the nodes: the MCPTT server and the MCPTT user database speak Diameter over SCTP (TS 29.380). Most
  distributions load the `sctp` kernel module on demand; OpenShift needs it enabled (below). The Services carrying
  SCTP are headless, so kube-proxy is not involved, only the CNI.
- A StorageClass with ReadWriteOnce volumes (the cluster's default unless `persistence.storageClass` is set).
- The phones reach `externalAddress` directly, without NAT: the SIP core checks that a phone's SDP address is the
  source address of its connection, as in the tutorial.

## Tutorial 1 on Kubernetes

A one-node cluster on the computer that shares the Wi-Fi with the phones (k3s, MicroK8s and similar, whose CNI
supports `hostPort`; or kind, whose node publishes the ports: tutorial 6's
[`kind-cluster.sh`](../../tutorials/end-to-end/06-mcx-over-oai-5g-kubernetes/kind-cluster.sh) makes one):

```bash
helm install openmcx helm/openmcx -n openmcx --create-namespace \
    -f helm/openmcx/examples/tutorial-1-wlan-android.yaml --set externalAddress=<HOST_IP>
kubectl -n openmcx get pods -w                      # every pod ready after a minute or two; mcptt-server last
kubectl -n openmcx get secret openmcx-config -o jsonpath='{.data.ADMIN\.txt}' | base64 -d
```

Then continue with the tutorial's README at step 4 (open MCX Admin at `https://<HOST_IP>:8446/`, create alice and
bob from the template `phone-user`, activate the phones). The ports on `HOST_IP` are the tutorial's, so its firewall
notes apply. `externalAddress` is the node's address on the Wi-Fi.

## How the phones reach the system: `expose.type`

| `expose.type` | What it makes | `externalAddress` |
|---|---|---|
| `hostPort` (default) | The edge pods bind their ports on their node, as `docker compose` publishes them. | The node's address. In a cluster of several nodes, pin the edge pods with `expose.nodeSelector`. |
| `LoadBalancer` | One Service `openmcx-external` of type LoadBalancer (MetalLB, a cloud) with every port; `spec.loadBalancerIP` is `externalAddress`. | The Service's address. |
| `NodePort` | The same Service as NodePort. Every port must be in the NodePort range: the servers announce their own media ports in SDP, so `nodePort` = port = container port. See `examples/nodeport.yaml`. | A node's address. |
| `none` | Nothing external (tests inside the cluster). | Still written into the configuration. |

The edge pods (SIP core, IdMS, HTTP proxy, KMS, Credential Service, MCX Admin, MCPTT and MCVideo servers) run on one
node (`expose.colocate`): the external traffic keeps the phone's source address (`externalTrafficPolicy: Local`),
and such traffic only reaches pods on the node that receives it. In the external Service each port targets a
container port name that only one edge pod has (`ext-sip`, `ext-idms`, …, `m4000`, …), so one address carries all
components. Cloud load balancers often limit the number of ports per Service (about 500 here with MCVideo), so
MetalLB, `hostPort` or `NodePort` suit better.

Ports other than the tutorial's (`expose.ports`, `expose.media`) are written into the configuration by the setup Job:
MCX Admin's activation codes and console, IdMS's links, the servers' SDP.

## The configuration

Every pod reads its files from one Secret (`config.secretName`, default `openmcx-config`): a new CA and the
servers' certificates, the users and groups, the configuration of every server and MCX Admin, the database passwords,
the CA key the Credential Service signs device certificates with. Protect the namespace accordingly.

**Generated** (`config.generate: true`, default): before install and upgrade, a Job runs the tutorial's setup
(`openmcx-setup` image, `/opt/tutorials/configure.py`) for `externalAddress` and stores the result in the Secret,
when the Secret does not exist. The Secret is not part of the release: it outlives `helm uninstall`, so that a
reinstall keeps the CA the activated phones trust. If it was made for another address, the Job fails and says so.
The script is [files/openmcx-config.py](files/openmcx-config.py).

**From a directory** (`config.generate: false`): a tutorial's `./config`, written by its setup container and not yet
used by a running system (a used directory holds files only root reads):

```bash
docker compose -f tutorials/end-to-end/01-mcx-over-wlan-android/docker-compose-basic-mcx.yaml run --rm setup
python3 helm/openmcx/files/openmcx-config.py \
    --from-dir tutorials/end-to-end/01-mcx-over-wlan-android/config --namespace openmcx | kubectl apply -f -
helm install openmcx helm/openmcx -n openmcx --set config.generate=false --set externalAddress=<HOST_IP>
```

**Start over** with a new system (new CA: the phones must be activated again):

```bash
helm uninstall openmcx -n openmcx
kubectl -n openmcx delete secret openmcx-config
kubectl -n openmcx delete pvc -l app.kubernetes.io/instance=openmcx       # users, groups, messages, MySQL
```

The setup's certificates last 30 days, as in the tutorial.

## Persistence

Each service with data has a PersistentVolumeClaim `<release>-<name>` (MySQL: `data-sip-db-0`), as the Compose file's
volumes; `persistence.enabled: false` uses emptyDir. Two claims are shared by two pods and always exist: the device
CRL (`<release>-crl`: the Credential Service writes it, the SIP core reads it) and the users' projection
(`<release>-userdb`: MCX Admin writes it, the MCPTT user database reads it). With
`persistence.sharedAccessMode: ReadWriteOnce` each pair is scheduled on one node; `ReadWriteMany` lifts that.
`persistence.keep: true` keeps the claims on uninstall.

## OpenShift

1. **Security context constraints.** The OpenMCX images and MySQL run as root (as with Docker), and `hostPort` binds
   host ports. With `openshift.enabled: true` the chart creates a SecurityContextConstraints for the release's service
   account that allows any user ID and, for `hostPort`, host ports, and nothing else (no privileged containers, no host
   network or paths). Installing it needs cluster-admin. Without it (`openshift.scc.create: false`), bind the service
   account `<release>-openmcx` to an SCC yourself, e.g. `oc adm policy add-scc-to-user anyuid -z openmcx-openmcx`
   (`anyuid` has no host ports: use `LoadBalancer` then). The setup Job runs under `restricted-v2`.
2. **SCTP.** Enable the module on the workers (the nodes reboot):

   ```yaml
   apiVersion: machineconfiguration.openshift.io/v1
   kind: MachineConfig
   metadata:
     name: load-sctp-module
     labels:
       machineconfiguration.openshift.io/role: worker
   spec:
     config:
       ignition:
         version: 3.2.0
       storage:
         files:
           - path: /etc/modprobe.d/sctp-blacklist.conf
             mode: 0644
             overwrite: true
             contents:
               source: data:,
           - path: /etc/modules-load.d/sctp-load.conf
             mode: 0644
             overwrite: true
             contents:
               source: data:,sctp
   ```

3. **Exposure.** `LoadBalancer` with the MetalLB operator ([examples/openshift-metallb.yaml](examples/openshift-metallb.yaml)),
   or `hostPort` with `expose.nodeSelector` on one worker. Routes do not fit: the phones use SIP over TLS and UDP media,
   and reach the HTTPS services by address and port from their activation code.

```bash
oc new-project openmcx
helm install openmcx helm/openmcx -n openmcx \
    -f helm/openmcx/examples/openshift-metallb.yaml --set externalAddress=<address from the MetalLB pool>
```

## Values

| Value | Default | |
|---|---|---|
| `externalAddress` | (required) | IPv4 address of the system for the phones and the browser. |
| `images.prefix`, `images.tag` | `openmcx/`, `1.0.0` | `<prefix>openmcx-<program>:<tag>`, every program. |
| `images.overrides` | `{}` | A whole reference per program, e.g. `openmcx-mcptt-server: reg/x:1`. |
| `images.mysql`, `images.wait` | MySQL digest, `busybox:1.36.1` | Database; the init containers that wait for peers. |
| `images.pullSecrets` | `[]` | Image pull Secret names. |
| `config.secretName` | `openmcx-config` | The configuration Secret. |
| `config.generate` | `true` | Make it with the setup Job when it does not exist. |
| `expose.type` | `hostPort` | `hostPort`, `LoadBalancer`, `NodePort` or `none`. |
| `expose.colocate`, `expose.nodeSelector` | `true`, `{}` | Edge pods on one node; which node. |
| `expose.service.*` | | Annotations, `loadBalancerClass`, `loadBalancerIP` of the external Service. |
| `expose.ports.*` | 5061, 8443-8447 | `sip`, `idms`, `httpProxy`, `kms`, `admin`, `credentials`. |
| `expose.media.*` | 4000/5000, 7000/7200/7400 | First port of each media range; `portsPerBase` 100. |
| `sipCore.tlsKeylog` | `false` | Troubleshooting only: the SIP core writes its TLS secrets to `/tmp/kamailio-tls-keylog.txt`, for Wireshark to decrypt a capture; tutorial 6, step 7. Never in production. |
| `mcptt.pcf` | `{}` | The MCPTT server's N5 block (`pcf` of `mcptt-server.json`, [POLICY.md](../../docs/POLICY.md)), written by the setup Job; tutorial 6 sets it. |
| `mcdata.enabled`, `mcvideo.enabled` | `true` | The MCData and MCVideo servers. |
| `persistence.*` | enabled, RWO | `storageClass`, `accessMode`, `sharedAccessMode`, `keep`, `sizes.<volume>`. |
| `openshift.enabled`, `openshift.scc.create` | `false`, `true` | The chart's SecurityContextConstraints. |
| `nodeSelector`, `tolerations`, `affinity` | | Every pod. |
| `podSecurityContext`, `securityContext` | `{}` | Every pod and container. |
| `resources.<component>` | `{}` | Per component (`sip-core`, `mcptt-server`, …). |

## Limits

- One replica per component, as in the Compose file; the MC servers keep call state in memory.
- One release per namespace (fixed Service names).
- WLAN, as tutorial 1, unless `mcptt.pcf` is set: then the MCPTT server asks a 5G core's PCF for its UEs' QoS over N5,
  as in tutorial 6. No Rx (4G) or network location from a core.
- The images run as root; running them under OpenShift's `restricted-v2` (random user ID) has not been tried.
