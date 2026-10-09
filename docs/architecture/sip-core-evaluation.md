# Choosing the SIP core for openMCX: Kamailio, OpenSIPS, Asterisk and FreeSWITCH

Research date: 2026-09-20 (Kamailio and OpenSIPS); comparison with Asterisk and
FreeSWITCH added 2026-10-09. Status: source-based architecture recommendation;
none of the candidates has been benchmarked in this repository. Kamailio 6.1.4 has
since been built and is the SIP core of every openMCX lab and tutorial.

## Recommendation

Use **Kamailio** for the MCPTT-only Phase 1 SIP core. Start qualification with
[release 6.1.4](https://www.kamailio.org/w/2026/08/kamailio-v6-1-4-released/),
then freeze its source commit, build dependencies and image digest after testing.

The deciding factor is application-server integration. Kamailio provides a
documented [ISC module](https://www.kamailio.org/docs/modules/6.1.x/modules/ims_isc.html)
for matching initial filter criteria on registration and other requests and
routing to a SIP AS. OpenSIPS offers a capable general SIP core, but its current
[IMS Community Edition S-CSCF configuration](https://github.com/OpenSIPS/opensips-ims-ce/blob/main/docs/scscf.md)
documents `SERVICE` and `APPLICATION` routing destinations as not handled. That
is a limitation of the published CE configuration, not proof that OpenSIPS cannot
implement application-server routing.

The recommendation is an integration-risk judgment: Kamailio offers more directly
reusable IMS service-selection machinery. It is not a performance ranking or a
claim of Release 19 MCPTT compliance.

## Fit to the required architecture

The supplied TS 23.280 V19.10.1 §7.4.3.1.3.1 permits non-IMS internals when
exposed reference points meet their specified compatibility requirements.
Section 7.4.3.1.3.3 allows omitting the registrar finder with one registrar.
Therefore Phase 1 can use one compact `sip-core` deployment with proxy,
registration and application-selection responsibilities. A complete P-CSCF /
I-CSCF / S-CSCF deployment is not automatically required by IP transport.

SIP-1 remains the profiled Gm relationship and SIP-2 the ISC/Ma relationship.
Generic SIP REGISTER and INVITE support is insufficient evidence for either.
The exact registration, identity, service-selection, security and event behaviour
must be derived from the selected MCPTT procedures and reference-point profile.

The MCPTT application server is a separate deployment. SIP-core routing does not
implement affiliation, controlling/participating roles, floor arbitration, media
distribution, group authorization, key distribution or speech encoding. Reusing
an RTP relay also does not supply those application behaviours.

## Capability comparison

| Criterion | Kamailio | OpenSIPS | Decision consequence |
|---|---|---|---|
| Base SIP core | Registrar, proxy, transactions, routing and subscriber storage | Registrar, proxy, transactions, routing and subscriber storage | Both are plausible; no measured capacity advantage asserted |
| IMS registration | Released IMS registrar/usrloc and authentication modules in the [6.1.x module set](https://www.kamailio.org/docs/modules/6.1.x/) | Published Dockerized P-/I-/S-CSCF deployment in [IMS CE](https://github.com/OpenSIPS/opensips-ims-ce) | Kamailio offers established module boundaries; both need procedure-level qualification |
| AS selection | `ims_isc` provides iFC matching and AS routing | CE's documented service/application routing needs additional work | Main reason to prefer Kamailio for this project |
| Subscriber and Diameter integration | [IMS I-CSCF](https://www.kamailio.org/docs/modules/6.1.x/modules/ims_icscf.html), [S-CSCF registrar](https://www.kamailio.org/docs/modules/6.1.x/modules/ims_registrar_scscf.html), `cdp` and `cdp_avp` provide relevant building blocks | [Diameter support](https://docs.opensips.org/tutorials/diameter-aaa/) and CE's documented Cx subsets | Qualify the actual subscription/profile path; neither automatically supplies MCPTT-2 under TS 29.283 |
| Call-leg control | Keep project-owned MCPTT SIP-AS states behind SIP-2 | [B2BUA framework](https://docs.opensips.org/tutorials/b2bua/) can assist generic call-leg handling | OpenSIPS has a useful option, but MCPTT procedures still require implementation |
| SIP access protection | TLS and [IMS IPsec module](https://www.kamailio.org/docs/modules/6.1.x/modules/ims_ipsec_pcscf.html) | TLS, [AKA](https://docs.opensips.org/modules/3-6/auth_aka/) and [IPsec](https://docs.opensips.org/manual/3-6/modules/proto_ipsec/) facilities | Select protection from the normative profile; do not infer TS 33.180 compliance from module availability |
| HTTP integration | HTTP utility modules | HTTP/REST utility modules | Neither replaces the common-service entities or their protocols |
| Docker packaging | [Official container sources](https://github.com/kamailio/kamailio-docker) and versioned SIP-server releases | CE provides Compose/configuration examples | Verify included modules and build pins; sample image tags are not reproducibility evidence |
| Operations | RPC, tracing, statistics and metrics modules | MI/CLI, tracing, statistics and metrics modules | Both can support readiness and evidence collection; integration tests decide |
| Licensing boundary | [Project licensing](https://github.com/kamailio/kamailio#license) and container-repository licensing must be recorded per component | [Core licence](https://github.com/OpenSIPS/opensips/blob/master/COPYING) and CE repository licence are separate inputs | Record exact dependency licences when choosing distributable images |

OpenSIPS is preferable if the team already has a qualified OpenSIPS service-AS
integration or the planned B2BUA framework substantially reduces verified MCPTT
application work. No such existing integration is present in this repository.
Re-evaluate the choice if the same protocol suite demonstrates that advantage.

## PBX and media servers: Asterisk and FreeSWITCH

Asterisk and FreeSWITCH are often named as open-source SIP servers. They were not
candidates in the comparison above because they fill a different role: both are
back-to-back user agents (B2BUA) that end each call on one side and start a new
one on the other, and both handle the media (mixing, transcoding, recording). The
SIP core in front of the MC servers is a proxy role: it routes and forwards
requests and leaves the dialog and the media between the MC client and the MC
server.

| What openMCX needs from the SIP core | Kamailio | OpenSIPS | Asterisk | FreeSWITCH |
|---|---|---|---|---|
| Licence | GPL-2.0 (some modules BSD) | GPL-2.0 | GPL-2.0; commercial licences from Sangoma | MPL 1.1 |
| Kind of server | SIP proxy and registrar | SIP proxy and registrar (B2BUA module optional) | PBX, B2BUA | Softswitch, B2BUA, media server |
| One end-to-end dialog from MC client to MC server | Fits (proxy) | Fits (proxy) | Does not fit: two dialogs per call | Does not fit: two dialogs per call |
| MCPTT signalling passed on unchanged (`application/vnd.3gpp.mcptt-info+xml`, Accept-Contact feature tags, P-Asserted-Identity, Resource-Priority) | Fits: a proxy forwards the request | Fits: a proxy forwards the request | Possible with work: each header and body copied between the two dialogs | Possible with work: as Asterisk |
| IMS CSCF behaviour (TS 24.229) | Fits: P-, I- and S-CSCF modules, Diameter (`cdp`) | Fits: IMS Community Edition | Does not fit: not a CSCF | Does not fit: not a CSCF |
| Hand requests to the MC server as application server | Fits: `ims_isc` (iFC), or script routing as used today | Possible with work: CE service/application routing documented as not handled | Does not fit: it is itself the endpoint | Does not fit: it is itself the endpoint |
| Media | Fits: not touched; the MCPTT server relays media under floor control (TS 24.380) | Fits: not touched | Does not fit: a second media layer beside the MC servers | Does not fit: as Asterisk |
| Mutual TLS with verified peer certificates | Fits (`tls`) | Fits | Fits | Fits |
| RFC 5626 outbound flows | Fits (registrar, `nathelper`) | Fits | Possible with work | Possible with work |
| Footprint of a distributable image | Fits: only the modules needed are built | Fits | Large: PBX applications and codecs | Large: media modules |
| Remote control (MCX Admin, dashboard) | Fits (`xhttp`, `jsonrpcs`) | Fits (MI) | Fits (AMI, ARI) | Fits (Event Socket) |

"Possible with work" means the feature exists or can be added but needs project
work or qualification for this role; no capacity or performance comparison is
asserted.

Using Asterisk or FreeSWITCH as the MC server itself was not chosen either. They
supply SIP call legs, conferencing and media, but none of the MC service: floor
control (TS 24.380), affiliation, group and private call procedures, priority and
emergency handling, MCX service authorisation, MIKEY-SAKKE key distribution and
XML protection would all remain to be written on top of a PBX call model. openMCX
implements these in its own MCPTT, MCVideo and MCData servers.

## How Kamailio fits openMCX as built

- **Proxy role.** The client's request reaches the participating function as the
  client sent it, so the MC server, not the SIP core, applies TS 24.379 / 24.281 /
  24.282.
- **Media stays in the MC servers.** MCPTT media is not mixed: one talker at a time
  is relayed under floor control. A proxy that never touches RTP leaves that to the
  MCPTT server.
- **MCX rules are configuration.** `docker/kamailio.cfg` enforces mutual TLS with a
  verified peer certificate, the From identity of the authenticated user, routing
  of client requests only to the MC servers ("Route forbidden" otherwise), the
  sender's own address in a client's SDP, and RFC 5626 flows. The same image with
  another configuration is a plain registrar and proxy.
- **Small, reproducible image.** `docker/Dockerfile.kamailio` builds the pinned
  6.1.4 source (SHA-256 checked) with only `tls auth_db db_mysql http_client`
  added to the default module set, and ships its source and notices.
- **Clean licence boundary.** GPL-2.0 Kamailio runs as its own program in its own
  container and talks to the AGPL openMCX servers only over SIP and its RPC.
- **Growth path to IMS.** The IMS modules (CSCFs, ISC/iFC, Diameter Cx/Rx) remain
  available for a full IMS core. They are not loaded today: the current
  configuration routes to the MC servers with project script routes generated per
  lab.

## Packaging and interface decisions

Use one `sip-core` service in the standalone profile and keep its SIP subscription
data separate from MCPTT user profiles. Reuse only the modules required by the
chosen deployment. Do not load every IMS module merely because it is available.

Using `ims_isc` requires satisfying its actual profile and registration-state
dependencies; loading it beside a generic registrar is not a complete solution.
The implementation qualification task must demonstrate how subscriber service
criteria reach the core and how the MCPTT SIP AS is triggered. If the selected
module path needs Cx, implement that path at `sip-db`; do not emulate it by
renaming a SQL query AAA-1. A private internal storage option is possible only
where permitted by the selected deployment and must be labelled as such.

The implementation plan must also select the permitted security profile and prove
its identity bindings. TLS is a candidate IP signalling transport, not a blanket
substitute for every IMS or MC application security requirement. IPsec, if selected,
has its own container networking requirements; the design does not add those
privileges to services that do not use it.

Full IMS deployment remains an option if reference-point qualification shows it
reduces custom implementation work. That would change deployment packaging, not
move MCPTT service logic into the SIP proxy or introduce 5G transport scope.

## Qualification before adoption is considered proven

| Test | Required evidence |
|---|---|
| Reproducible build | Exact source commit/tag, dependency versions, base/image digests, module list, schema versions and passing config checks |
| Registration | Two configured identities; correct authentication, binding lifetime, refresh, de-registration and required registration events |
| Identity enforcement | Wrong credentials, forged trusted headers, expired authorization and unsupported transport/security negotiation fail correctly |
| AS selection | Required MCPTT registration notifications and service triggering reach the right AS; unauthorized subscribers cannot invoke it |
| Signalling transparency | MCPTT feature tags, service identifiers, multipart XML, SDP, PUBLISH, SUBSCRIBE/NOTIFY and applicable request methods survive SIP-1/SIP-2 routing |
| Dialog routing | ACK, CANCEL, BYE and re-INVITE follow correct routes; retransmissions do not create duplicate service state |
| Failure handling | Core, AS and subscriber-store outages have observable protocol outcomes; recovery does not retain stale authorization |
| Service integration | A real MCPTT call completes with separately evidenced authorization, affiliation, floor and speech behaviour |

Run black-box fixtures derived from the specifications, not only the project
client. Preserve protocol captures and component versions. Performance and
third-party interoperability remain unmeasured until their own tests run.

For entity placement and all Phase 1 reference points, use the
MCPTT architecture and
[reference-point inventory](mcptt-reference-points.md).
