# pjproject patches

OpenMCX builds pjproject 2.17 from its pinned archive (dependencies/lock.json) and applies these patches, in order,
in docker/Dockerfile.dev and docker/Dockerfile.centos:

- `0001-tcp-client-port.patch`: `pjsip_tcp_transport_set_client_port()` sets the local port that new outgoing TCP
  connections of a listener bind to. IMS AKA over TCP needs it: the UE sets up its TCP connection from its
  protected client port port_uc to the P-CSCF's protected server port port_ps (TS 33.203 clause 7.1, TCP case), and
  pjproject otherwise binds port 0. The patch defines `PJSIP_TCP_TRANSPORT_HAS_CLIENT_PORT`; the SIP engine
  refuses an IMS AKA configuration without it, so a build on an older development image (no patch) still compiles
  and runs digest clients unchanged.

The patches are under pjproject's licence (GPL-2.0-or-later).
