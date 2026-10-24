# pjproject patches

OpenMCX builds pjproject 2.17 from its pinned archive (dependencies/lock.json) and applies these patches, in order,
in docker/Dockerfile.dev and docker/Dockerfile.centos:

- `0001-tcp-client-port.patch`: `pjsip_tcp_transport_set_client_port()` sets the local port that new outgoing TCP
  connections of a listener bind to. IMS AKA over TCP needs it: the UE sets up its TCP connection from its
  protected client port port_uc to the P-CSCF's protected server port port_ps (TS 33.203 clause 7.1, TCP case), and
  pjproject otherwise binds port 0. The patch defines `PJSIP_TCP_TRANSPORT_HAS_CLIENT_PORT`; the SIP engine
  refuses an IMS AKA configuration without it, so a build on an older development image (no patch) still compiles
  and runs digest clients unchanged.
- `0002-udp-to-tcp.patch`: `pjsip_set_udp_to_tcp_callback()`. IMS AKA over UDP pins every request to the UDP
  transport of its security association set (port_uc), but some requests go over TCP: RFC 3261 section 18.1.1
  (TS 24.229 clause 4.2A) sends a request of 1300 bytes or more over TCP, and a dialog whose route set names TCP (the
  P-CSCF's Record-Route of an INVITE that went over TCP) sends its ACK, BYE and re-INVITEs over TCP. pjproject cannot
  combine a pinned UDP transport with a TCP destination (pjsip_process_route_set() refuses it, the resolver keeps UDP);
  the patch lets the TCP destination through and the callback names the set's TCP connection from port_uc to
  port_ps, and the request goes over it as a TCP request (top Via, no retransmissions). The patch defines
  `PJSIP_HAS_UDP_TO_TCP_CALLBACK`; IMS AKA over UDP needs it.

The patches are under pjproject's licence (GPL-2.0-or-later).
