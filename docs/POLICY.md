# QoS for call media: N5 and Rx

The MCPTT and MCVideo servers can ask the network's policy control for the QoS of a call's media, as the AF
(application function) of the access the user is on (TS 24.379 clause 4.13):

| Access | Interface | Policy control | Configuration block | Specification |
|---|---|---|---|---|
| 5G (5GS) | N5, `Npcf_PolicyAuthorization` over HTTP/2 | PCF | `"pcf"` | TS 29.514, TS 23.289 clauses 5.4 to 5.6 |
| 4G (EPS) | Rx (MCPTT-5), Diameter | PCRF | `"rx"` | TS 29.214, TS 23.379 clause 7.5.2.6, TS 23.280 clause 10.11.2a |
| WLAN or any other | none | none | none | TS 24.379 clause 4.13: no dedicated bearers, no request |

Each block lists the UE address ranges of its access (`ue_subnets`). When a call leg becomes active, the server
looks up the UE's address (from its SDP) in the blocks, `pcf` first, then `rx`. The leg gets one policy session with
the first block that holds the address. A leg whose UE is in no block gets no request, and its call works as before.
Without either block, the servers make no policy requests at all.

Policy requests are best effort by default: when the PCF or PCRF refuses or does not answer, the call goes on.
`"required": true` releases such a leg instead (BYE with Reason cause 503). `"release_on_terminate": true` also
releases a leg whose policy session the network ends.

## What is requested

The AF never sends a QCI or 5QI. Policy control picks it from the application identifier and the media type, by
operator policy (TS 29.213, TS 29.513). TS 23.379 clause 5.7.3 asks for QCI 65 for MCPTT voice.

| Information | N5 (`AppSessionContext`) | Rx (AA-Request) |
|---|---|---|
| UE | `ueIpv4`, with `dnn` and `sliceInfo` | Framed-IP-Address |
| MC service | `afAppId` | AF-Application-Identifier: the service's ICSI (TS 29.214 annex A.13.1 NOTE 3) |
| Media | `medComponents`: audio (RTP, RTCP, floor control), video for MCVideo | Media-Component-Description: the same components and flows |
| Flows | `fDescs`, both written `permit out` | Flow-Description: downlink `permit out`, uplink `permit in` (TS 29.214 clause 5.3.8) |
| Bandwidth | `marBwUl`, `marBwDl` | Max-Requested-Bandwidth-UL and -DL |
| Priority | `resPrio` from `prio_map` | Reservation-Priority and MCPTT-Identifier (MCVideo-Identifier), from the call's Resource-Priority, e.g. `mcpttp.15` (TS 29.214 annex A.13.2) |
| Network events | `evSubsc` with a `notifUri` | Specific-Action 4, 8 and 9; the PCRF sends Re-Auth-Requests on the Rx session |
| End | DELETE of the app session | Session-Termination-Request; an Abort-Session-Request from the PCRF is answered, then the session ends |

On Rx, the server offers the MCPTT (or MCVideo) feature in Supported-Features (TS 29.214 clause 5.4.1). It sends
MCPTT-Identifier in a later request only when the PCRF accepted that feature.

## The `rx` block

```json
"rx": {
  "enabled": true,
  "destination_realm": "epc.example.org",
  "destination_host": "pcrf.epc.example.org",
  "ue_subnets": ["10.45.0.0/16"],
  "audio_bw_kbps": 41,
  "video_bw_kbps": 1024,
  "required": false,
  "release_on_terminate": false,
  "timeout_ms": 2000
}
```

| Key | Meaning |
|---|---|
| `destination_realm` | Required: the realm the AA-Request is routed to (RFC 6733 section 6.1) |
| `destination_host` | Optional: the PCRF's Diameter identity |
| `ue_subnets` | Required: the UE address ranges of the EPS |
| `af_application_identifier` | Optional: by default the ICSI of the server's service (`urn:urn-7:3gpp-service.ims.icsi.mcptt` or `...mcvideo`) |
| `diameter_config` | The freeDiameter configuration with the PCRF as a peer; defaults to the server's `diameter_config` |
| `audio_bw_kbps`, `video_bw_kbps`, `required`, `release_on_terminate`, `timeout_ms` | As in the `pcf` block |

A process runs one freeDiameter core. An MCPTT server with MCPTT-2 (`diameter_config`, the user database) and Rx uses
one configuration file for both. The PCRF is one more `ConnectPeer` in it, for example over TCP without TLS:

```
ConnectPeer = "pcrf.epc.example.org" { ConnectTo = "192.0.2.12"; Port = 3868; No_SCTP; No_TLS; Realm = "epc.example.org"; };
```

The core advertises Rx in its capabilities exchange only when the `rx` block is enabled.

## Status and events

The server's status has an `rx` entry like the `pcf` entry: the active sessions, with their Session-Id and the
features the PCRF accepted, and counters. The events are `rx_enabled`, `rx_session_created`,
`rx_session_create_failed`, `rx_session_updated`, `rx_session_update_failed`, `rx_session_terminated`,
`rx_re_auth` (with the Specific-Action), `rx_abort_session` (with the Abort-Cause) and `rx_leg_released`.

## Tests

- `test_rx` (unit): the service information, and one Rx session through its whole life against a PCRF peer:
  initial and update AA-Requests, Re-Auth-Request, Abort-Session-Request, Session-Termination-Request.
- The `rx` lab (`tools/regress.py --select rx`): `tests/integration/rx_scenario.py` with a recording mock PCRF
  (`tests/integration/mock_pcrf.py`). It checks each request field by field: group and private calls, emergency
  upgrade and cancel, Re-Auth, abort, a refusal, and a client on WLAN with no Rx session.
- The `pcf-n5` lab does the same for N5 with `tests/integration/mock_pcf.go`.
