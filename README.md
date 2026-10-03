```
                            __  __   ____ __  __
  ___   _ __    ___  _ __  |  \/  | / ___|\ \/ /
 / _ \ | '_ \  / _ \| '_ \ | |\/| || |     \  /
| (_) || |_) ||  __/| | | || |  | || |___  /  \
 \___/ | .__/  \___||_| |_||_|  |_| \____|/_/\_\
       |_|
```

# openMCX — 3GPP Release 19 MCx services

The project **openMCX** implements **3GPP Release 19 mission-critical services (MCx)** for an IP network: the common service core,
**MCPTT** (mission-critical push to talk), **MCData** (mission-critical data) and **MCVideo** (mission-critical
video). It runs as a set of containers — a SIP core, application servers, common services and clients —
and every feature is exercised by automated scenarios in a fresh lab. Off-network (ProSe) operation is outside this
build.

This is the **standalone edition**: one MC system for all three services. What exists only between two MC systems
(interconnection, MC gateway servers, migration) is not part of it. The clients are in
[openmcx-client](https://github.com/openMCX/openmcx-client) and MCX Admin in
[openmcx-admin](https://github.com/openMCX/openmcx-admin).

**Containerised deployment** on Ubuntu 24.04 LTS (default) and Ubuntu 26.04 LTS ([building](docs/BUILD.md)).

It is not an interoperability-certified implementation: see the current limits in the [feature list](docs/FEATURES.md#current-limits).

## Services

### MCPTT

- Prearranged, chat, broadcast and ad hoc group calls, with floor control and queueing
- Private calls (automatic, manual and forced commencement, with or without floor control), first-to-answer, ambient listening and remotely initiated calls
- Emergency and imminent-peril calls, emergency alerts, priority pre-emption
- Call-back, transfer and forwarding; functional aliases; regroups
- Location reporting and requests, emergency alert and group geographic areas
- End-to-end protected media (GMK and PCK) and protected XML signalling

### MCData

- Short data (SDS) over the signalling and media planes, one-to-one, group and ad hoc
- File distribution over HTTP and over the media plane, with disposition notifications
- Emergency and imminent-peril communications, group emergency alerts
- IP connectivity, enhanced status, communication release, functional aliases
- Message store with notification channels, location
- End-to-end protected payloads, signalling and XML

### MCVideo

- Prearranged, chat and ad hoc group calls, with transmission control (queueing, revocation, implicit request) and reception control
- Private calls with and without transmission control, in every commencement mode
- Emergency and imminent-peril calls with pre-emptive transmission, emergency alerts, ad hoc group emergency alerts
- Video pull and push, one-to-one and to or from the server with its recording; ambient viewing; remote transmission
- Regroups, functional aliases, remote group selection and location
- End-to-end protected video (GMK and PCK), protected transmission control and protected XML signalling

### Common services

- Identity (OIDC), group management (XCAP and subscriptions), configuration, location and key management
- Separate participating and controlling servers within one MC system

## Documentation

- **[Feature list](docs/FEATURES.md)**: what each service supports, how it is verified, and the current limits
- **[Using the lab](docs/USAGE.md)**: build, run, client commands, verification and SIP debugging
- **Tests**: [MCPTT](tests/README.md), [MCData](tests/MCDATA_TEST.md) and [MCVideo](tests/MCVIDEO_TEST.md) test indexes, with call flows and evidence
- **Acceptance matrices**: [MCPTT](docs/architecture/mcptt-standards-and-acceptance.md), [MCData](docs/architecture/mcdata-standards-and-acceptance.md) and [MCVideo](docs/architecture/mcvideo-standards-and-acceptance.md)
