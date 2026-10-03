# MCVideo location tests

These tests cover **step V8e of increment V8 of the MCVideo plan**: location (TS 24.281 V19.6.0 clause 18 and 6.2.9). They cover the reporting configuration at service authorisation, the reports on its triggers, the requests and configuration changes of authorised users, and the refusals 191 to 193. They also cover the group geographic area and the emergency alert area.

Back to the [MCVideo test index](../MCVIDEO_TEST.md). Architecture: MCVideo design, [standards and acceptance](../../docs/architecture/mcvideo-standards-and-acceptance.md) (row MV-LOC-01).

## How it works

- **Shared with MCPTT.** Clause 18 follows TS 24.379 clause 13, and `mcvideo-server` runs the core's location procedures. Two things were hard-wired to MCPTT and now follow the server's service:
  - the location body's MIME type, `application/vnd.3gpp.mcvideo-location-info+xml`
  - the codec namespace, `urn:3gpp:ns:mcvideoLocationInfo:1.0` (TS 24.281 F.3), with `<McvideoSignallingEvent>` and `<mcvideo-reporting-uri>`.
- **Configuration.** The MCVideo server holds its own configuration and areas (`mcvideo.location`). The rights are in each user's MCVideo profile (`location`: `request`, `configure`, `report`, `share_with`), naming MCVideo IDs.
- **Warnings.** The MCVideo numbers are used: 191 for an empty or invalid target list, 192 for a request and 193 for a configuration by a user without the right.
- **Client.** The MCVideo client has its own reporter, beside the MCPTT and MCData ones, sharing the UE's simulated position and radio.
  - It answers requests and reports on its triggers. The MCVideo signalling events are the log-on and the start of a non-emergency group or private call.
  - It uses the emergency configuration while it has an emergency alert or an emergency call.
  - It can request other users' locations and change their configuration (`mcvideo-location`).
- **Areas (6.2.9).**
  - Entering an emergency alert area starts an MCVideo emergency alert.
  - Entering and leaving the group geographic area of the selected group affiliates the client and de-affiliates it.
- **SEAL.** The SEAL location management server is not used by `mcvideo-server`: the lab gives it no LMS.

## Client commands and status

```bash
mcx-client --config FILE --command 'location position <latitude> <longitude>'   # shared by the three services
mcx-client --config FILE --command 'mcvideo-location request [refresh] [filter <area> in|out] [fa <alias>] [no-list] <MCVideo ID>...'
mcx-client --config FILE --command 'mcvideo-location configure <MCVideo ID>[,<MCVideo ID>...] <configuration JSON>'
```

`status.json` adds `mcvideo_location`:
- `configured`, `configuration` and `emergency`
- `sent` and `received`: the reports
- `area_notices`
- `server`
- `last_request` and `last_result`

## Running the tests

```bash
tools/regress.py --image openmcx:v8e --client-image openmcx-client:v8e --select mcvideo-location
```

The lab is `--mcvideo --location`. It has the MCPTT location lab's configuration: log-on, group call, travelled-distance, zone entry and exit and cell change triggers, and an emergency periodic trigger. It has the same areas and the same rights:
- client-a may request and configure
- client-b shares with anyone
- client-c shares with client-b only
- client-d may not report.

## Performed tests

| ID | Date | Build | Test | Result |
|---|---|---|---|---|
| MV-LC-01 | 2026-09-27 | `openmcx:v8e` (`d58f835e1979`), `openmcx-client:v8e` (`398a352db11d`) | Every MCVideo client holds the configuration sent after its service authorisation, and the server stores it with TriggerIds t1 to t7 | Passed |
| MV-LC-02 | 2026-09-27 | same | client-a, client-b and client-c report their log-on positions | Passed |
| MV-LC-03 | 2026-09-27 | same | client-d, not allowed to report, is refused, and nothing is stored | Passed |
| MV-LC-04 | 2026-09-27 | same | Moving into the zone fires the travelled-distance and zone-entry triggers, and the stored position follows | Passed |
| MV-LC-05 | 2026-09-27 | same | A non-emergency MCVideo group call fires the signalling event trigger | Passed |
| MV-LC-06 | 2026-09-27 | same | client-a's request for client-b is answered with the RequestId, client-b's MCVideo ID and its position | Passed |
| MV-LC-07 | 2026-09-27 | same | With refresh, the server asks client-b before answering | Passed |
| MV-LC-08 | 2026-09-27 | same | A LocationFilter for users inside the zone excludes client-b. client-c, sharing only with client-b, is not reported to client-a | Passed |
| MV-LC-09 | 2026-09-27 | same | client-b's request is refused with 403 `192`, a request naming no one with 403 `191`, and client-c's configuration change with 403 `193` | Passed |
| MV-LC-10 | 2026-09-27 | same | client-a adds a periodic trigger to client-b's configuration, and client-b reports on it | Passed |
| MV-LC-11 | 2026-09-27 | same | client-c entering the group geographic area is recorded; leaving it de-affiliates client-c, and entering again affiliates it | Passed |
| MV-LC-12 | 2026-09-27 | same | client-a entering the emergency alert area starts an MCVideo emergency alert, which client-b receives, and client-a then reports Emergency on the emergency trigger. After the alert is cancelled and client-a leaves the area, the alert is gone | Passed |

Run results:
- **Debug TCP:** 29 checks (`artifacts/regress-v8e-location-tcp/mcvideo-location/`).
- **TLS:** 29 checks (`artifacts/regress-v8e-tls/`).
- **Other location labs**, on the same images, since the core changed: MCPTT `location` (50 checks), `mcdata-location` (27) and `mcdata-location-protected` (28), `inter-location` and `inter-location-gateway` (27 each). All passed.
- **Unit tests:** the location codec's MCVideo configuration and report round trips, namespace and MIME type.

Defects found by the runs and fixed:
- The client's location handling took an emergency alert, which carries an mcvideo-info body and a location report, for a location report. The alert was then never recorded. A report beside an info body now goes to the alert handling, as on the MCData side.

## Coverage gaps

| Area | Gap |
|---|---|
| Other functions | Requests for users of another participating function (18.2.3.3, 18.2.4.2) come with V10 |
| XML protection | The location XML is not encrypted for MCVideo; signalling protection comes with V9 |
| Functional alias triggers | The alias activation and deactivation triggers and location-based alias activation (20.2.1.4) are not exercised for MCVideo |
| SEAL | `mcvideo-server` does not use the SEAL location management server |
| Positions | Positions and radio identities are simulated |
