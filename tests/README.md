# Tests

The automated tests of the OpenMCX servers: unit tests of the protocol code, and lab scenarios that start a fresh
system in Docker, drive the clients through a procedure, check the state the clients and servers report, and check
the messages on the wire.

- [MCPTT test index](MCPTT_TEST.md): the MCPTT tests by call type.
- [MCData test index](MCDATA_TEST.md): the MCData tests by service.
- [MCVideo test index](MCVIDEO_TEST.md): the MCVideo tests by service.

How to run them, and how to add a scenario, is in the [developer guide](../docs/DEVELOPER_GUIDE.md#9-testing):
`tools/regress.py` prepares, runs and tears down every lab of the matrix ([using the lab](../docs/USAGE.md#6-tests)).
The evidence paths named in the reports (`artifacts/...`) are what a lab run writes on the computer that ran it
(results, logs and captures); they are not kept in the repository.

## Layout

The indexes stay in this directory; the reports they link to live beside them, one directory per service.

| Path | Holds |
|---|---|
| `tests/README.md`, `tests/MCPTT_TEST.md`, `tests/MCDATA_TEST.md`, `tests/MCVIDEO_TEST.md` | The indexes: start here |
| `tests/mcptt/` | One report per MCPTT call type or service (`PREARRANGED_TEST.md`, `PRIVATE_CALL_TEST.md`, …) |
| `tests/mcdata/` | One report per MCData service (`MCDATA_SDS_TEST.md`, `MCDATA_FD_TEST.md`, `MCDATA_IPCONN_TEST.md`, …) |
| `tests/mcvideo/` | One report per MCVideo service (`MCVIDEO_GROUP_CALL_TEST.md`, …) |
| `tests/integration/` | The Python scenario drivers and wire verifiers the reports cite |
| `tests/test_*.cpp` | The unit tests (run with `ctest`) |

A passing scenario shows the procedure working in the lab, not complete conformance to the specification. What the
present edition does not include, and the known limits of what it implements, are in the
[limitations](../docs/LIMITATIONS.md).
