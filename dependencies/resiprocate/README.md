# reSIProcate

OpenMCX keeps reSIProcate in its fork, [github.com/openMCX/resiprocate](https://github.com/openMCX/resiprocate): the
upstream release with OpenMCX's patches as commits on a release branch, each build a tag.

| | |
|---|---|
| Branch | `openmcx-1.14`, from upstream's tag `resiprocate-1.14.0` (632e215) |
| Pinned tag | `openmcx-1.14.0-1` (commit 2843a5771) |
| Archive | `https://github.com/openMCX/resiprocate/archive/refs/tags/openmcx-1.14.0-1.tar.gz` |
| SHA-256 | `a04a018a1e6be6321f979b0aa9f3abb9c30daddf7936b5caa853db650a7dc1e8` (also in `dependencies/lock.json` and `docker/Dockerfile.dev`) |

Licence: the Vovida Software License 1.0 (BSD-style, with a clause on the name "VOCAL") for rutil, the stack and DUM;
the bundled `rutil/dns/ares` is under the MIT-style c-ares licence. OpenMCX's commits are under the same licence.

The SIP stack that replaces pjproject (`prototype/resiprocate/PLAN.md`). The development image builds it
(`docker/Dockerfile.dev`, into `/opt/resiprocate`). `build.sh` downloads the pinned tag unless the work directory
already has it, checks its SHA-256 and builds the static rutil, resip and dum libraries with OpenSSL (repro, media,
TURN, tests, popt, GeoIP and DTLS off), with the licence in `share/doc/resiprocate`:

```sh
dependencies/resiprocate/build.sh /tmp/resiprocate /tmp/resiprocate-build
```

## OpenMCX's commits on `openmcx-1.14`

- `2843a5771` dum: a NOTIFY before the 2xx of its SUBSCRIBE creates the dialog. RFC 6665 section 4.1.2.4, "the
  subscriber MUST be prepared to receive NOTIFY requests before the SUBSCRIBE transaction has completed". DUM answered
  481 to such a NOTIFY (`DialogSet::dispatch` refused any NOTIFY with a To tag and no dialog), and the notifier then
  ended the subscription. With the commit, a NOTIFY for a dialog set that sent the SUBSCRIBE (or REFER) creates the
  dialog, from which `Dialog` makes the client subscription. Other NOTIFYs with a To tag and no dialog are still
  refused with 481. Not proposed upstream (decided 2026-11-22).

## Changing the fork

1. Commit on `openmcx-1.14` (or, for a new upstream release, a new `openmcx-X.Y` branch from its tag with
   OpenMCX's commits cherry-picked onto it), and push it.
2. Tag the result `openmcx-X.Y.Z-N` (N counts OpenMCX's builds of that release) and push the tag. Tags are never
   moved: a change is a new tag.
3. Here: the tag in `build.sh`, the URL, size and SHA-256 of its archive in `dependencies/lock.json`, and the
   `RESIPROCATE_*` arguments of `docker/Dockerfile.dev`; the list of commits above; then rebuild the development image.
