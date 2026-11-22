# reSIProcate (prototype)

Pinned source: [reSIProcate 1.14.0](https://github.com/resiprocate/resiprocate/releases/tag/resiprocate-1.14.0),
archive SHA-256 `f132e4d0fcae0c155f91e5dad608a9985e199e4e3c09b6029a70b1b3b6d0b156` (also in `dependencies/lock.json`,
marked for the prototype). Licence: the Vovida Software License 1.0 (BSD-style, with a clause on the name "VOCAL") for
rutil, the stack and DUM; the bundled `rutil/dns/ares` is under the MIT-style c-ares licence.

For the SIP stack prototype only (`prototype/resiprocate/README.md`); no program or image contains it. `build.sh`
downloads the release, checks its SHA-256, applies the patches here and builds the static rutil, resip and dum
libraries with OpenSSL (repro, media, TURN, tests, popt, GeoIP and DTLS off):

```sh
dependencies/resiprocate/build.sh /tmp/resiprocate /tmp/resiprocate-build
```

Patches, applied in order (under reSIProcate's licence):

- `0001-dum-NOTIFY-before-the-2xx-of-its-SUBSCRIBE.patch`: RFC 6665 section 4.1.2.4, "the subscriber MUST be prepared
  to receive NOTIFY requests before the SUBSCRIBE transaction has completed". DUM answered 481 to such a NOTIFY
  (`DialogSet::dispatch` refused any NOTIFY with a To tag and no dialog), and the notifier then ended the subscription.
  With the patch, a NOTIFY for a dialog set that sent the SUBSCRIBE (or REFER) creates the dialog, from which `Dialog`
  makes the client subscription. Other NOTIFYs with a To tag and no dialog are still refused with 481.
