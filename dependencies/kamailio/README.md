# Kamailio patches

The SIP core and the P-CSCF run Kamailio 6.1.4 ([source](https://github.com/kamailio/kamailio/tree/6.1.4), archive
SHA-256 `d6b4fd7924fb524f355d66dbfbdc869035c78ea886b86f9efb44abb946d7b7c6`, dependencies/lock.json) with seven changes,
applied by docker/Dockerfile.kamailio after each is checked against its SHA-256:

- [0001-ims_auth-local-vectors-and-AKAv2-SHA-256.patch](0001-ims_auth-local-vectors-and-AKAv2-SHA-256.patch),
  SHA-256 `abd536c6e7c8bfbac3e9c1b4fa18d3852c177c8d2d3e87471852529e7d2b169f`: the ims_auth module's locally made IMS AKA vectors (av_mode=1) made usable (nine defects, listed
  in the patch), and HTTP Digest AKAv2-SHA-256 offered before AKAv1-MD5 (parameter aka_v2_sha256, TS 33.203
  clause 6.1.1).
- [0002-ims_ipsec_pcscf-any-Via-port-and-flags.patch](0002-ims_ipsec_pcscf-any-Via-port-and-flags.patch),
  SHA-256 `1090846a2ba9a2b408a00d1238be2986bcc7d290188c57ee362535e210507d32`: ims_ipsec_pcscf and ims_usrloc_pcscf handle an initial registration whose REGISTER has another
  Via port than 5060 (TS 37.579-1 table 5.5.2.13-1), so that its security associations are deleted when it ends
  (TS 33.203 clause 7.4), and read the flags of ipsec_create() and ipsec_forward() whole (flags above 127 were
  sign-extended).
- [0003-ims_ipsec_pcscf-Rel-19-algorithms-and-port-guards.patch](0003-ims_ipsec_pcscf-Rel-19-algorithms-and-port-guards.patch),
  SHA-256 `6991470876586f2fc278f93519c60285dcf426ed90a53c006951a19ac3d1d1fb`: ims_ipsec_pcscf offers and selects the
  algorithms of TS 33.203 annexes H and I (HMAC-SHA-256-128, AES-GCM, AES-GMAC and their unique-salt variants; the
  algorithms removed from annex H are refused) from its ordered list (parameter ipsec_algorithms), parses every
  Security-Client mechanism on its own, guards the protected ports (clause 7.1), keeps port_ps across a
  re-registration (clause 7.4.0), deletes the old set of a re-registration and the new set of a failed authentication
  once their pending transactions are over (clause 7.4.2a; ipsec_destroy_when_idle), and gives the configuration the
  checks of clauses 6.1.5 (ipsec_set_released) and 7.1 rule 3: the pair (UE address, protected client port) not yet
  in the SA table (ipsec_sa_pair_free) and no more than six SAs per direction for one IMPI (ipsec_impi_sets_free); a
  request to the UE whose matched contact's set is gone goes over the set the UE uses, found by UE address and port_us
  (clauses 7.1 and 7.4.0; spi_set_outbound_by_us).
  The SA table is a record per SPI pair in use (UE, ports, SPIs, IMPI, temporary until ipsec_set_completed at SM12):
  a new challenge deletes the IMPI's registration SAs (clauses 7.3.1.4 and 7.4.2a), a temporary set ends after
  ipsec_temp_set_lifetime (reg-await-auth, TS 24.229 clause 5.2.2.2), a reply to a protected request can leave over
  its set (ipsec_reply_over_sa, clause 7.1), and the SPI pool uses a shared-memory lock and gives a pair back once.

- [0004-presence-reginfo-RFC-3680-and-TS-24.229-reg-event.patch](0004-presence-reginfo-RFC-3680-and-TS-24.229-reg-event.patch),
  SHA-256 `b114671b2ccc84d22d41bf30318e263df8f2f8603fb10820c9f1a330d57fefff`: the reg event package of the SIP core (RFC 3680, TS 24.229
  clause 5.4.2.1): pua_reginfo's documents follow RFC 3680 (a REGISTER's contact is "registered", no attributes the
  reginfo schema does not have), presence_reginfo's versions start at 0 (RFC 3680 section 5.1), a final NOTIFY with
  every registration terminated ends the subscription (presence: an event may declare a body final, TS 24.229 clause
  5.4.2.1.2), and pua_reginfo has the operator commands reginfo.shorten (network-initiated re-authentication, the
  event "shortened", TS 24.229 clause 5.4.1.6) and reginfo.deregister (network-initiated deregistration,
  "deactivated" or "rejected", clause 5.4.1.5; docker/sipcore-deregister releases the sessions first); pua refreshes a record a given time before its expiry
  (refresh_before: the P-CSCF's reg subscription 600 s before, TS 24.229 clause 5.2.3) and sends a SUBSCRIBE's
  Expires unchanged; ims_registrar_pcscf
  processes every RFC 3680 contact event (shortened, rejected and probation were skipped).

Kamailio and the patches are GPL-2.0-or-later (the patched files carry a notice of the change, GPL-2.0 section 2(a)).
The image carries the source archive and the patches in /usr/src.
- [0005-pua-TS-24.229-5.2.3-reg-event-subscription.patch](0005-pua-TS-24.229-5.2.3-reg-event-subscription.patch),
  SHA-256 `bbef36860baaef9fb5b90f833441f07c503f9424c849a32de47fcf903a1d1657`: pua keeps the P-CSCF's reg event subscription as TS 24.229 clause 5.2.3
  asks: made once, upon the 200 (OK) to the first initial REGISTER (a later REGISTER no longer refreshes it); every
  refresh asks for the Expires of the initial SUBSCRIBE, 600 s before the expiry of a subscription granted for more
  than 1200 s, else at half time; a refresh that fails with a non-481 response (or gets none) leaves the subscription
  valid until its last known expiry, without a further refresh, and a new initial subscription follows (the record
  keeps its outbound proxy for it); a 481 makes a new initial subscription at once.
- [0006-presence-NOTIFYs-of-a-subscription-in-CSeq-order.patch](0006-presence-NOTIFYs-of-a-subscription-in-CSeq-order.patch),
  SHA-256 `b7f5e609d8e122c825f602b06321fc74732b337bb8e4d194997e4d3c8040d308`: the presence module sends the NOTIFYs of a subscription in CSeq order
  (RFC 3261 clause 12.2.1.1): the first NOTIFY of a reg event subscription, whose body takes longer to build, left
  after a later one that a PUBLISH made in another process, and the UE answered it 500 (clause 12.2.2); a reentrant
  lock per subscription hash slot is held from taking the CSeq to sending the request.
- [0007-ims_ipsec_pcscf-close-TCP-connections-of-a-deleted-set.patch](0007-ims_ipsec_pcscf-close-TCP-connections-of-a-deleted-set.patch),
  SHA-256 `3050d2cfd8fc1f5efe79f6fc6b29fd4bb288b208f8c59982c6fdea293916216d`: ims_ipsec_pcscf closes the TCP connections of a set of security
  associations between its protected ports and the UE's (port_pc to port_us, port_uc to port_ps) when the set is
  deleted (TS 33.203 clause 7.1, NOTE 6): a later set of the same UE given the same port_pc otherwise sent its first
  request over the old connection, which the UE no longer had, and the request was lost.
