# Kamailio patches

The SIP core and the P-CSCF run Kamailio 6.1.4 ([source](https://github.com/kamailio/kamailio/tree/6.1.4), archive
SHA-256 `d6b4fd7924fb524f355d66dbfbdc869035c78ea886b86f9efb44abb946d7b7c6`, dependencies/lock.json) with three changes,
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
  SHA-256 `acde9008d8759957f6fd6f808a9885ba63a92d4798816f05cc0ffb84f8f6a87d`: ims_ipsec_pcscf offers and selects the
  algorithms of TS 33.203 annexes H and I (HMAC-SHA-256-128, AES-GCM, AES-GMAC and their unique-salt variants; the
  algorithms removed from annex H are refused) from its ordered list (parameter ipsec_algorithms), parses every
  Security-Client mechanism on its own, guards the protected ports (clause 7.1), keeps port_ps across a
  re-registration (clause 7.4.0), deletes the old set of a re-registration and the new set of a failed authentication
  once their pending transactions are over (clause 7.4.2a; ipsec_destroy_when_idle), and gives the configuration the
  checks of clauses 6.1.5 (ipsec_set_released) and 7.1 rule 3: the pair (UE address, protected client port) not yet
  in the SA table (ipsec_sa_pair_free) and no more than six SAs per direction for one IMPI (ipsec_impi_sets_free).
  The SA table is a record per SPI pair in use (UE, ports, SPIs, IMPI, temporary until ipsec_set_completed at SM12):
  a new challenge deletes the IMPI's registration SAs (clauses 7.3.1.4 and 7.4.2a), a temporary set ends after
  ipsec_temp_set_lifetime (reg-await-auth, TS 24.229 clause 5.2.2.2), a reply to a protected request can leave over
  its set (ipsec_reply_over_sa, clause 7.1), and the SPI pool uses a shared-memory lock and gives a pair back once.

Kamailio and the patches are GPL-2.0-or-later (the patched files carry a notice of the change, GPL-2.0 section 2(a)).
The image carries the source archive and the patches in /usr/src.
