# libsrtp patch

OpenMCX builds libsrtp 2.8.1 from its pinned archive (commit 6ff02afa8d2dc3f2e8896af391d137c1c66ff6fa, tag v2.8.1;
archive SHA-256 `1ef3e6315e0ea3cd05f4980c8b5f7a9df369e3d586f5e0616e6cc4c778401d4c`, dependencies/lock.json) as a
static library in /usr/local, in place of the distribution's package, and applies this patch in docker/Dockerfile.dev
and docker/Dockerfile.centos after checking it against its SHA-256:

- [0001-srtcp-index-zero.patch](0001-srtcp-index-zero.patch), SHA-256
  `965965cd8718165a3617ebaf8e0744d79d9b7d367cf3eff25d5b60246168fc58`: the sender's SRTCP index starts at zero.
  RFC 3711 section 3.4: "The SRTCP index MUST be set to zero before the first SRTCP packet is sent, and MUST be
  incremented by one, modulo 2^31, after each SRTCP packet is sent." srtp_protect_rtcp() and srtp_protect_rtcp_mki()
  of libsrtp 2.8.1 increment the index before they read it, so the first SRTCP packet carries index 1; the patch
  reads it first. A key still protects at most 2^31 - 1 SRTCP packets: the replay database refuses the increment
  past 2^31 - 1 (srtp_err_status_key_expired), so the last index sent is now 2^31 - 2. Receivers accept either start.
  The patch defines `SRTP_OPENMCX_SRTCP_INDEX_ZERO` in srtp.h; the unit test tests/test_srtcp_index.cpp checks the
  first two indices with it (skipped without the patch).

OpenMCX also relies on srtp_update_stream() of libsrtp 2.8.1 unchanged: for an ssrc_specific stream it replaces the
master key and restores the stream's SRTCP replay database (rtcp_rdb) and extended RTP index (rtp_rdbx.index), so a
floor or transmission control stream that goes on under a new CSK keeps its SRTCP index and replay window (RFC 3711
section 3.4: "after a re-key, the SRTCP index MUST NOT be reset to zero again"; src/security/security.cpp
SecureStream::rekey). tests/test_floor_rekey.cpp checks it; a later libsrtp must keep this behaviour.

libsrtp's own reference test srtp_driver ("srtp_protect and srtp_unprotect against reference packet") encodes an
SRTCP index of 1 in its reference ciphertext and fails with the patch; the image builds do not run libsrtp's tests.

libsrtp and the patch are under libsrtp's licence (BSD-3-Clause, LICENSE in the archive); the changed lines carry
the notice "Modified by OpenMCX, 2026-10-25 (the first SRTCP index is zero)".
