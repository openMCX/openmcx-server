//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Protected calls: the SRTP contexts of group media (GMK), private call media (PCK) and the SRTCP contexts of
// floor control (CSK), with key activation, expiry, revocation, rotation, replay protection and bounded state.
//
// Specifications: TS 33.180 V19.4.0 (Rel-19); RFC 3711 (SRTP).

#include "mcx/protected_call.hpp"

#include <functional>
#include <iostream>
#include <stdexcept>

namespace {
using Bytes = std::vector<std::uint8_t>;

//------------------------------------------------------------------------------
// Throws the message when the condition does not hold.
void check(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}

//------------------------------------------------------------------------------
// Fails unless the action throws.
template <class Action> void rejects(Action action) {
  bool failed = false;
  try {
    action();
  } catch (const std::exception &) {
    failed = true;
  }
  check(failed, "invalid security operation accepted");
}

//------------------------------------------------------------------------------
// A valid key with TS 33.180 annex E.6 properties: a GMK for "sip:group@example.org" (CSB-ID purpose tag
// '0'), or with floor set a CSK (purpose tag '2'), active since 30 s and expiring in an hour.
mcx::keying::KeyMessage key(bool floor = false) {
  mcx::keying::KeyMessage message;
  message.csb_id = floor ? 0x20000001 : 1;
  for (unsigned index = 0; index < 16; ++index) {
    message.key[index] = index;
    message.random[index] = index + 16;
  }
  auto now = std::uint64_t(std::time(nullptr));
  message.properties = mcx::keying::KeyProperties{std::uint8_t(floor ? 2 : 0),
                                                  1,
                                                  now - 30,
                                                  now + 3600,
                                                  "",
                                                  floor ? std::vector<std::string>{}
                                                        : std::vector<std::string>{"sip:group@example.org"}};
  return message;
}

//------------------------------------------------------------------------------
// An RTP packet: version 2, payload type 96, sequence number 1, SSRC 0x12345678.
Bytes rtp() { return {0x80, 0x60, 0, 1, 0, 0, 1, 0x40, 0x12, 0x34, 0x56, 0x78, 1, 2, 3, 4, 5, 6, 7, 8}; }

//------------------------------------------------------------------------------
// An RTCP APP packet named "MCPT" (floor control), SSRC 0x12345678.
Bytes rtcp() { return {0x80, 0xcc, 0, 4, 0x12, 0x34, 0x56, 0x78, 0x4d, 0x43, 0x50, 0x54, 1, 2, 3, 4, 5, 6, 7, 8}; }

//------------------------------------------------------------------------------
// TS 33.180 clause 7.4.2: group media protected with SRTP keys derived from the GMK. A repeated GMK
// keeps the context (no packet index reuse, replay rejected); a wrong sender or an altered packet fails without
// consuming the context; a new GMK starts a new context; a different key under the same GMK-ID is rejected;
// a cleared group key is not usable.
void stable_group_context() {
  mcx::ProtectedCall tx, rx;
  auto gmk = key();
  tx.set_group(gmk);
  rx.set_group(gmk);
  auto packet = rtp();
  auto wire = tx.protect_media(packet, "sip:alice@example.org");
  check(rx.unprotect_media(wire, "sip:alice@example.org") == packet, "media recovery");
  tx.set_group(gmk);
  rx.set_group(gmk);
  rejects([&] { tx.protect_media(packet, "sip:alice@example.org"); });
  rejects([&] { rx.unprotect_media(wire, "sip:alice@example.org"); });
  packet[3] = 2;
  wire = tx.protect_media(packet, "sip:alice@example.org");
  rejects([&] { rx.unprotect_media(wire, "sip:bob@example.org"); });
  auto altered = wire;
  altered[11] ^= 1;
  rejects([&] { rx.unprotect_media(altered, "sip:alice@example.org"); });
  check(rx.unprotect_media(wire, "sip:alice@example.org") == packet,
        "failed peer checks do not consume proper context");
  auto next = gmk;
  next.csb_id = 2;
  next.key[0] ^= 1;
  next.random[0] ^= 1;
  tx.set_group(next);
  rx.set_group(next);
  rejects([&] { rx.unprotect_media(wire, "sip:alice@example.org"); });
  packet[3] = 1;
  auto fresh = tx.protect_media(packet, "sip:alice@example.org");
  check(rx.unprotect_media(fresh, "sip:alice@example.org") == packet, "new GMK epoch resets sequence context");
  auto collision = next;
  collision.key[0] ^= 1;
  rejects([&] { rx.set_group(collision); });
  rx.clear_group();
  check(!rx.group_ready(), "cleared group not ready");
  rejects([&] { rx.unprotect_media(fresh, "sip:alice@example.org"); });
}

//------------------------------------------------------------------------------
// TS 33.180 clauses 9.4.6 and 9.4.7: floor control protected with SRTCP keys derived from the CSK. A
// repeated CSK keeps the outbound SRTCP index and the replay state; an altered packet is rejected; a new CSK
// starts a new context; an unprotected packet is rejected.
void stable_floor_context() {
  mcx::ProtectedCall tx, rx;
  auto csk = key(true);
  tx.set_floor(csk);
  rx.set_floor(csk);
  auto packet = rtcp();
  auto first = tx.protect_floor(packet);
  check(rx.unprotect_floor(first) == packet, "floor recovery");
  tx.set_floor(csk);
  rx.set_floor(csk);
  rejects([&] { rx.unprotect_floor(first); });
  auto second = tx.protect_floor(packet);
  check(first != second, "duplicate CSK must not reset outbound SRTCP index");
  check(rx.unprotect_floor(second) == packet, "next floor index accepted");
  auto altered = second;
  altered[7] ^= 1;
  rejects([&] { rx.unprotect_floor(altered); });
  auto next = csk;
  next.csb_id++;
  next.key[0] ^= 1;
  next.random[0] ^= 1;
  tx.set_floor(next);
  rx.set_floor(next);
  rejects([&] { rx.unprotect_floor(first); });
  check(rx.unprotect_floor(tx.protect_floor(packet)) == packet, "new CSK epoch");
  rejects([&] { rx.unprotect_floor(packet); });
}

//------------------------------------------------------------------------------
// TS 33.180 annex E.6.10: a GMK or CSK past its Expiry time is not ready and not used.
void expiry() {
  auto message = key();
  message.properties->expiry_unix_seconds = std::uint64_t(std::time(nullptr)) - 1;
  mcx::ProtectedCall call;
  call.set_group(message);
  check(!call.group_ready(), "expired GMK not ready");
  rejects([&] { call.protect_media(rtp(), "sip:alice@example.org"); });
  message = key(true);
  message.properties->expiry_unix_seconds = std::uint64_t(std::time(nullptr)) - 1;
  call.set_floor(message);
  check(!call.floor_ready(), "expired CSK not ready");
  rejects([&] { call.protect_floor(rtcp()); });
}

//------------------------------------------------------------------------------
// TS 33.180 annex E.6.10: an Expiry time of 0 means the key never expires: such a GMK or CSK is ready and used, its
// epoch survives the purge when another GMK arrives, and a re-delivery cannot turn a dated GMK into one that never
// expires (it would extend its lifetime).
void expiry_zero_never_expires() {
  auto message = key();
  message.properties->expiry_unix_seconds = 0;
  mcx::ProtectedCall call;
  call.set_group(message);
  check(call.group_ready(), "GMK with expiry 0 must be ready");
  check(!call.protect_media(rtp(), "sip:alice@example.org").empty(), "GMK with expiry 0 must protect");
  auto other = key();
  other.csb_id = 2;
  other.key[0] ^= 1;
  call.set_group(other);
  call.set_group(message);
  check(call.group_ready(), "GMK epoch with expiry 0 must survive the purge");
  rejects([&] { call.protect_media(rtp(), "sip:alice@example.org"); }); // same index: the epoch kept its state
  auto floor = key(true);
  floor.properties->expiry_unix_seconds = 0;
  call.set_floor(floor);
  check(call.floor_ready(), "CSK with expiry 0 must be ready");
  check(!call.protect_floor(rtcp()).empty(), "CSK with expiry 0 must protect");
  auto dated = key();
  dated.csb_id = 3;
  dated.key[0] ^= 2;
  mcx::ProtectedCall renewed;
  renewed.set_group(dated);
  auto forever = dated;
  forever.properties->expiry_unix_seconds = 0;
  rejects([&] { renewed.set_group(forever); });
}

//------------------------------------------------------------------------------
// TS 33.180 annex E.6.4: a GMK before its Activation time is not used; annex E.6.9: a revoked CSK
// (Status bit 0 is 0) is not used.
void inactive_keys() {
  auto message = key();
  message.properties->activation_unix_seconds = std::uint64_t(std::time(nullptr)) + 300;
  mcx::ProtectedCall call;
  call.set_group(message);
  check(!call.group_ready(), "future GMK must not report ready");
  rejects([&] { call.protect_media(rtp(), "sip:alice@example.org"); });
  message = key(true);
  message.properties->status = 0;
  call.set_floor(message);
  check(!call.floor_ready(), "revoked CSK must not report ready");
  rejects([&] { call.protect_floor(rtcp()); });
}

//------------------------------------------------------------------------------
// TS 33.180 clause 5.7 and annex E.6.4: a GMK received ahead of its Activation time leaves the current one in use
// (a receiver still holding only the current GMK decodes the media); the most recent active one is used.
void next_group_key_waits() {
  mcx::ProtectedCall tx, rx;
  auto current = key();
  tx.set_group(current);
  rx.set_group(current);
  auto next = current;
  next.csb_id = 2;
  next.key[0] ^= 1;
  next.random[0] ^= 1;
  next.properties->activation_unix_seconds = std::uint64_t(std::time(nullptr)) + 300;
  tx.set_group(next);
  check(tx.group_ready(), "current GMK stays ready while the next waits");
  auto packet = rtp();
  check(rx.unprotect_media(tx.protect_media(packet, "sip:alice@example.org"), "sip:alice@example.org") == packet,
        "media stays under the current GMK");
  auto later = current;
  later.csb_id = 3;
  later.key[1] ^= 1;
  later.properties->activation_unix_seconds = current.properties->activation_unix_seconds + 10;
  tx.set_group(later);
  rx.set_group(later);
  packet[3] = 2;
  check(rx.unprotect_media(tx.protect_media(packet, "sip:alice@example.org"), "sip:alice@example.org") == packet,
        "the most recent active GMK is used");
}

//------------------------------------------------------------------------------
// TS 33.180 annexes E.6.9 and E.6.10: a repeated GMK with its Status now revoked, or a repeated CSK with
// an earlier Expiry time, takes effect.
void duplicate_metadata() {
  mcx::ProtectedCall call;
  auto gmk = key();
  call.set_group(gmk);
  auto revoked = gmk;
  revoked.properties->status = 0;
  call.set_group(revoked);
  check(!call.group_ready(), "same GMK authenticated revocation applied");
  rejects([&] { call.protect_media(rtp(), "sip:alice@example.org"); });
  auto csk = key(true);
  call.set_floor(csk);
  revoked = csk;
  revoked.properties->expiry_unix_seconds = std::uint64_t(std::time(nullptr)) - 1;
  call.set_floor(revoked);
  check(!call.floor_ready(), "same CSK shortened expiry applied");
  rejects([&] { call.protect_floor(rtcp()); });
}

//------------------------------------------------------------------------------
// Writes the SSRC (RFC 3550 section 5.1) into octets 8 to 11 of the packet.
void set_ssrc(Bytes &packet, std::uint32_t ssrc) {
  for (int index = 0; index < 4; ++index) packet[8 + index] = std::uint8_t(ssrc >> (24 - 8 * index));
}

//------------------------------------------------------------------------------
// 300 SSRCs under one GMK do not exhaust the media contexts; a repeated GMK
// still refuses packet index reuse for the first SSRC; a new GMK clears the retired SSRCs.
void bounded_media_lifecycle() {
  mcx::ProtectedCall tx, rx;
  auto gmk = key();
  tx.set_group(gmk);
  rx.set_group(gmk);
  auto packet = rtp();
  Bytes first;
  for (unsigned ssrc = 1; ssrc <= 300; ++ssrc) {
    set_ssrc(packet, ssrc);
    auto wire = tx.protect_media(packet, "sip:alice@example.org");
    if (ssrc == 1) first = wire;
    check(rx.unprotect_media(wire, "sip:alice@example.org") == packet, "300 bursts must not exhaust contexts");
  }
  tx.set_group(gmk);
  rx.set_group(gmk);
  set_ssrc(packet, 1);
  rejects([&] { tx.protect_media(packet, "sip:alice@example.org"); });
  rejects([&] { rx.unprotect_media(first, "sip:alice@example.org"); });
  gmk.csb_id++;
  gmk.key[0] ^= 1;
  tx.set_group(gmk);
  rx.set_group(gmk);
  check(rx.unprotect_media(tx.protect_media(packet, "sip:alice@example.org"), "sip:alice@example.org") == packet,
        "new epoch clears retired SSRCs");
}

//------------------------------------------------------------------------------
// RFC 3711 section 3.3.2: a packet from an unknown SSRC that fails authentication does not evict the
// context of an active sender.
void unauthenticated_context_does_not_evict() {
  mcx::ProtectedCall tx, rx;
  auto gmk = key();
  tx.set_group(gmk);
  rx.set_group(gmk);
  auto packet = rtp();
  Bytes first;
  for (unsigned ssrc = 1; ssrc <= 8; ++ssrc) {
    set_ssrc(packet, ssrc);
    auto wire = tx.protect_media(packet, "sip:alice@example.org");
    if (ssrc == 1) first = wire;
    rx.unprotect_media(wire, "sip:alice@example.org");
  }
  set_ssrc(first, 9);
  rejects([&] { rx.unprotect_media(first, "sip:alice@example.org"); });
  set_ssrc(packet, 1);
  packet[3] = 2;
  check(rx.unprotect_media(tx.protect_media(packet, "sip:alice@example.org"), "sip:alice@example.org") == packet,
        "unauthenticated stream must not evict active peer");
}

//------------------------------------------------------------------------------
// The outbound SRTCP contexts under one CSK are bounded (1024 SSRCs); the
// refused one does not disturb earlier indices; a new CSK releases them.
void bounded_floor_contexts() {
  mcx::ProtectedCall tx;
  auto csk = key(true);
  tx.set_floor(csk);
  auto packet = rtcp();
  Bytes first;
  for (unsigned ssrc = 1; ssrc <= 1024; ++ssrc) {
    for (int index = 0; index < 4; ++index) packet[4 + index] = std::uint8_t(ssrc >> (24 - 8 * index));
    auto wire = tx.protect_floor(packet);
    if (ssrc == 1) first = wire;
  }
  for (int index = 0; index < 4; ++index) packet[4 + index] = std::uint8_t(1025U >> (24 - 8 * index));
  rejects([&] { tx.protect_floor(packet); });
  packet[4] = packet[5] = packet[6] = 0;
  packet[7] = 1;
  check(tx.protect_floor(packet) != first, "floor capacity preserves earlier outbound index");
  csk.csb_id++;
  csk.key[0] ^= 1;
  tx.set_floor(csk);
  check(!tx.protect_floor(packet).empty(), "CSK rotation releases bounded floor contexts");
}

//------------------------------------------------------------------------------
// TS 33.180 clause 7.4.2: clearing and selecting the same GMK again, or switching to another GMK and
// back, keeps its packet indices: no reuse, no replay, the next sequence number accepted.
void reselect_group_keeps_epoch() {
  mcx::ProtectedCall tx, rx;
  auto group_a = key();
  tx.set_group(group_a);
  rx.set_group(group_a);
  auto packet = rtp();
  auto first = tx.protect_media(packet, "sip:alice@example.org");
  rx.unprotect_media(first, "sip:alice@example.org");
  tx.clear_group();
  rx.clear_group();
  tx.set_group(group_a);
  rx.set_group(group_a);
  rejects([&] { tx.protect_media(packet, "sip:alice@example.org"); });
  rejects([&] { rx.unprotect_media(first, "sip:alice@example.org"); });
  packet[3] = 2;
  auto second = tx.protect_media(packet, "sip:alice@example.org");
  check(rx.unprotect_media(second, "sip:alice@example.org") == packet, "reselected epoch keeps next sequence usable");
  auto group_b = group_a;
  group_b.csb_id = 77;
  group_b.key[0] ^= 1;
  group_b.properties->groups = {"sip:other@example.org"};
  tx.set_group(group_b);
  rx.set_group(group_b);
  tx.set_group(group_a);
  rx.set_group(group_a);
  rejects([&] { tx.protect_media(packet, "sip:alice@example.org"); });
  rejects([&] { rx.unprotect_media(second, "sip:alice@example.org"); });
  packet[3] = 3;
  check(rx.unprotect_media(tx.protect_media(packet, "sip:alice@example.org"), "sip:alice@example.org") == packet,
        "A to B to A retains next sequence");
}

//------------------------------------------------------------------------------
// The retained GMK contexts are bounded (16): a 17th is refused until one expires (TS 33.180 annex
// E.6.10); an expired GMK cannot be renewed under the same GMK-ID; a GMK without properties is refused.
void bounded_group_epoch_cache() {
  mcx::ProtectedCall call;
  auto first = key();
  call.set_group(first);
  auto packet = rtp();
  call.protect_media(packet, "sip:alice@example.org");
  auto last = first;
  for (unsigned id = 2; id <= 16; ++id) {
    last = first;
    last.csb_id = id;
    last.key[0] = id;
    call.set_group(last);
  }
  auto next = first;
  next.csb_id = 17;
  next.key[0] = 17;
  rejects([&] { call.set_group(next); });
  call.set_group(first);
  rejects([&] { call.protect_media(packet, "sip:alice@example.org"); });
  last.properties->expiry_unix_seconds = std::uint64_t(std::time(nullptr)) - 1;
  call.set_group(last);
  call.set_group(next);
  check(call.group_ready(), "expired epoch frees bounded cache capacity");
  call.set_group(first);
  rejects([&] { call.protect_media(packet, "sip:alice@example.org"); });
  auto expired = key();
  expired.csb_id = 100;
  expired.properties->expiry_unix_seconds = std::uint64_t(std::time(nullptr)) - 1;
  mcx::ProtectedCall other;
  other.set_group(expired);
  expired.properties->expiry_unix_seconds = std::uint64_t(std::time(nullptr)) + 100;
  rejects([&] { other.set_group(expired); });
  auto missing = first;
  missing.properties.reset();
  rejects([&] { call.set_group(missing); });
}

} // namespace

//------------------------------------------------------------------------------
// A PCK (TS 33.180 annex E.3, PCK-ID purpose tag '1') without properties.
mcx::keying::KeyMessage pck() {
  mcx::keying::KeyMessage message;
  message.csb_id = 0x10000007;
  for (unsigned index = 0; index < 16; ++index) {
    message.key[index] = index + 1;
    message.random[index] = index + 40;
  }
  return message;
}

//------------------------------------------------------------------------------
// TS 33.180 clause 7.4.1 and table E.1.3-1: private call media under the PCK, each direction with its
// own CS-ID (0 for the initiator, 1 for the receiver); a PCK-ID without purpose tag '1' and a different key
// under the same PCK-ID are rejected; a suspended PCK is not used and resumes with its packet indices; an
// ended PCK cannot be resumed.
void private_call_context() {
  mcx::ProtectedCall caller, callee;
  auto pck_key = pck();
  caller.set_private(pck_key, true);
  callee.set_private(pck_key, false);
  check(caller.private_ready() && callee.private_ready(), "PCK ready");
  auto packet = rtp();
  auto wire = caller.protect_media(packet, "sip:alice@example.org");
  check(callee.unprotect_media(wire, "sip:alice@example.org") == packet, "caller to callee");
  auto reply = rtp();
  set_ssrc(reply, 0x0badcafe);
  auto back = callee.protect_media(reply, "sip:bob@example.org");
  check(caller.unprotect_media(back, "sip:bob@example.org") == reply, "callee to caller");
  // Each direction has its own CS-ID: a packet cannot be reflected back to its sender.
  rejects([&] { caller.unprotect_media(wire, "sip:alice@example.org"); });
  auto wrong = pck_key;
  wrong.csb_id = 0x20000007;
  rejects([&] { caller.set_private(wrong, true); });
  auto collision = pck_key;
  collision.key[0] ^= 1;
  rejects([&] { callee.set_private(collision, false); });
  // A group key is not used while the PCK is selected, and set-aside calls resume
  // with their packet indices.
  callee.suspend_private();
  check(!callee.private_ready(), "suspended");
  rejects([&] { callee.unprotect_media(wire, "sip:alice@example.org"); });
  callee.resume_private(pck_key.csb_id);
  rejects([&] { callee.unprotect_media(wire, "sip:alice@example.org"); });
  packet[3] = 2;
  check(callee.unprotect_media(caller.protect_media(packet, "sip:alice@example.org"), "sip:alice@example.org") ==
            packet,
        "resumed context");
  callee.end_private(pck_key.csb_id);
  check(!callee.private_ready(), "ended");
  rejects([&] { callee.resume_private(pck_key.csb_id); });
}

//------------------------------------------------------------------------------
// Runs every test and reports the failed ones.
int main() {
  unsigned failures = 0;
  for (auto test : {std::pair<const char *, std::function<void()>>{"private_call_context", private_call_context},
                    {"stable_group_context", stable_group_context},
                    {"stable_floor_context", stable_floor_context},
                    {"expiry", expiry},
                    {"expiry_zero_never_expires", expiry_zero_never_expires},
                    {"inactive_keys", inactive_keys},
                    {"next_group_key_waits", next_group_key_waits},
                    {"duplicate_metadata", duplicate_metadata},
                    {"bounded_media_lifecycle", bounded_media_lifecycle},
                    {"unauthenticated_context_does_not_evict", unauthenticated_context_does_not_evict},
                    {"bounded_floor_contexts", bounded_floor_contexts},
                    {"reselect_group_keeps_epoch", reselect_group_keeps_epoch},
                    {"bounded_group_epoch_cache", bounded_group_epoch_cache}}) {
    try {
      test.second();
    } catch (const std::exception &error) {
      std::cerr << test.first << ": " << error.what() << '\n';
      ++failures;
    }
  }
  if (!failures) std::cout << "protected call tests passed\n";
  return failures ? 1 : 0;
}
