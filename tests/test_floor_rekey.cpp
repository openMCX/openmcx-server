//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Floor and transmission control SRTCP under a new CSK (ProtectedCall::set_floor), and the SSRC a peer allocates
// for this endpoint's floor control messages (mcx::floor_ssrc_refused).
// - RFC 3711 section 3.4 (through TS 33.180 clauses 9.4.7 and 9.4.8): "after a re-key, the SRTCP index MUST NOT be
//   reset to zero again": a stream that goes on continues its index on the wire under the new key, in both
//   directions, and its receiver accepts it and still refuses a replay (section 3.3.2), also of a packet received
//   under the old key (its replay list stays); a stream that starts under the new key starts at index 0; a failed
//   re-key breaks the stream in both directions; a key whose derivation or copy fails changes nothing.
// - RFC 7714 sections 8.4, 9.1 and 9.4, RFC 3711 section 9.1: an SSRC already used under the key for another stream
//   is refused for a new one; the stream going on keeps its SSRC; an unused SSRC is accepted; an SSRC negotiated
//   for a stream without a packet yet is not issued.
// Skipped (exit 77) without OpenMCX's libsrtp patch (dependencies/libsrtp): the indices checked start at 0.
//
// Specifications: TS 33.180 V19.5.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19); RFC 3711, RFC 7714.

#include "mcx/protected_call.hpp"

#include <srtp2/srtp.h>

#include <cstdlib>
#include <ctime>
#include <functional>
#include <new>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {
using Bytes = std::vector<std::uint8_t>;

// The allocation by operator new that fails, counted from when it is armed (allocation_failure); -1: none.
long failing_allocation = -1;
long allocations = 0;
} // namespace

//------------------------------------------------------------------------------
// Replaces the global allocation functions of this test program, so that the allocation failing_allocation fails with
// std::bad_alloc (failed_key_copy_keeps_key). libsrtp and OpenSSL allocate with malloc and are not affected.
void *operator new(std::size_t size) {
  if (failing_allocation >= 0 && allocations++ == failing_allocation) throw std::bad_alloc();
  if (void *memory = std::malloc(size ? size : 1)) return memory;
  throw std::bad_alloc();
}
void operator delete(void *memory) noexcept { std::free(memory); }
void operator delete(void *memory, std::size_t) noexcept { std::free(memory); }

namespace {
//------------------------------------------------------------------------------
// Arms the allocation that fails (allocations counted from now); disarmed with -1.
void allocation_failure(long index) {
  allocations = 0;
  failing_allocation = index;
}

//------------------------------------------------------------------------------
// Throws the message when the condition does not hold.
void check(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}

//------------------------------------------------------------------------------
// Fails unless the action throws.
template <class Action> void rejects(Action action, const char *message) {
  bool failed = false;
  try {
    action();
  } catch (const std::exception &) {
    failed = true;
  }
  check(failed, message);
}

//------------------------------------------------------------------------------
// A CSK (purpose tag '2', TS 33.180 annex G) with the CSK-ID [id], active since 30 s and expiring in an hour
// (TS 33.180 annex E.6).
mcx::keying::KeyMessage csk(std::uint32_t id, std::uint8_t seed) {
  mcx::keying::KeyMessage message;
  message.csb_id = id;
  for (unsigned index = 0; index < 16; ++index) {
    message.key[index] = std::uint8_t(seed + index);
    message.random[index] = std::uint8_t(seed + index + 16);
  }
  const auto now = std::uint64_t(std::time(nullptr));
  message.properties = mcx::keying::KeyProperties{2, 1, now - 30, now + 3600, "", {}};
  return message;
}

//------------------------------------------------------------------------------
// An RTCP APP packet (RFC 3550 section 6.7) of five words with the SSRC [ssrc].
Bytes rtcp(std::uint32_t ssrc) {
  return {0x80, 0xcc, 0, 4, std::uint8_t(ssrc >> 24), std::uint8_t(ssrc >> 16), std::uint8_t(ssrc >> 8),
          std::uint8_t(ssrc), 0x4d, 0x43, 0x50, 0x54, 1, 2, 3, 4, 5, 6, 7, 8};
}

//------------------------------------------------------------------------------
// RFC 7714 section 9 and RFC 3711 section 3.4: the SRTCP index of a protected packet (the E flag cleared), before
// the 4-octet MKI (TS 33.180 clause 9.4.6: the CSK-ID).
std::uint32_t srtcp_index(const Bytes &packet) {
  const auto at = packet.size() - 8;
  return ((std::uint32_t(packet[at]) << 24) | (std::uint32_t(packet[at + 1]) << 16) |
          (std::uint32_t(packet[at + 2]) << 8) | packet[at + 3]) &
         0x7fffffffu;
}

//------------------------------------------------------------------------------
// The MKI of a protected floor packet: its last four octets.
std::uint32_t mki(const Bytes &packet) {
  const auto at = packet.size() - 4;
  return (std::uint32_t(packet[at]) << 24) | (std::uint32_t(packet[at + 1]) << 16) |
         (std::uint32_t(packet[at + 2]) << 8) | packet[at + 3];
}

constexpr std::uint32_t client_to_server = 0x11111111, server_to_client = 0x22222222, ended = 0x33333333,
                        fresh = 0x44444444;

//------------------------------------------------------------------------------
// A call goes on across a key download (TS 33.180 clause 5.8): both ends take the new CSK with the call's two
// SSRCs continuing. Each direction's first packet under the new key carries the previous index + 1 and the new
// MKI, and is accepted; a replay is refused; a stream that ended with the old key, and a new one, start at 0.
void rekey_continues_index(bool mcvideo) {
  mcx::ProtectedCall client(mcvideo), server(mcvideo);
  const auto old_key = csk(0x20000001, 0), new_key = csk(0x20000002, 0x40);
  client.set_floor(old_key);
  server.set_floor(old_key);
  Bytes up, down;
  for (unsigned n = 0; n < 3; ++n) {
    up = client.protect_floor(rtcp(client_to_server));
    check(srtcp_index(up) == n, "client index before the re-key");
    check(server.unprotect_floor(up) == rtcp(client_to_server), "server receives under the old key");
  }
  for (unsigned n = 0; n < 2; ++n) {
    down = server.protect_floor(rtcp(server_to_client));
    check(client.unprotect_floor(down) == rtcp(server_to_client), "client receives under the old key");
  }
  // A stream of an earlier call under the old key.
  check(server.unprotect_floor(client.protect_floor(rtcp(ended))) == rtcp(ended), "ended stream");

  const std::set<std::uint32_t> continuing{client_to_server, server_to_client};
  client.set_floor(new_key, continuing);
  server.set_floor(new_key, continuing);

  const auto next_up = client.protect_floor(rtcp(client_to_server));
  check(srtcp_index(next_up) == srtcp_index(up) + 1, "client index continues after the re-key");
  check(mki(next_up) == new_key.csb_id, "client packet under the new CSK");
  check(server.unprotect_floor(next_up) == rtcp(client_to_server), "server accepts the continuing index");
  rejects([&] { server.unprotect_floor(next_up); }, "server refuses a replay under the new key");
  rejects([&] { server.unprotect_floor(up); }, "server refuses a packet under the old key");

  const auto next_down = server.protect_floor(rtcp(server_to_client));
  check(srtcp_index(next_down) == srtcp_index(down) + 1, "server index continues after the re-key");
  check(mki(next_down) == new_key.csb_id, "server packet under the new CSK");
  check(client.unprotect_floor(next_down) == rtcp(server_to_client), "client accepts the continuing index");
  rejects([&] { client.unprotect_floor(next_down); }, "client refuses a replay under the new key");

  const auto restarted = client.protect_floor(rtcp(ended));
  check(srtcp_index(restarted) == 0, "a stream not going on starts again at 0 under the new key");
  check(server.unprotect_floor(restarted) == rtcp(ended), "restarted stream accepted");
  const auto first = server.protect_floor(rtcp(fresh));
  check(srtcp_index(first) == 0, "a new stream under the new key starts at 0");
  check(client.unprotect_floor(first) == rtcp(fresh), "new stream accepted");

  // Without continuing streams the old behaviour is kept: every context ends with the old key.
  client.set_floor(csk(0x20000003, 0x80));
  check(srtcp_index(client.protect_floor(rtcp(client_to_server))) == 0, "no continuing stream: fresh context");
}

//------------------------------------------------------------------------------
// The SSRC a peer allocates for this endpoint's floor control messages (TS 24.380 clause 4.3.3.1).
void peer_ssrc_history() {
  mcx::ProtectedCall server, client;
  const auto key = csk(0x20000001, 0);
  server.set_floor(key);
  client.set_floor(key);
  // The server told the client to send with 0x11111111 in an earlier call, which the client did.
  check(server.unprotect_floor(client.protect_floor(rtcp(client_to_server))) == rtcp(client_to_server), "earlier");
  constexpr std::uint32_t own = 0x55555555, unused = 0x66666666, other_call = 0x77777777;
  const std::set<std::uint32_t> in_use{other_call};
  // A new leg: the peer offers the SSRC it was told to send with before, under the same key: refused.
  check(mcx::floor_ssrc_refused(client_to_server, own, std::nullopt, &server, in_use), "used SSRC refused");
  // The SSRC of another stream under way under the key (no packet yet): refused.
  check(mcx::floor_ssrc_refused(other_call, own, std::nullopt, &server, in_use), "SSRC under way refused");
  // The server's own SSRC for the leg: refused, as before.
  check(mcx::floor_ssrc_refused(own, own, std::nullopt, &server, in_use), "own SSRC refused");
  check(mcx::floor_ssrc_refused(own, own, std::nullopt, nullptr), "own SSRC refused without protection");
  // An unused SSRC: accepted.
  check(!mcx::floor_ssrc_refused(unused, own, std::nullopt, &server, in_use), "unused SSRC accepted");
  // The stream going on (re-INVITE, later answer, refresh) with its SSRC, already carrying packets: accepted.
  server.protect_floor(rtcp(unused));
  check(server.floor_ssrc_used(unused), "the SSRC is used once it carried a packet");
  check(!mcx::floor_ssrc_refused(unused, own, unused, &server, in_use), "continuation accepted");
  // A relay has no SSRC of its own: before the opposite direction is known only the history applies; then the
  // opposite direction's SSRC is refused (RFC 7714 section 8.4), also for a stream that would go on with it.
  constexpr std::uint32_t opposite = 0x88888888;
  check(!mcx::floor_ssrc_refused(opposite, std::nullopt, std::nullopt, &server, in_use), "relay offer accepted");
  check(mcx::floor_ssrc_refused(client_to_server, std::nullopt, std::nullopt, &server, in_use), "relay: used");
  check(mcx::floor_ssrc_refused(opposite, opposite, std::nullopt, &server, in_use), "relay: opposite SSRC refused");
  check(mcx::floor_ssrc_refused(opposite, opposite, opposite, &server, in_use), "relay: opposite before current");
  // Floor control in the clear: no key, so the history does not apply.
  check(!mcx::floor_ssrc_refused(client_to_server, own, std::nullopt, nullptr), "unprotected: not checked");
  // Under a new key the history is that key's: the streams that go on stay used, the others are free again.
  server.set_floor(csk(0x20000002, 0x40), {unused});
  check(server.floor_ssrc_used(unused), "continuing stream used under the new key");
  check(!server.floor_ssrc_used(client_to_server), "ended stream free under the new key");
}

//------------------------------------------------------------------------------
// RFC 3711 section 3.3.2 across a re-key: the receiver's replay list of a stream that goes on is the one it had
// under the old key. The sender sent indices 0 to 5 under the old key and index 3 was lost; under the new key, a
// packet with index 3 is accepted (inside the window, not received) and those with 4 and 5 are refused (received
// under the old key). A receiver whose context ended with the old key accepts them: the check tells the two apart.
void replay_window_kept() {
  constexpr std::uint32_t ssrc = client_to_server;
  const auto old_key = csk(0x20000001, 0), new_key = csk(0x20000002, 0x40);
  mcx::ProtectedCall sender(false), kept(false), restarted(false), forger(false);
  sender.set_floor(old_key);
  kept.set_floor(old_key);
  restarted.set_floor(old_key);
  for (unsigned n = 0; n < 6; ++n) {
    const auto packet = sender.protect_floor(rtcp(ssrc));
    if (n == 3) continue;
    kept.unprotect_floor(packet);
    restarted.unprotect_floor(packet);
  }
  kept.set_floor(new_key, {ssrc});
  restarted.set_floor(new_key);
  // Packets under the new key with the indices 0 to 5 (a stream that started under the new key).
  forger.set_floor(new_key);
  std::vector<Bytes> under_new;
  for (unsigned n = 0; n < 6; ++n) under_new.push_back(forger.protect_floor(rtcp(ssrc)));
  check(srtcp_index(under_new[4]) == 4, "packet with index 4 under the new key");
  check(kept.unprotect_floor(under_new[3]) == rtcp(ssrc), "index lost under the old key accepted");
  rejects([&] { kept.unprotect_floor(under_new[4]); }, "index received under the old key refused");
  rejects([&] { kept.unprotect_floor(under_new[5]); }, "highest index received under the old key refused");
  check(restarted.unprotect_floor(under_new[4]) == rtcp(ssrc), "control: an ended context has no replay list");
}

//------------------------------------------------------------------------------
// SecureStream::rekey: a re-key that fails breaks the stream, so that neither direction is left under the old key
// while the other has the new one; every later packet is refused in both directions.
void failed_rekey_breaks_stream() {
  const auto key = csk(0x20000001, 0);
  auto material = mcx::derive_floor_security(key.key, key.random, key.csb_id, false);
  mcx::SecureStream sender(material, fresh), receiver(material, fresh);
  check(receiver.unprotect_rtcp(sender.protect_rtcp(rtcp(fresh))) == rtcp(fresh), "stream works before");
  auto other = material;
  other.mki.resize(8); // another protection profile: the re-key fails
  rejects([&] { receiver.rekey(other); }, "re-key with another profile refused");
  const auto next = sender.protect_rtcp(rtcp(fresh));
  rejects([&] { receiver.unprotect_rtcp(next); }, "broken stream refuses inbound packets");
  rejects([&] { receiver.protect_rtcp(rtcp(fresh)); }, "broken stream refuses outbound packets");
  rejects([&] { receiver.rekey(material); }, "a broken stream is not repaired by another re-key");
}

//------------------------------------------------------------------------------
// ProtectedCall::set_floor: the new key's SRTCP material is derived before anything changes, so a key whose
// derivation fails (here a key identifier with the purpose tag 4, which derive_floor_security refuses) leaves the
// current key and its contexts as they were: the stream goes on under the old CSK-ID with its index, and the
// receiver under the old key accepts it.
void failed_derivation_keeps_key() {
  const auto old_key = csk(0x20000001, 0);
  mcx::ProtectedCall sender(false), receiver(false);
  sender.set_floor(old_key);
  receiver.set_floor(old_key);
  Bytes last;
  for (unsigned n = 0; n < 3; ++n) {
    last = sender.protect_floor(rtcp(client_to_server));
    receiver.unprotect_floor(last);
  }
  auto invalid = csk(0x40000002, 0x40);
  rejects([&] { sender.set_floor(invalid, {client_to_server}); }, "a key whose derivation fails is refused");
  const auto next = sender.protect_floor(rtcp(client_to_server));
  check(mki(next) == old_key.csb_id, "the old CSK-ID stays the floor key");
  check(srtcp_index(next) == srtcp_index(last) + 1, "the stream's index goes on");
  check(receiver.unprotect_floor(next) == rtcp(client_to_server), "the stream works under the old key");
  check(srtcp_index(sender.protect_floor(rtcp(fresh))) == 0, "a new stream starts under the old key as before");
}

//------------------------------------------------------------------------------
// Whether two key messages are the same in every member set_floor keeps.
bool same_key(const mcx::keying::KeyMessage &first, const mcx::keying::KeyMessage &second) {
  return first.csb_id == second.csb_id && first.key == second.key && first.random == second.random &&
         first.properties == second.properties;
}

//------------------------------------------------------------------------------
// ProtectedCall::set_floor when an allocation fails while it runs, for each allocation in turn (the derivation, the
// copy of the key with the text and groups of its properties, the contexts): after a failure the floor key is
// either the old one in full, its stream going on under the old CSK-ID with its index, or the new one in full; never
// the new properties over the old key or its streams. The re-delivery of the same CSK-ID with new properties too:
// the properties are the old or the new ones in full.
void failed_key_copy_keeps_key() {
  auto old_key = csk(0x20000001, 0), new_key = csk(0x20000002, 0x40);
  old_key.properties->text = std::string(64, 'o');
  old_key.properties->groups = {std::string(64, 'g'), std::string(64, 'h')};
  new_key.properties->text = std::string(64, 'n');
  new_key.properties->groups = {std::string(64, 'x'), std::string(64, 'y'), std::string(64, 'z')};
  new_key.properties->expiry_unix_seconds += 60;
  unsigned failures = 0, kept_old = 0;
  for (long index = 0;; ++index) {
    mcx::ProtectedCall sender(false), receiver(false);
    sender.set_floor(old_key);
    receiver.set_floor(old_key);
    Bytes last;
    for (unsigned n = 0; n < 3; ++n) receiver.unprotect_floor(last = sender.protect_floor(rtcp(client_to_server)));
    bool failed = false;
    allocation_failure(index);
    try {
      sender.set_floor(new_key, {client_to_server});
    } catch (const std::bad_alloc &) {
      failed = true;
    }
    allocation_failure(-1);
    const auto &current = sender.floor_key();
    check(current.has_value(), "a floor key stays");
    if (!failed) {
      check(same_key(*current, new_key), "a completed switch holds the new key in full");
      break;
    }
    ++failures;
    check(same_key(*current, old_key) || same_key(*current, new_key), "after a failure: the old or the new key in full");
    if (same_key(*current, old_key)) {
      ++kept_old;
      const auto next = sender.protect_floor(rtcp(client_to_server));
      check(mki(next) == old_key.csb_id, "the old key's stream goes on under the old CSK-ID");
      check(srtcp_index(next) == srtcp_index(last) + 1, "the old key's stream keeps its index");
      check(receiver.unprotect_floor(next) == rtcp(client_to_server), "the old key's stream works");
    }
    check(index < 1000, "set_floor completes once allocations no longer fail");
  }
  check(failures > 0 && kept_old > 0, "allocation failures were injected before the switch");

  // The same CSK-ID again with new properties.
  auto redelivered = old_key;
  redelivered.properties = new_key.properties;
  for (long index = 0;; ++index) {
    mcx::ProtectedCall keys(false);
    keys.set_floor(old_key);
    bool failed = false;
    allocation_failure(index);
    try {
      keys.set_floor(redelivered);
    } catch (const std::bad_alloc &) {
      failed = true;
    }
    allocation_failure(-1);
    const auto &properties = keys.floor_key()->properties;
    check(properties == old_key.properties || properties == redelivered.properties,
          "re-delivery: the old or the new properties in full");
    if (!failed) {
      check(properties == redelivered.properties, "a completed re-delivery holds the new properties");
      break;
    }
    check(properties == old_key.properties, "a failed re-delivery keeps the old properties");
    check(index < 1000, "the re-delivery completes once allocations no longer fail");
  }
}

//------------------------------------------------------------------------------
// ProtectedCall::issue_ssrc: an SSRC negotiated for a stream that has carried no packet (reserved) is not issued.
void issue_skips_reserved() {
  mcx::ProtectedCall keys(false);
  keys.set_floor(csk(0x20000001, 0));
  std::vector<std::uint32_t> draws{fresh, ended, fresh};
  std::size_t at = 0;
  const auto draw = [&] { return draws.at(at++); };
  check(keys.issue_ssrc(draw, {fresh}) == ended, "reserved SSRC skipped");
  check(keys.issue_ssrc(draw) == fresh, "not reserved: issued");
}
} // namespace

int main() {
#ifndef SRTP_OPENMCX_SRTCP_INDEX_ZERO
  std::cout << "skipped: libsrtp without OpenMCX's patch (dependencies/libsrtp), its first SRTCP index is 1\n";
  return 77;
#else
  unsigned failures = 0;
  for (auto test : {std::pair<const char *, std::function<void()>>{"rekey_continues_index_mcptt",
                                                                    [] { rekey_continues_index(false); }},
                    {"rekey_continues_index_mcvideo", [] { rekey_continues_index(true); }},
                    {"peer_ssrc_history", peer_ssrc_history},
                    {"replay_window_kept", replay_window_kept},
                    {"failed_rekey_breaks_stream", failed_rekey_breaks_stream},
                    {"failed_derivation_keeps_key", failed_derivation_keeps_key},
                    {"failed_key_copy_keeps_key", failed_key_copy_keeps_key},
                    {"issue_skips_reserved", issue_skips_reserved}}) {
    try {
      test.second();
      std::cout << "PASS " << test.first << '\n';
    } catch (const std::exception &error) {
      std::cerr << "FAIL " << test.first << ": " << error.what() << '\n';
      ++failures;
    }
  }
  return failures ? 1 : 0;
#endif
}
