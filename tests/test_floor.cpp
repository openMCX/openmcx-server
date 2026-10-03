// Floor control: the MCPT message and field codec, the floor control server arbitration and the floor participant
// timers of TS 24.380 (clauses 6.2.4, 6.3.4, 6.3.5, 8.1 and 8.2).
//
// Specifications: TS 24.380 V19.2.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19).

// Keep wire-format assertions active in release image builds too.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "mcx/floor.hpp"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using Bytes = std::vector<std::uint8_t>;

//------------------------------------------------------------------------------
// Checks that the action throws std::runtime_error (a refused encode or decode).
template <typename F> void expect_runtime_error(F &&action) {
  bool threw = false;
  try {
    action();
  } catch (const std::runtime_error &) {
    threw = true;
  }
  assert(threw);
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.1.2 and clause 8.1.3: the fixture decodes to the given header (subtype ack bit, SSRC) and
// fields, and the same packet encodes back to the fixture byte for byte.
void expect_packet(const Bytes &fixture, mcx::FloorType type, bool ack_required, std::uint32_t ssrc,
                   const std::vector<mcx::FloorField> &fields) {
  const auto decoded = mcx::decode_floor(fixture);
  assert(decoded.type == type);
  assert(decoded.ack_required == ack_required);
  assert(decoded.ssrc == ssrc);
  assert(decoded.fields == fields);

  const mcx::FloorPacket packet{type, ack_required, ssrc, fields};
  assert(mcx::encode_floor(packet) == fixture);
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.4 (Floor Request), clause 8.2.5 (Floor Granted), clause 8.2.9 (Floor Taken), clause 8.2.6
// (Floor Deny), clause 8.2.7 (Floor Release), clause 8.2.8 (Floor Idle) and clause 8.2.13 (Floor Ack): hand-built
// packets round-trip byte for byte; the Audio SSRC of Granted Participant field (clause 8.2.3.16) has length 6 and
// zero spare octets.
void test_literal_packets() {
  // Hand-derived from TS 24.380 clause 8.1.2, clause 8.1.3, and clauses 8.2.3 to 8.2.13.
  const Bytes request{
      0x80, 0xcc, 0x00, 0x03, 0x01, 0x02, 0x03, 0x04, 0x4d, 0x43, 0x50, 0x54, 0x00, 0x02, 0x07, 0x00,
  };
  expect_packet(request, mcx::FloorType::Request, false, 0x01020304, {{0, {0x07, 0x00}}});

  const Bytes granted{
      0x91, 0xcc, 0x00, 0x06, 0x0a, 0x0b, 0x0c, 0x0d, 0x4d, 0x43, 0x50, 0x54, 0x01, 0x02,
      0x00, 0x1e, 0x0e, 0x06, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x02, 0x05, 0x00,
  };
  expect_packet(granted, mcx::FloorType::Granted, true, 0x0a0b0c0d,
                {{1, {0x00, 0x1e}}, {14, {0x11, 0x22, 0x33, 0x44, 0x00, 0x00}}, {0, {0x05, 0x00}}});

  // TS 24.380 clause 8.2.3.16: SSRC length includes both reserved octets.
  // A trailing SSRC exposed a read beyond the packet in the dissector.
  const Bytes taken{
      0x82, 0xcc, 0x00, 0x04, 0x0a, 0x0b, 0x0c, 0x0d, 0x4d, 0x43,
      0x50, 0x54, 0x0e, 0x06, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00,
  };
  expect_packet(taken, mcx::FloorType::Taken, false, 0x0a0b0c0d, {mcx::audio_ssrc_field(0x11223344)});
  auto old_encoding = taken;
  old_encoding[13] = 4;
  expect_runtime_error([&] { (void)mcx::decode_floor(old_encoding); });
  auto nonzero_spare = taken;
  nonzero_spare[18] = 1;
  expect_runtime_error([&] { (void)mcx::decode_floor(nonzero_spare); });
  nonzero_spare = taken;
  nonzero_spare[19] = 1;
  expect_runtime_error([&] { (void)mcx::decode_floor(nonzero_spare); });

  const Bytes deny{
      0x83, 0xcc, 0x00, 0x03, 0x10, 0x20, 0x30, 0x40, 0x4d, 0x43, 0x50, 0x54, 0x02, 0x02, 0x00, 0x01,
  };
  expect_packet(deny, mcx::FloorType::Deny, false, 0x10203040, {{2, {0x00, 0x01}}});

  const Bytes release{
      0x94, 0xcc, 0x00, 0x02, 0x7f, 0x00, 0x00, 0x01, 0x4d, 0x43, 0x50, 0x54,
  };
  expect_packet(release, mcx::FloorType::Release, true, 0x7f000001, {});

  const Bytes idle{
      0x85, 0xcc, 0x00, 0x03, 0xde, 0xad, 0xbe, 0xef, 0x4d, 0x43, 0x50, 0x54, 0x08, 0x02, 0x12, 0x34,
  };
  expect_packet(idle, mcx::FloorType::Idle, false, 0xdeadbeef, {{8, {0x12, 0x34}}});

  const Bytes ack{
      0x8a, 0xcc, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd, 0x4d, 0x43,
      0x50, 0x54, 0x0c, 0x02, 0x04, 0x00, 0x0a, 0x02, 0x00, 0x02,
  };
  expect_packet(ack, mcx::FloorType::Ack, false, 0xaabbccdd, {{12, {0x04, 0x00}}, {10, {0x00, 0x02}}});
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3 (table 8.2.3.1-2): the field helpers for User ID (clause 8.2.3.8), Floor Priority
// (clause 8.2.3.2), Duration (clause 8.2.3.3), Reject Cause (clause 8.2.3.4), Audio SSRC of Granted Participant
// (clause 8.2.3.16), Message Sequence Number (clause 8.2.3.10), Source (clause 8.2.3.12) and Message Type
// (clause 8.2.3.14) write and read their values and refuse wrong lengths and values.
void test_field_helpers() {
  const auto user = mcx::user_id_field("sip:alice@example.test");
  assert(user.id == 6);
  assert(mcx::read_user_id(user) == "sip:alice@example.test");

  assert(mcx::read_priority(mcx::priority_field(197)) == 197);
  assert(mcx::read_duration(mcx::duration_field(300)) == 300);
  const auto cause = mcx::read_reject_cause(mcx::reject_cause_field(255, "policy"));
  assert(cause.cause == 255);
  assert(cause.phrase == "policy");
  assert(mcx::audio_ssrc_field(0x89abcdef).value == Bytes({0x89, 0xab, 0xcd, 0xef, 0, 0}));
  assert(mcx::read_audio_ssrc(mcx::audio_ssrc_field(0x89abcdef)) == 0x89abcdef);
  expect_runtime_error([] { (void)mcx::read_audio_ssrc({14, {1, 2, 3, 4}}); });
  expect_runtime_error([] { (void)mcx::read_audio_ssrc({14, {1, 2, 3, 4, 0, 1}}); });
  expect_runtime_error([] { (void)mcx::encode_floor({mcx::FloorType::Taken, false, 1, {{14, {1, 2, 3, 4}}}}); });
  assert(mcx::read_message_sequence(mcx::message_sequence_field(65535)) == 65535);
  assert(mcx::read_source(mcx::source_field(2)) == 2);
  assert(mcx::read_message_type(mcx::message_type_field(mcx::FloorType::Release)) == mcx::FloorType::Release);

  expect_runtime_error([] { (void)mcx::read_priority({0, {1}}); });
  expect_runtime_error([] { (void)mcx::read_priority({0, {1, 1}}); });
  expect_runtime_error([] { (void)mcx::read_source({10, {0, 4}}); });
  expect_runtime_error([] { (void)mcx::read_message_type({12, {0x1f, 0}}); });
  expect_runtime_error([] { (void)mcx::read_user_id({6, {}}); });
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.1.2 and clause 8.2.2.1 (table 8.2.2.1-1): truncated packets, a wrong RTCP version,
// padding, payload type or name, a wrong length, an unsupported subtype, an ack bit on a message without one and
// a field running past the packet are refused; oversized fields and a Floor Ack without fields are not encoded.
void test_bounds_and_malformed_packets() {
  const Bytes request{
      0x80, 0xcc, 0x00, 0x03, 0x01, 0x02, 0x03, 0x04, 0x4d, 0x43, 0x50, 0x54, 0x00, 0x02, 0x07, 0x00,
  };
  for (std::size_t size = 0; size < request.size(); ++size) {
    expect_runtime_error([&] { (void)mcx::decode_floor(std::span<const std::uint8_t>(request.data(), size)); });
  }

  auto malformed = request;
  malformed[0] = 0x40; // RTCP version 1
  expect_runtime_error([&] { (void)mcx::decode_floor(malformed); });
  malformed = request;
  malformed[0] = 0xa0; // RTCP padding is forbidden for MCPT messages
  expect_runtime_error([&] { (void)mcx::decode_floor(malformed); });
  malformed = request;
  malformed[1] = 203;
  expect_runtime_error([&] { (void)mcx::decode_floor(malformed); });
  malformed = request;
  malformed[8] = 'X';
  expect_runtime_error([&] { (void)mcx::decode_floor(malformed); });
  malformed = request;
  malformed[3] = 4; // declared length exceeds buffer
  expect_runtime_error([&] { (void)mcx::decode_floor(malformed); });
  malformed = request;
  malformed.push_back(0); // undeclared trailing octet
  expect_runtime_error([&] { (void)mcx::decode_floor(malformed); });
  malformed = request;
  malformed[0] = 0x87; // unsupported Floor Revoke Request subtype
  expect_runtime_error([&] { (void)mcx::decode_floor(malformed); });
  malformed = request;
  malformed[0] = 0x90; // Request has no acknowledgement-bit form
  expect_runtime_error([&] { (void)mcx::decode_floor(malformed); });
  malformed = request;
  malformed[13] = 3; // field value runs into missing bytes
  expect_runtime_error([&] { (void)mcx::decode_floor(malformed); });

  expect_runtime_error([] {
    mcx::FloorPacket packet{mcx::FloorType::Request, false, 1, {{0, Bytes(256, 0)}}};
    (void)mcx::encode_floor(packet);
  });
  expect_runtime_error([] {
    mcx::FloorPacket packet{mcx::FloorType::Ack, true, 1, {}};
    (void)mcx::encode_floor(packet);
  });
  expect_runtime_error([] {
    mcx::FloorPacket packet{mcx::FloorType::Ack, false, 1, {}};
    (void)mcx::encode_floor(packet);
  });
  const Bytes empty_ack{
      0x8a, 0xcc, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x4d, 0x43, 0x50, 0x54,
  };
  expect_runtime_error([&] { (void)mcx::decode_floor(empty_ack); });
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.1.3 (table 8.1.3-2) and clause 8.1.4: a field with ID 192 or above (2-octet length)
// round-trips, and its padding is ignored on receipt.
void test_unknown_extension_field() {
  const Bytes fixture{
      0x84, 0xcc, 0x00, 0x04, 0x01, 0x00, 0x00, 0x01, 0x4d, 0x43,
      0x50, 0x54, 0xc8, 0x00, 0x02, 0xaa, 0xbb, 0x00, 0x00, 0x00,
  };
  expect_packet(fixture, mcx::FloorType::Release, false, 0x01000001, {{200, {0xaa, 0xbb}}});

  auto nonzero_padding = fixture;
  nonzero_padding.back() = 0xff;
  const auto decoded = mcx::decode_floor(nonzero_padding);
  assert((decoded.fields == std::vector<mcx::FloorField>{{200, {0xaa, 0xbb}}}));
}

//------------------------------------------------------------------------------
// Checks one notice from the floor arbitrator: its kind, recipient, participant and reject cause.
void assert_notice(const mcx::FloorNotice &notice, mcx::FloorNoticeKind kind, std::string recipient,
                   std::string participant, std::uint16_t cause = 0) {
  assert(notice.kind == kind);
  assert(notice.recipient == recipient);
  assert(notice.participant == participant);
  assert(notice.reject_cause == cause);
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 8.2.3.5 to 8.2.3.7, 8.2.3.9, 8.2.3.11, 8.2.3.15 and 8.2.3.21: the on-network fields
// (Queue Info, Granted Party's Identity, Permission to Request the Floor, Queue Size, Queued User ID, Floor
// Indicator, Location); a Floor Taken (clause 8.2.9) byte for byte; the Message Sequence Number (clause 8.2.3.10)
// tracker with wraparound; and the retransmission of an ack-required message until the matching Floor Ack
// (clause 8.2.13) arrives.
void test_on_network_fields_and_reliability() {
  // TS 24.380 clauses 8.2.3.5 to 8.2.3.7 and clause 8.2.3.15: fixed hand-derived field octets.
  assert((mcx::granted_party_identity_field("sip:a@b") == mcx::FloorField{4, {'s', 'i', 'p', ':', 'a', '@', 'b'}}));
  assert(mcx::read_granted_party_identity(mcx::granted_party_identity_field("sip:a@b")) == "sip:a@b");
  assert((mcx::permission_to_request_field(true) == mcx::FloorField{5, {0, 1}}));
  assert(!mcx::read_permission_to_request({5, {0, 0}}));
  expect_runtime_error([] { (void)mcx::read_permission_to_request({5, {0, 2}}); });
  assert((mcx::floor_indicator_field(0x8000) == mcx::FloorField{13, {0x80, 0}}));
  assert(mcx::read_floor_indicator({13, {0x84, 0}}) == 0x8400);
  assert((mcx::location_not_provided_field() == mcx::FloorField{19, {0}}));
  assert((mcx::queue_info_field(254, 7) == mcx::FloorField{3, {254, 7}}));
  assert(mcx::read_queue_info({3, {255, 7}}).position == 255);
  expect_runtime_error([] { (void)mcx::encode_floor({mcx::FloorType::Request, false, 1, {{13, {1}}}}); });
  mcx::FloorPacket taken{mcx::FloorType::Taken,
                         true,
                         8,
                         {mcx::granted_party_identity_field("sip:a@b"), mcx::permission_to_request_field(true),
                          mcx::message_sequence_field(65535), mcx::audio_ssrc_field(9)}};
  mcx::validate_on_network_floor(taken);
  const Bytes literal_taken{
      0x92, 0xcc, 0x00, 0x09, 0, 0, 0, 8, 'M', 'C', 'P',  'T',  4,  7, 's', 'i', 'p', ':', 'a', '@',
      'b',  0,    0,    0,    5, 2, 0, 1, 8,   2,   0xff, 0xff, 14, 6, 0,   0,   0,   9,   0,   0,
  };
  assert(mcx::encode_floor(taken) == literal_taken);
  assert(mcx::decode_floor(literal_taken) == taken);
  assert((mcx::queue_size_field(258) == mcx::FloorField{7, {1, 2}}));
  assert(mcx::read_queue_size({7, {1, 2}}) == 258);
  assert(mcx::read_queued_user_id(mcx::queued_user_id_field("sip:a@b")) == "sip:a@b");
  expect_runtime_error([] { (void)mcx::floor_indicator_field(0xc000); });
  expect_runtime_error([] { (void)mcx::floor_indicator_field(0x8001); });
  expect_runtime_error([] { (void)mcx::FloorAckRetry(1, 2, 0, 0); });
  auto missing = taken;
  missing.fields.pop_back();
  expect_runtime_error([&] { mcx::validate_on_network_floor(missing); });
  missing = taken;
  missing.fields.push_back(mcx::message_sequence_field(0));
  expect_runtime_error([&] { mcx::validate_on_network_floor(missing); });
  mcx::FloorSequenceTracker sequence;
  assert(sequence.accept(taken));
  assert(!sequence.accept(taken));
  mcx::FloorPacket idle{mcx::FloorType::Idle, true, 8, {mcx::message_sequence_field(0)}};
  assert(sequence.accept(idle));   // wraparound, same stream across Taken and Idle
  assert(!sequence.accept(taken)); // stale state must not restore a former talker
  mcx::FloorAckRetry retry(7, 8, 2, 100, 3);
  idle.ssrc = 7;
  retry.send(idle, 0);
  assert(retry.pending() == 1);
  assert(retry.tick(99).empty());
  assert(retry.tick(100) == std::vector<mcx::FloorPacket>{idle});
  mcx::FloorPacket ack{
      mcx::FloorType::Ack, false, 8, {mcx::source_field(2), mcx::message_type_field(mcx::FloorType::Idle)}};
  auto forged = ack;
  forged.ssrc = 9;
  assert(!retry.receive(forged));
  forged = ack;
  forged.fields[0] = mcx::source_field(0);
  assert(!retry.receive(forged));
  forged = ack;
  forged.fields[1] = mcx::message_type_field(mcx::FloorType::Taken);
  assert(!retry.receive(forged));
  assert(retry.receive(ack));
  assert(retry.pending() == 0);
  assert(retry.tick(200).empty());
  retry.send(idle, 300);
  assert(retry.tick(400).size() == 1);
  assert(retry.tick(500).size() == 1);
  assert(retry.tick(600).empty());
  assert(retry.pending() == 0);
  assert(retry.take_failed() == std::vector<mcx::FloorType>{mcx::FloorType::Idle});
  assert(retry.take_failed().empty());
  retry.send(idle, 700);
  retry.cancel(mcx::FloorType::Idle);
  assert(retry.pending() == 0);
  assert(retry.tick(800).empty());
  idle.ack_required = false;
  retry.send(idle, 900);
  assert(retry.pending() == 0);
  sequence.reset();
  assert(sequence.accept(taken));
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.4.3.3 (Floor Request in 'G: Floor Idle'), clause 6.3.4.4.8 (Floor Request while taken:
// Floor Deny, clause 8.2.6.2 cause #1 or cause #255), clause 6.3.4.4.6 (Floor Release) and clause 6.3.4.4.4
// (timer T2 (Stop talking) expired): grants, Floor Taken, denials, idle and revoke notices to every participant.
void test_arbitration() {
  // The call-handling core holds the arbitrator as a MediaPlaneController.
  {
    std::unique_ptr<mcx::MediaPlaneController> control =
        std::make_unique<mcx::FloorArbitrator>(std::vector<std::string>{"alice", "bob"}, 1000);
    const auto grant = control->request("alice", 100);
    assert(grant.size() == 2);
    assert_notice(grant[0], mcx::FloorNoticeKind::Granted, "alice", "alice");
    assert(control->owner() == std::optional<std::string>{"alice"} && control->state() == mcx::FloorState::Taken);
    control->release("alice", 200);
    assert(!control->owner().has_value());
  }
  mcx::FloorArbitrator floor({"carol", "alice", "bob", "alice"}, 1000);
  assert(!floor.owner().has_value());
  assert(floor.is_authorized("alice"));

  const auto grant = floor.request("alice", 100);
  assert(grant.size() == 3);
  assert_notice(grant[0], mcx::FloorNoticeKind::Granted, "alice", "alice");
  assert_notice(grant[1], mcx::FloorNoticeKind::Taken, "bob", "alice");
  assert_notice(grant[2], mcx::FloorNoticeKind::Taken, "carol", "alice");
  assert(floor.owner() == std::optional<std::string>{"alice"});

  assert(floor.request("alice", 200).empty()); // duplicate is idempotent
  const auto denied = floor.request("bob", 300);
  assert(denied.size() == 1);
  assert_notice(denied[0], mcx::FloorNoticeKind::Denied, "bob", "alice", 1);
  const auto unauthorized = floor.request("mallory", 400);
  assert(unauthorized.size() == 1);
  assert_notice(unauthorized[0], mcx::FloorNoticeKind::Denied, "mallory", "alice", 255);

  assert(floor.release("bob", 500).empty());
  assert(floor.owner() == std::optional<std::string>{"alice"});
  const auto idle = floor.release("alice", 600);
  assert(idle.size() == 3);
  assert_notice(idle[0], mcx::FloorNoticeKind::Idle, "alice", "");
  assert_notice(idle[1], mcx::FloorNoticeKind::Idle, "bob", "");
  assert_notice(idle[2], mcx::FloorNoticeKind::Idle, "carol", "");
  assert(!floor.owner().has_value());

  // TS 24.380 clause 6.3.4.4.5: T2 starts with the first RTP packet, not with the grant; clause 6.3.4.4.4: its
  // expiry revokes with cause #2 (Media burst too long).
  (void)floor.request("bob", 1000);
  assert(floor.tick(2500).empty());
  floor.media_received("bob", 2500);
  assert(floor.tick(3499).empty());
  const auto timeout = floor.tick(3500);
  assert(timeout.size() == 4);
  assert_notice(timeout[0], mcx::FloorNoticeKind::Revoke, "bob", "bob", 2);
  assert_notice(timeout[1], mcx::FloorNoticeKind::Idle, "alice", "");
  assert_notice(timeout[2], mcx::FloorNoticeKind::Idle, "bob", "");
  assert_notice(timeout[3], mcx::FloorNoticeKind::Idle, "carol", "");
  assert(!floor.owner().has_value());
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.4.4.4 (timer T2 expired: Floor Revoke, clause 8.2.10.2 cause #2), clause 6.3.4.5
// ('G: pending Floor Revoke', with the Floor Revoke repeated on timer T8, clause 6.3.5.6.3), clause 6.3.4.5.5
// (timer T3 (Stop talking grace) expired: the queued request with the highest priority is granted), clause
// 6.3.4.4.8 (queued Floor Request, Floor Queue Position Info) and clause 6.3.4.4.3 and clause 6.3.4.5.6 (timer T1
// (End of RTP media) expired).
void test_timed_arbitration_and_queue() {
  mcx::FloorArbitratorOptions options;
  options.max_talk_ms = 1000;
  options.media_idle_ms = 4000;
  options.revoke_grace_ms = 500;
  options.revoke_retry_ms = 200;
  options.queue_enabled = true;
  mcx::FloorArbitrator floor({"a", "b", "c", "d"}, options);
  (void)floor.request("a", 0, 3);
  assert(floor.tick(1000).empty()); // T2 starts on first media, not grant
  floor.media_received("a", 1000);
  assert(floor.request("b", 1100, 3, true)[0].kind == mcx::FloorNoticeKind::QueuePosition);
  assert(floor.request("c", 1200, 9, true)[0].queue_position == 1);
  assert(floor.queue_position("b").queue_position == 2);
  assert(floor.request("d", 1300, 7, false)[0].kind == mcx::FloorNoticeKind::Denied);
  assert(floor.tick(1999).empty());
  const auto revoke = floor.tick(2000);
  assert(revoke.size() == 1 && revoke[0].kind == mcx::FloorNoticeKind::Revoke);
  assert(revoke[0].reject_cause == 2);
  assert(floor.state() == mcx::FloorState::PendingRevoke);
  assert(floor.owner() == "a"); // media may continue during grace
  assert(floor.tick(2199).empty());
  assert(floor.tick(2200)[0].kind == mcx::FloorNoticeKind::Revoke);
  const auto next = floor.tick(2500);
  assert(next[0].kind == mcx::FloorNoticeKind::Granted);
  assert(next[0].recipient == "c" && next[0].priority == 9);
  assert(floor.owner() == "c");
  (void)floor.release("b", 2600); // queued user cancels its request
  assert(floor.queue_position("b").queue_position == 254);
  assert(floor.tick(6499)[0].kind == mcx::FloorNoticeKind::Granted);
  const auto no_media = floor.tick(6500);
  assert(no_media[0].kind == mcx::FloorNoticeKind::Idle);
  assert(floor.state() == mcx::FloorState::Idle);
  (void)floor.request("a", 7000);
  floor.media_received("a", 7100);
  (void)floor.tick(8100);
  assert(floor.release("a", 8200)[0].kind == mcx::FloorNoticeKind::Idle);
  assert(floor.tick(9000).empty());
  // End-of-media supervision remains active during stop-talking grace.
  options.media_idle_ms = 300;
  options.max_talk_ms = 100;
  mcx::FloorArbitrator silent({"a", "b"}, options);
  (void)silent.request("a", 0);
  silent.media_received("a", 0);
  assert(silent.tick(100)[0].kind == mcx::FloorNoticeKind::Revoke);
  silent.media_received("a", 150);
  assert(silent.tick(450)[0].kind == mcx::FloorNoticeKind::Idle);
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.4.4.9 and clause 6.3.4.4.10: the Floor Granted to a queued participant is repeated on
// timer T20 (Floor Granted) up to counter C20; then timer T1 (clause 6.3.4.4.3) moves on to the next queued
// participant, whose first RTP media stops T20.
void test_queued_grant_retransmission() {
  mcx::FloorArbitratorOptions options;
  options.queue_enabled = true;
  options.grant_retry_ms = 100;
  options.max_grant_transmissions = 3;
  options.media_idle_ms = 500;
  mcx::FloorArbitrator floor({"a", "b", "c"}, options);
  (void)floor.request("a", 0);
  (void)floor.request("b", 1, 7, true);
  (void)floor.request("c", 2, 4, true);
  (void)floor.release("a", 10);
  assert(floor.awaiting_grant_media());
  assert(floor.tick(109).empty());
  const auto repeat = floor.tick(110);
  assert(repeat.size() == 1 && repeat[0].kind == mcx::FloorNoticeKind::Granted);
  assert(repeat[0].recipient == "b" && repeat[0].priority == 7);
  assert(floor.tick(210).size() == 1);
  assert(floor.tick(310).empty());
  assert(floor.owner() == "b");      // C20 exhaustion alone does not free floor
  const auto next = floor.tick(510); // T1 advances queued participant
  assert(next[0].kind == mcx::FloorNoticeKind::Granted && next[0].recipient == "c");
  floor.media_received("c", 520);
  assert(!floor.awaiting_grant_media());
  assert(floor.tick(610).empty()); // first RTP stops T20
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.2.4.4.5 and clause 6.2.4.4.6 (timer T101 (Floor Request) expired, N times), clause
// 6.2.4.4.9 (Floor Queue Position Info: 'U: queued'), clause 6.2.4.9.9 to clause 6.2.4.9.11 (timer T104 (Floor
// Queue Position Request)), clause 6.2.4.9.4, clause 6.2.4.9.12 and clause 6.2.4.9.13 (queued Floor Granted, user
// accept and timer T132 (Queued granted user action)), clause 6.2.4.6.2 and clause 6.2.4.6.3 (timer T100 (Floor
// Release)) and clause 6.2.4.3.6 (timer T103 (End of RTP media)).
void test_participant_timers() {
  mcx::FloorParticipantTimerOptions options{100, 100, 100, 300, 200, 3};
  mcx::FloorParticipantTimers timers(options);
  mcx::FloorPacket request{mcx::FloorType::Request, false, 7, {}};
  timers.send(request, 0);
  assert(timers.state() == mcx::FloorParticipantState::PendingRequest);
  assert(timers.tick(100) == std::vector<mcx::FloorPacket>{request});
  assert(timers.tick(200).size() == 1);
  assert(timers.tick(300).empty());
  assert(timers.state() == mcx::FloorParticipantState::NoPermission);
  assert(timers.take_failed() == std::vector<mcx::FloorType>{mcx::FloorType::Request});
  timers.send(request, 400);
  mcx::FloorPacket queue{mcx::FloorType::QueuePositionInfo, true, 8, {mcx::queue_info_field(1, 3)}};
  timers.receive(queue, 410);
  assert(timers.state() == mcx::FloorParticipantState::Queued);
  assert(timers.tick(500).empty());
  const mcx::FloorPacket query{mcx::FloorType::QueuePositionRequest, false, 7, {}};
  timers.send(query, 510);
  assert(timers.tick(610) == std::vector<mcx::FloorPacket>{query});
  timers.receive(queue, 620);
  assert(timers.tick(710).empty());
  mcx::FloorPacket granted{
      mcx::FloorType::Granted, true, 8, {mcx::duration_field(30), mcx::priority_field(3), mcx::audio_ssrc_field(9)}};
  timers.receive(granted, 800);
  assert(timers.awaiting_user_confirmation());
  assert(timers.confirm_queued_grant());
  assert(timers.state() == mcx::FloorParticipantState::HasPermission);
  assert(timers.tick(1000).empty());
  mcx::FloorPacket release{mcx::FloorType::Release, true, 7, {}};
  timers.send(release, 1100);
  assert(timers.tick(1200) == std::vector<mcx::FloorPacket>{release});
  mcx::FloorPacket idle{mcx::FloorType::Idle, true, 8, {mcx::message_sequence_field(1)}};
  timers.receive(idle, 1210);
  assert(timers.tick(1300).empty());
  timers.media_received(1400);
  assert(timers.remote_media_active());
  (void)timers.tick(1700);
  assert(!timers.remote_media_active());
  timers.send(request, 1800);
  timers.receive(queue, 1810);
  timers.receive(granted, 1820);
  timers.receive(granted, 1900); // repeated grant must not reset T132
  const auto abandoned = timers.tick(2020);
  assert(abandoned.size() == 1 && abandoned[0].type == mcx::FloorType::Release);
  assert(abandoned[0].ssrc == 7);
  assert(timers.state() == mcx::FloorParticipantState::NoPermission);
  assert(timers.tick(2120).empty());
  timers.send(request, 2200);
  timers.receive(queue, 2210);
  timers.send(query, 2220);
  assert(timers.tick(2320).size() == 1);
  assert(timers.tick(2420).size() == 1);
  const auto query_timeout = timers.tick(2520);
  assert(query_timeout.size() == 1 && query_timeout[0].type == mcx::FloorType::Release);
  assert(timers.state() == mcx::FloorParticipantState::PendingRelease);
  assert(timers.take_failed() == std::vector<mcx::FloorType>{mcx::FloorType::QueuePositionRequest});
  assert(timers.tick(2620).size() == 1);
  assert(timers.tick(2720).size() == 1);
  assert(timers.tick(2820).empty());
  assert(timers.state() == mcx::FloorParticipantState::NoPermission);
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.2.4.6: in 'U: pending Release' a delayed Floor Granted does not regain the floor
// (clause 6.2.4.6.8), a Floor Ack does not end the state, and Floor Taken ends it (clause 6.2.4.6.5).
void test_release_state_reordering() {
  mcx::FloorParticipantTimers timers({100, 100, 100, 300, 200, 3});
  const mcx::FloorPacket request{mcx::FloorType::Request, false, 7, {}};
  const mcx::FloorPacket granted{
      mcx::FloorType::Granted, true, 8, {mcx::duration_field(30), mcx::priority_field(0), mcx::audio_ssrc_field(9)}};
  const mcx::FloorPacket release{mcx::FloorType::Release, true, 7, {}};
  const mcx::FloorPacket ack{
      mcx::FloorType::Ack, false, 8, {mcx::source_field(2), mcx::message_type_field(mcx::FloorType::Release)}};
  const mcx::FloorPacket taken{
      mcx::FloorType::Taken, true, 8, {mcx::message_sequence_field(2), mcx::audio_ssrc_field(10)}};
  timers.send(request, 0);
  timers.receive(granted, 10);
  timers.send(release, 20);
  timers.receive(granted, 30); // TS 24.380 clause 6.2.4.6.8: delayed Granted does not regain floor
  assert(timers.state() == mcx::FloorParticipantState::PendingRelease);
  timers.receive(ack, 40); // ACK policy does not replace a server state indication
  assert(timers.tick(120) == std::vector<mcx::FloorPacket>{release});
  timers.receive(taken, 130); // TS 24.380 clause 6.2.4.6.5 resolves queued/nonowner cancellation
  assert(timers.state() == mcx::FloorParticipantState::NoPermission);
  assert(timers.tick(220).empty());
  timers.receive(granted, 230); // unsolicited stale grant remains ignored
  assert(timers.state() == mcx::FloorParticipantState::NoPermission);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.4 and TS 24.380 clause 6.2.4.2.2: with an implicit floor request the participant
// waits in 'U: pending Request' without sending or repeating a Floor Request, and enters 'U: has permission'
// on Floor Granted (clause 6.2.4.4.2).
void test_implicit_grant() {
  mcx::FloorParticipantTimers timers({100, 100, 100, 300, 200, 3});
  const mcx::FloorPacket granted{
      mcx::FloorType::Granted, true, 8, {mcx::duration_field(30), mcx::priority_field(0), mcx::audio_ssrc_field(9)}};
  timers.expect_implicit_grant(); // TS 24.379 clause 6.4: no Floor Request is sent
  assert(timers.state() == mcx::FloorParticipantState::PendingRequest);
  assert(timers.tick(1000).empty()); // nothing to retransmit
  assert(timers.take_failed().empty());
  timers.receive(granted, 1010);
  assert(timers.state() == mcx::FloorParticipantState::HasPermission);
  bool refused = false;
  try {
    timers.expect_implicit_grant();
  } catch (const std::runtime_error &) {
    refused = true;
  }
  assert(refused);
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.4.3.4: the Floor Idle is repeated on timer T7 (Floor Idle) up to counter C7, also
// after a Floor Release returns the floor to 'G: Floor Idle'.
void test_idle_retransmissions() {
  mcx::FloorArbitratorOptions options;
  assert(options.revoke_grace_ms == 3000);
  options.idle_retry_ms = 100;
  options.max_idle_transmissions = 3;
  mcx::FloorArbitrator floor({"a", "b"}, options);
  floor.start_idle(0); // caller sent the initial Idle while admitting the call
  assert(floor.tick(99).empty());
  assert(floor.tick(100).size() == 2);
  assert(floor.tick(200).size() == 2);
  assert(floor.tick(300).empty());
  (void)floor.request("a", 400);
  assert(floor.tick(500).empty());
  (void)floor.release("a", 600); // returned Idle counts as the first transmission
  assert(floor.tick(700).size() == 2);
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.5.2.2: a participant joining an ongoing call gets Floor Idle, or Floor Taken naming
// the current talker; a participant removed from the call loses its queued request.
void test_dynamic_authorization() {
  mcx::FloorArbitratorOptions options;
  options.queue_enabled = true;
  mcx::FloorArbitrator floor({"a", "b"}, options);
  const auto idle = floor.add("c");
  assert(idle.size() == 1);
  assert_notice(idle[0], mcx::FloorNoticeKind::Idle, "c", "");
  assert(floor.add("c").empty());
  assert(floor.is_authorized("c"));
  expect_runtime_error([&] { (void)floor.add(""); });
  (void)floor.request("a", 0, 7);
  (void)floor.request("b", 1, 3, true);
  const auto taken = floor.add("d");
  assert(taken.size() == 1);
  assert_notice(taken[0], mcx::FloorNoticeKind::Taken, "d", "a");
  assert(taken[0].priority == 7);
  assert(floor.owner() == "a");
  assert(floor.queue_position("b").queue_position == 1);
  assert(floor.request("d", 2, 2, true)[0].queue_position == 2);
  const auto next = floor.release("a", 3);
  assert(next[0].recipient == "b");
  assert(floor.owner() == "b");
  (void)floor.remove("d", 4);
  assert(!floor.is_authorized("d"));
  assert(floor.queue_position("d").queue_position == 254);
  assert(floor.owner() == "b");
  (void)floor.add("d");
  (void)floor.release("b", 5);
  assert(floor.request("d", 6)[0].kind == mcx::FloorNoticeKind::Granted);
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.4.4.7: a Floor Request with pre-emptive priority revokes the current talker
// (Floor Revoke, clause 8.2.10.2 cause #4) and is granted after the grace period; an equal or lower priority is
// denied.
void test_preemptive_floor_request() {
  mcx::FloorArbitratorOptions options;
  options.queue_enabled = false;
  options.revoke_grace_ms = 300;
  options.revoke_retry_ms = 100;
  options.media_idle_ms = 10000;
  mcx::FloorArbitrator floor({"alice", "bob", "carol"}, options);
  (void)floor.request("alice", 0, 5);
  floor.media_received("alice", 1);
  auto preempt = floor.request("bob", 10, 8, false, true);
  assert(preempt.size() == 1);
  assert(preempt[0].kind == mcx::FloorNoticeKind::Revoke && preempt[0].recipient == "alice" &&
         preempt[0].reject_cause == 4);
  assert(floor.owner() == "alice" && floor.state() == mcx::FloorState::PendingRevoke);
  auto retry = floor.tick(110);
  assert(retry.size() == 1 && retry[0].kind == mcx::FloorNoticeKind::Revoke && retry[0].reject_cause == 4);
  auto granted = floor.tick(310);
  assert(granted[0].kind == mcx::FloorNoticeKind::Granted && granted[0].recipient == "bob");
  assert(floor.owner() == "bob");
  auto equal = floor.request("carol", 311, 9, false, true);
  assert(equal[0].kind == mcx::FloorNoticeKind::Denied && floor.owner() == "bob");
  auto emergency = floor.request("carol", 320, 1, false, 2);
  assert(emergency[0].kind == mcx::FloorNoticeKind::Revoke && emergency[0].reject_cause == 4);
  assert(floor.release("bob", 321)[0].recipient == "carol");
  floor.set_priority_class("carol", 3);
  assert(floor.request("alice", 322, 99, false, 2)[0].kind == mcx::FloorNoticeKind::Denied);
  floor.set_priority_class("carol", 0);
  assert(floor.request("alice", 323, 99, false, 2)[0].kind == mcx::FloorNoticeKind::Revoke);
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.4.4.7: a pre-emption keeps the queue, the pre-emptor goes first, and its admitted
// priority ends with its Floor Release.
void test_preemption_preserves_queue_and_release() {
  mcx::FloorArbitratorOptions options;
  options.queue_enabled = true;
  mcx::FloorArbitrator floor({"a", "b", "c", "d"}, options);
  (void)floor.request("a", 0, 1);
  (void)floor.request("b", 1, 9, true);
  (void)floor.request("c", 2, 2, true);
  auto preempt = floor.request("c", 3, 2, true, true);
  assert(preempt[0].kind == mcx::FloorNoticeKind::Revoke && preempt[0].reject_cause == 4);
  assert(preempt[1].kind == mcx::FloorNoticeKind::QueuePosition && preempt[1].queue_position == 1);
  assert(floor.queue_position("b").queue_position == 2);
  assert(floor.admitted_priority("c") == 2);
  assert(floor.admitted_priority("a") == 1);
  assert(!floor.admitted_priority("d"));
  floor.set_priority_class("c", floor.admitted_priority("c").value_or(0) >= 2 ? 1 : 0);
  // An ordinary higher numeric request cannot overtake the preemptor.
  (void)floor.request("d", 4, 99, true);
  assert(floor.release("a", 5)[0].recipient == "c");
  assert(floor.release("c", 6)[0].recipient == "d");
  assert(!floor.admitted_priority("c"));
  assert(floor.release("d", 7)[0].recipient == "b");
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.4.4.11: when the permitted participant leaves the call the floor becomes idle for the
// others.
void test_departure_releases_owner() {
  mcx::FloorArbitrator floor({"alice", "bob"}, 1000);
  (void)floor.request("alice", 10);
  const auto notices = floor.remove("alice", 20);
  assert(notices.size() == 1);
  assert_notice(notices[0], mcx::FloorNoticeKind::Idle, "bob", "");
  assert(!floor.owner().has_value());
  assert(!floor.is_authorized("alice"));
  assert(floor.remove("unknown", 30).empty());
}

} // namespace

//------------------------------------------------------------------------------
// Broadcast group call: TS 24.380 clause 8.2.3.15 (the Floor Indicator B-bit and its combinations) and
// clause 6.3.5.3.4 (Floor Deny with cause #5 (Receive only)).
void test_broadcast_fields() {
  assert((mcx::floor_indicator_field(0x4000) == mcx::FloorField{13, {0x40, 0}}));
  expect_runtime_error([] { (void)mcx::floor_indicator_field(0x4000 | 0x8000); }); // broadcast and normal
  // Local policy (TS 24.380 clause 8.2.3.15): B combines with D or E only.
  assert(mcx::floor_indicator_field(0x4000 | 0x1000).value == (Bytes{0x50, 0}));            // emergency broadcast
  assert(mcx::floor_indicator_field(0x4000 | 0x0800 | 0x0400).value == (Bytes{0x4c, 0}));   // imminent-peril broadcast
  expect_runtime_error([] { (void)mcx::floor_indicator_field(0x4000 | 0x1000 | 0x0800); }); // emergency and imminent
  expect_runtime_error([] { (void)mcx::floor_indicator_field(0x8000 | 0x1000); });          // normal and emergency
  expect_runtime_error([] { (void)mcx::floor_indicator_field(0x4000 | 0x2000); });          // broadcast and system
  assert(mcx::floor_call_type_bits(false, false, false) == 0x8000);
  assert(mcx::floor_call_type_bits(true, false, false) == 0x4000);
  assert(mcx::floor_call_type_bits(false, true, true) == 0x1000);
  assert(mcx::floor_call_type_bits(false, false, true) == 0x0800);
  assert(mcx::floor_call_type_bits(true, true, false) == 0x5000);
  assert(mcx::floor_call_type_bits(true, false, true) == 0x4800);
  assert(mcx::floor_indicator_field(0x4000 | 0x0400).value == (Bytes{0x44, 0})); // queueing capability may combine
  mcx::FloorPacket taken{mcx::FloorType::Taken,
                         true,
                         8,
                         {mcx::floor_indicator_field(0x4000), mcx::message_sequence_field(1),
                          mcx::granted_party_identity_field("sip:a@b"), mcx::permission_to_request_field(false),
                          mcx::audio_ssrc_field(9)}};
  mcx::validate_on_network_floor(taken);
  const Bytes literal_taken{
      0x92, 0xcc, 0x00, 0x0a, 0,   0,   0,   8, 'M', 'C', 'P', 'T', 13, 2, 0x40, 0, 8, 2, 0, 1, 4, 7,
      's',  'i',  'p',  ':',  'a', '@', 'b', 0, 0,   0,   5,   2,   0,  0, 14,   6, 0, 0, 0, 9, 0, 0,
  };
  // RFC 3550 section 6.4.1: the length (octets 2 and 3) is the packet's size in 32-bit words minus one, 10 here.
  assert(mcx::encode_floor(taken) == literal_taken);
  const auto decoded = mcx::decode_floor(mcx::encode_floor(taken));
  unsigned permission_fields = 0, indicator_fields = 0;
  for (const auto &field : decoded.fields) {
    if (field.id == 5) {
      ++permission_fields;
      assert(!mcx::read_permission_to_request(field));
    }
    if (field.id == 13) {
      ++indicator_fields;
      assert(mcx::read_floor_indicator(field) == 0x4000);
    }
  }
  assert(permission_fields == 1 && indicator_fields == 1);
  mcx::FloorPacket deny{
      mcx::FloorType::Deny, true, 8, {mcx::floor_indicator_field(0x4000), mcx::reject_cause_field(5)}};
  mcx::validate_on_network_floor(deny);
  const auto denied = mcx::decode_floor(mcx::encode_floor(deny));
  assert(denied.type == mcx::FloorType::Deny && mcx::read_reject_cause(denied.fields[1]).cause == 5);
}

//------------------------------------------------------------------------------
// Runs every floor control test.
int main() {
  test_preemptive_floor_request();
  test_preemption_preserves_queue_and_release();
  test_literal_packets();
  test_field_helpers();
  test_bounds_and_malformed_packets();
  test_unknown_extension_field();
  test_on_network_fields_and_reliability();
  test_arbitration();
  test_timed_arbitration_and_queue();
  test_queued_grant_retransmission();
  test_participant_timers();
  test_release_state_reordering();
  test_implicit_grant();
  test_idle_retransmissions();
  test_dynamic_authorization();
  test_departure_releases_owner();
  test_broadcast_fields();
  std::cout << "floor tests passed\n";
}
