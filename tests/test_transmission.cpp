//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// MCVideo transmission control: the MCV0, MCV1 and MCV2 message and field codec of TS 24.581 clause 9.2.
//
// Specifications: TS 24.581 V19.2.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19).

#ifdef NDEBUG
#undef NDEBUG
#endif
#include "mcx/transmission.hpp"

#include <algorithm>
#include <cassert>
#include <iostream>
#include <stdexcept>

using namespace mcx;
using namespace mcx::transmission;

namespace {
//------------------------------------------------------------------------------
// True when the action throws std::runtime_error (a refused encode or decode).
template <typename Action> bool refused(Action action) {
  try {
    action();
  } catch (const std::runtime_error &) {
    return true;
  }
  return false;
}
} // namespace

//------------------------------------------------------------------------------
// TS 24.581 clauses 6.2.4 and 6.2.5 with clauses 11.1.1 and 11.2.1: the transmission participant timers T100 to
// T104 and counters C100 to C104 on a fake clock (1000 ms intervals, limits of 3).
static void participant_timers() {
  const Packet request{Type::Request, false, 5, {priority_field(1)}};
  const Packet end{Type::EndRequest, false, 5, {}};
  const Packet queue{Type::QueuePositionRequest, false, 5, {}};
  const Packet receive{Type::ReceiveMediaRequest, false, 5, {}};
  const Packet reception_end{
      Type::ReceptionEndRequest, false, 5, {transmitting_user_field("sip:bob@mcx.test"), audio_ssrc_field(1)}};
  const auto server = [](Type type, std::vector<FloorField> fields = {}) {
    return Packet{type, false, 9, std::move(fields)};
  };

  // Defaults of table 11.2.1-1 and a refused zero limit.
  assert(ParticipantTimerOptions{}.c100_request == 3 && ParticipantTimerOptions{}.c104_receive_release == 3);
  assert(refused([] { ParticipantTimers{ParticipantTimerOptions{.c101_end_request = 0}}; }));

  // Clauses 6.2.4.3.2, 6.2.4.4.3 and 6.2.4.4.4: T100 resends at each expiry below C100, then gives up into 'U: has
  // no permission to transmit'.
  {
    ParticipantTimers timers;
    timers.send(request, 0);
    assert(timers.state() == ParticipantState::PendingRequest);
    assert(timers.tick(999).empty());
    assert(timers.tick(1000) == std::vector<Packet>{request});
    assert(timers.tick(1999).empty());
    assert(timers.tick(2000) == std::vector<Packet>{request});
    assert(timers.take_failed().empty());
    assert(timers.tick(3000).empty());
    assert(timers.state() == ParticipantState::NoPermission);
    assert(timers.take_failed() == std::vector<Type>{Type::Request} && timers.take_failed().empty());
    assert(timers.tick(10000).empty());
  }

  // Clause 6.2.4.4.6: Transmission Granted stops T100; clause 6.2.4.5.3 starts T101; clauses 6.2.4.6.2 and
  // 6.2.4.6.4: T101 resends, Transmission End Response stops it.
  {
    ParticipantTimers timers;
    timers.send(request, 0);
    timers.receive(server(Type::Granted), 500);
    assert(timers.state() == ParticipantState::HasPermission && timers.tick(5000).empty());
    assert(refused([&] { timers.send(request, 5000); }));
    timers.send(end, 5000);
    assert(timers.state() == ParticipantState::PendingEnd);
    assert(timers.tick(6000) == std::vector<Packet>{end});
    timers.receive(server(Type::EndResponse), 6100);
    assert(timers.state() == ParticipantState::NoPermission && timers.tick(20000).empty());
    assert(timers.take_failed().empty());
  }

  // Clause 6.2.4.6.3: T101 expired N times enters 'U: has no permission to transmit'.
  {
    ParticipantTimers timers;
    timers.send(request, 0);
    timers.send(end, 100); // clause 6.2.4.4.7: T100 stopped, T101 started
    assert(timers.tick(1099).empty());
    assert(timers.tick(1100) == std::vector<Packet>{end} && timers.tick(2100) == std::vector<Packet>{end});
    assert(timers.tick(3100).empty() && timers.state() == ParticipantState::NoPermission);
    assert(timers.take_failed() == std::vector<Type>{Type::EndRequest});
  }

  // Clause 6.2.4.4.2: Transmission rejected stops T100.
  {
    ParticipantTimers timers;
    timers.send(request, 0);
    timers.receive(server(Type::Rejected, {reject_cause_field(1)}), 10);
    assert(timers.state() == ParticipantState::NoPermission && timers.tick(5000).empty());
    assert(timers.take_failed().empty());
  }

  // Queued path: clause 6.2.4.4.5 (Queue Position Info stops T100, 'U: queued transmission'), clauses 6.2.4.9.3,
  // 6.2.4.9.7 and 6.2.4.9.2 (T102 started, resent, stopped), clause 6.2.4.9.9 (Granted).
  {
    ParticipantTimers timers;
    timers.send(request, 0);
    timers.receive(server(Type::QueuePositionInfo, {queue_info_field(2, 1)}), 200);
    assert(timers.state() == ParticipantState::Queued && timers.tick(5000).empty());
    timers.send(queue, 5000);
    assert(timers.tick(6000) == std::vector<Packet>{queue});
    timers.receive(server(Type::QueuePositionInfo, {queue_info_field(1, 1)}), 6200);
    assert(timers.state() == ParticipantState::Queued && timers.tick(9000).empty());
    timers.send(queue, 9000);
    timers.receive(server(Type::Granted), 9100);
    assert(timers.state() == ParticipantState::HasPermission && timers.tick(20000).empty());
  }

  // Clause 6.2.4.9.8: T102 expired N times sends a Transmission end request, starts T101 and enters 'U: pending end
  // of transmission'; clause 6.2.4.9.6: Transmission cancel request notify leaves the queue.
  {
    ParticipantTimers timers;
    timers.send(request, 0);
    timers.receive(server(Type::QueuePositionInfo, {queue_info_field(2, 1)}), 0);
    timers.send(queue, 1000);
    assert(timers.tick(2000) == std::vector<Packet>{queue} && timers.tick(3000) == std::vector<Packet>{queue});
    assert(timers.tick(4000) == std::vector<Packet>{end});
    assert(timers.state() == ParticipantState::PendingEnd);
    assert(timers.take_failed() == std::vector<Type>{Type::QueuePositionRequest});
    assert(timers.tick(5000) == std::vector<Packet>{end});
    timers.receive(server(Type::EndResponse), 5100);
    assert(timers.state() == ParticipantState::NoPermission);

    ParticipantTimers cancelled;
    cancelled.send(request, 0);
    cancelled.receive(server(Type::QueuePositionInfo, {queue_info_field(2, 1)}), 0);
    cancelled.send(queue, 10);
    cancelled.receive(server(Type::CancelRequestNotify), 20);
    assert(cancelled.state() == ParticipantState::NoPermission && cancelled.tick(9000).empty());
  }

  // Clause 6.2.4.5.5 step 4b: a revoke queueing the transmission, then a Queue Position Request from 'U: has
  // permission to transmit'; clause 6.2.4.5.7: the server's Transmission End Request ends the permission.
  {
    ParticipantTimers timers;
    timers.send(request, 0);
    timers.receive(server(Type::Granted), 0);
    timers.receive(server(Type::Revoked, {reject_cause_field(2)}), 100);
    timers.send(queue, 100);
    assert(timers.state() == ParticipantState::Queued);
    timers.receive(server(Type::Granted), 200);
    timers.receive(server(Type::EndRequest), 300);
    assert(timers.state() == ParticipantState::NoPermission);
  }

  // Clause 6.2.4.2.2 step 4: an implicit Transmission request starts T100 without sending.
  {
    ParticipantTimers timers;
    timers.expect_implicit_request(request, 0);
    assert(timers.state() == ParticipantState::PendingRequest);
    assert(timers.tick(1000) == std::vector<Packet>{request});
    timers.receive(server(Type::Granted), 1100);
    assert(timers.state() == ParticipantState::HasPermission);
    assert(refused([&] { timers.expect_implicit_request(request, 2000); }));
  }

  // Reception path: clauses 6.2.5.3.3, 6.2.5.4.3 and 6.2.5.4.5 (T103 resent, granted stops it), clauses 6.2.5.5.3,
  // 6.2.5.6.2 and 6.2.5.6.4 (T104 resent, Media Reception End Response stops it); the two machines run apart.
  {
    ParticipantTimers timers;
    timers.send(receive, 0);
    timers.send(request, 0);
    assert(timers.reception_state() == ReceptionState::PendingRequest);
    assert((timers.tick(1000) == std::vector<Packet>{request, receive}));
    timers.receive(server(Type::ReceiveMediaResponse, {result_field(true)}), 1500);
    assert(timers.reception_state() == ReceptionState::HasPermission);
    assert(timers.state() == ParticipantState::PendingRequest);
    assert(timers.tick(2000) == std::vector<Packet>{request});
    assert(refused([&] { timers.send(receive, 2000); }));
    timers.send(reception_end, 3000);
    assert(timers.reception_state() == ReceptionState::PendingRelease);
    assert(timers.tick(3000).empty()); // T100 expired N times here
    assert(timers.take_failed() == std::vector<Type>{Type::Request});
    assert(timers.tick(4000) == std::vector<Packet>{reception_end});
    timers.receive(server(Type::ReceptionEndResponse), 4500);
    assert(timers.reception_state() == ReceptionState::Terminated && timers.tick(20000).empty());
    timers.send(receive, 20000); // a new basic reception instance (clause 6.2.5.3.3 step 2)
    assert(timers.reception_state() == ReceptionState::PendingRequest);
  }

  // Clauses 6.2.5.4.4 and 6.2.5.6.3: T103 and T104 expired N times enter 'terminated'.
  {
    ParticipantTimers timers;
    timers.send(receive, 0);
    assert(timers.tick(1000).size() == 1 && timers.tick(2000).size() == 1 && timers.tick(3000).empty());
    assert(timers.reception_state() == ReceptionState::Terminated);
    assert(timers.take_failed() == std::vector<Type>{Type::ReceiveMediaRequest});
    timers.send(receive, 4000);
    timers.receive(server(Type::ReceiveMediaResponse, {result_field(true)}), 4000);
    timers.send(reception_end, 5000);
    assert(timers.tick(6000).size() == 1 && timers.tick(7000).size() == 1 && timers.tick(8000).empty());
    assert(timers.reception_state() == ReceptionState::Terminated);
    assert(timers.take_failed() == std::vector<Type>{Type::ReceptionEndRequest});
  }

  // Clause 6.2.5.4.2: a rejected Receive Media Response (Result 0, or a Reject Cause alone) stops T103 and enters
  // 'terminated'; clause 6.2.5.4.6: the user cancelling the pending request stops T103 and starts T104.
  {
    ParticipantTimers rejected;
    rejected.send(receive, 0);
    rejected.receive(server(Type::ReceiveMediaResponse, {result_field(false), reject_cause_field(1)}), 10);
    assert(rejected.reception_state() == ReceptionState::Terminated && rejected.tick(9000).empty());
    rejected.send(receive, 9000);
    rejected.receive(server(Type::ReceiveMediaResponse, {reject_cause_field(0)}), 9010);
    assert(rejected.reception_state() == ReceptionState::Terminated && rejected.take_failed().empty());

    ParticipantTimers cancelled;
    cancelled.send(receive, 0);
    cancelled.send(reception_end, 500);
    assert(cancelled.reception_state() == ReceptionState::PendingRelease);
    assert(cancelled.tick(1000).empty()); // T103 stopped
    assert(cancelled.tick(1500) == std::vector<Packet>{reception_end});
    // A late Receive Media Response has no procedure in 'U: pending reception release' (clause 6.2.5.1).
    cancelled.receive(server(Type::ReceiveMediaResponse, {result_field(true)}), 1600);
    assert(cancelled.reception_state() == ReceptionState::PendingRelease);
    cancelled.receive(server(Type::ReceptionEndResponse), 1700);
    assert(cancelled.reception_state() == ReceptionState::Terminated && cancelled.tick(9000).empty());
  }

  // Clauses 6.2.4.7.2 and 6.2.5.3.5: call release stops every timer; later messages are discarded.
  {
    ParticipantTimers timers;
    timers.send(request, 0);
    timers.send(receive, 0);
    timers.release();
    assert(timers.state() == ParticipantState::CallReleasing);
    assert(timers.reception_state() == ReceptionState::CallReleasing);
    assert(timers.tick(1000).empty() && timers.tick(5000).empty() && timers.take_failed().empty());
    timers.receive(server(Type::Granted), 5000);
    timers.send(request, 5000);
    assert(timers.state() == ParticipantState::CallReleasing && timers.tick(9000).empty());
  }

  // Only participant messages are registered.
  ParticipantTimers timers;
  assert(refused([&] { timers.send(Packet{Type::Granted, false, 5, {}}, 0); }));
}

//------------------------------------------------------------------------------
// TS 24.581 clause 9.1.2, clause 9.2.2.1 (tables 9.2.2.1-1 to 9.2.2.1-3) and clause 9.2.3 (table 9.2.3.1-1): each
// transmission control message encodes with its name (MCV0, MCV1, MCV2) and subtype and decodes back; Transmission
// Request (clause 9.2.4), Transmission Granted (clause 9.2.5), Transmission Arbitration Taken (clause 9.2.8) and the
// Remote Transmission messages (clauses 9.2.22 to 9.2.25) carry their fields; void subtypes, an MCPT packet, an ack
// bit on Transmission control ack (clause 9.2.31) and malformed fields are refused.
int main() {
  // TS 24.581 clause 9.2.4: a Transmission Request (MCV0, subtype x0000) with a priority,
  // byte for byte: V=2, subtype 0, PT 204, length 3 words after the first.
  Packet request{Type::Request, false, 0x11223344, {priority_field(5)}};
  const auto bytes = encode(request);
  const std::vector<std::uint8_t> expected{0x80, 204, 0, 3, 0x11, 0x22, 0x33, 0x44, 'M', 'C', 'V', '0', 0, 2, 5, 0};
  assert(bytes == expected);
  assert(decode(bytes) == request);

  // TS 24.581 clause 9.2.5: Transmission Granted (MCV1, x0000) with the ack bit, the duration and
  // both SSRCs of the transmitting user; Video SSRC is field 23 (clause 9.2.3.23).
  Packet granted{
      Type::Granted, true, 7, {duration_field(30), audio_ssrc_field(0xa1a2a3a4), video_ssrc_field(0xb1b2b3b4)}};
  const auto granted_bytes = encode(granted);
  assert(granted_bytes[0] == (0x80 | 0x10) && granted_bytes[8] == 'M' && granted_bytes[11] == '1');
  const auto back = decode(granted_bytes);
  assert(back == granted && read_video_ssrc(*find(back, Field::VideoSsrc)) == 0xb1b2b3b4);
  assert(find(back, Field::VideoSsrc)->id == 23);

  // Each message keeps its name and subtype.
  const std::pair<Type, std::uint8_t> names[] = {{Type::Release, '0'},
                                                 {Type::QueuePositionRequest, '0'},
                                                 {Type::Rejected, '1'},
                                                 {Type::ArbitrationTaken, '1'},
                                                 {Type::ArbitrationRelease, '1'},
                                                 {Type::Revoked, '1'},
                                                 {Type::QueuePositionInfo, '1'},
                                                 {Type::Idle, '1'},
                                                 {Type::EndRequest, '2'},
                                                 {Type::EndResponse, '2'},
                                                 {Type::Ack, '2'}};
  for (const auto &[type, name] : names) {
    const auto encoded = encode({type, false, 1, {}});
    assert(encoded[11] == name && decode(encoded).type == type);
  }
  assert(encode({Type::Idle, false, 1, {}})[0] == (0x80 | 15));
  assert(encode({Type::Ack, false, 1, {}})[0] == (0x80 | 4));
  assert(from_participant(Type::Request) && !from_server(Type::Request));
  assert(from_server(Type::Granted) && !from_participant(Type::Granted));
  assert(from_participant(Type::EndRequest) && from_server(Type::EndRequest));

  // An Arbitration Taken names the transmitting user.
  Packet taken{Type::ArbitrationTaken, false, 9, {transmitting_user_field("sip:alice.mcvideo@mcx.test")}};
  assert(read_transmitting_user(*find(decode(encode(taken)), Field::TransmittingUserId)) ==
         "sip:alice.mcvideo@mcx.test");

  // TS 24.581 clauses 9.2.22 to 9.2.25: Remote Transmission request and cancel request (MCV0 x0111 and
  // x1000) name the user whose transmission is asked for; the responses (MCV1 x1011
  // and x1100) carry a Result field (clause 9.2.3.17): 1 granted, 0 rejected.
  Packet remote{Type::RemoteRequest, false, 11, {user_id_field("sip:bob.mcvideo@mcx.test")}};
  auto remote_bytes = encode(remote);
  assert((remote_bytes[0] & 0x1f) == 7 && std::equal(remote_bytes.begin() + 8, remote_bytes.begin() + 12, "MCV0"));
  assert(read_user_id(*find(decode(remote_bytes), Field::UserId)) == "sip:bob.mcvideo@mcx.test");
  auto cancel_bytes = encode({Type::RemoteCancelRequest, false, 11, {user_id_field("sip:bob.mcvideo@mcx.test")}});
  assert((cancel_bytes[0] & 0x1f) == 8 && decode(cancel_bytes).type == Type::RemoteCancelRequest);
  for (const bool ok : {true, false}) {
    auto response = encode({Type::RemoteResponse, false, 12, {result_field(ok)}});
    assert((response[0] & 0x1f) == 11 && std::equal(response.begin() + 8, response.begin() + 12, "MCV1"));
    assert(read_result(*find(decode(response), Field::Result)) == ok);
    auto cancel_response = encode({Type::RemoteCancelResponse, false, 12, {result_field(ok)}});
    assert((cancel_response[0] & 0x1f) == 12 && read_result(*find(decode(cancel_response), Field::Result)) == ok);
  }
  assert(refused([] { (void)encode({Type::RemoteResponse, false, 1, {FloorField{15, {2, 0}}}}); }));
  assert(refused([] { (void)encode({Type::RemoteResponse, false, 1, {FloorField{15, {1}}}}); }));

  // Refused: an MCPTT floor packet, a void subtype (MCV0 x0101, MCV1 x1001), an ack
  // asking for an ack, and malformed fields.
  auto floor_packet = bytes;
  floor_packet[8] = 'M';
  floor_packet[9] = 'C';
  floor_packet[10] = 'P';
  floor_packet[11] = 'T';
  assert(refused([&] { (void)decode(floor_packet); }));
  auto void0 = bytes;
  void0[0] = 0x80 | 5;
  assert(refused([&] { (void)decode(void0); }));
  auto void1 = encode({Type::Granted, false, 1, {}});
  void1[0] = 0x80 | 9;
  assert(refused([&] { (void)decode(void1); }));
  auto ack_ack = encode({Type::Ack, false, 1, {}});
  ack_ack[0] = 0x80 | 0x14;
  assert(refused([&] { (void)decode(ack_ack); }));
  assert(refused([] { (void)encode({Type::Ack, true, 1, {}}); }));
  assert(refused([] { (void)encode({Type::Granted, false, 1, {FloorField{23, {1, 2, 3, 4}}}}); }));
  assert(refused([] { (void)encode({Type::Request, false, 1, {FloorField{0, {5, 1}}}}); }));
  assert(refused([] { (void)encode({Type::Granted, false, 1, {FloorField{4, {}}}}); }));

  // TS 24.581 clause 9.1.4 steps 2 and 3: a Transmission Granted with unknown fields (ID 100, one-octet length;
  // ID 200, two-octet length, clause 9.1.3) and a syntactically incorrect Transmission Priority (one octet instead of
  // two, clause 9.2.3.2) decodes: the unknown fields are kept, the incorrect field is left out, the others are read.
  {
    auto bytes = encode({Type::Granted, true, 7, {video_ssrc_field(0xb1b2b3b4), FloorField{100, {1, 2, 3}},
                                                  FloorField{200, {9, 9, 9, 9, 9}}}});
    bytes.insert(bytes.end(), {0, 1, 5, 0}); // the one-octet Transmission Priority field, padded
    const auto words = static_cast<std::uint16_t>(bytes.size() / 4 - 1);
    bytes[2] = static_cast<std::uint8_t>(words >> 8);
    bytes[3] = static_cast<std::uint8_t>(words);
    const auto lenient = decode(bytes);
    assert(lenient.type == Type::Granted && lenient.ack_required);
    assert(read_video_ssrc(*find(lenient, Field::VideoSsrc)) == 0xb1b2b3b4);
    assert(find(lenient, Field::Priority) == nullptr && lenient.fields.size() == 3);
    assert(std::any_of(lenient.fields.begin(), lenient.fields.end(), [](const FloorField &f) { return f.id == 200; }));
  }

  // TS 24.581 clause 9.2.13: the Media Transmission Notification (MCV1, subtype x0110) the server sends to every
  // other participant when one transmits (clauses 6.3.4.4.2 step 3, 6.3.5.7.4 step 3 and 6.3.6.3.3): the
  // transmitter's MCVideo ID and SSRCs, Permission to Request, the Transmission Indicator of an emergency call and
  // the Reception Mode (clause 9.2.3.22: '0' automatic, '1' not).
  const auto notification = media_transmission_notification(9, "sip:alice@mcx.test", 0xa1a2a3a4, 0xb1b2b3b4, true,
                                                            floor_call_type_bits(false, true, false), true);
  const auto notification_bytes = encode(notification);
  assert(notification_bytes[11] == '1' && (notification_bytes[0] & 0x1f) == 6);
  const auto notified = decode(notification_bytes);
  assert(notified == notification && notified.type == Type::MediaTransmissionNotification);
  assert(read_transmitting_user(*find(notified, Field::TransmittingUserId)) == "sip:alice@mcx.test");
  assert(read_audio_ssrc(*find(notified, Field::AudioSsrc)) == 0xa1a2a3a4);
  assert(read_video_ssrc(*find(notified, Field::VideoSsrc)) == 0xb1b2b3b4);
  assert(read_permission_to_request(*find(notified, Field::PermissionToRequest)));
  assert(read_floor_indicator(*find(notified, Field::Indicator)) == 0x1000);
  assert(read_reception_mode(*find(notified, Field::ReceptionMode)));
  assert(find(notified, Field::ReceptionMode)->value == (std::vector<std::uint8_t>{0, 0}));
  const auto manual = media_transmission_notification(9, "sip:alice@mcx.test", 1, 2, false, std::nullopt, false);
  assert(!find(manual, Field::Indicator) && !read_reception_mode(*find(manual, Field::ReceptionMode)));
  assert(!read_permission_to_request(*find(manual, Field::PermissionToRequest)));
  assert(refused([] { (void)encode({Type::MediaTransmissionNotification, false, 1, {FloorField{22, {0, 2}}}}); }));
  assert(refused([] { (void)encode({Type::MediaTransmissionNotification, false, 1, {FloorField{22, {0}}}}); }));

  // TS 24.581 clause 6.3.6.3.3 step 1: automatic reception in a broadcast, emergency or imminent peril call (1a),
  // manual reception otherwise (1b); without the server's reception control every member receives.
  assert(!automatic_reception(true, false, false, false));
  assert(automatic_reception(true, true, false, false));
  assert(automatic_reception(true, false, true, false));
  assert(automatic_reception(true, false, false, true));
  assert(automatic_reception(false, false, false, false));
  participant_timers();
  std::cout << "transmission tests passed\n";
}
