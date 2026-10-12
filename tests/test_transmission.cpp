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
  std::cout << "transmission tests passed\n";
}
