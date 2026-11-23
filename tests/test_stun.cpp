//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The STUN messages of ICE connectivity checks (src/media/stun.hpp): the sample request and IPv4 response of RFC 5769
// decoded and their MESSAGE-INTEGRITY and FINGERPRINT checked and reproduced; a built check round trip; damaged
// messages refused.
//
// Specifications: RFC 5389, RFC 5769, RFC 8445.

#include "stun.hpp"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

static void expect(bool condition, const std::string &what) {
  if (!condition) throw std::runtime_error(what);
}

// RFC 5769 section 2.1: the sample request (username "evtj:h6vY", padded with spaces).
static const std::vector<std::uint8_t> kSampleRequest{
    0x00, 0x01, 0x00, 0x58, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87,
    0xdf, 0xae, 0x80, 0x22, 0x00, 0x10, 0x53, 0x54, 0x55, 0x4e, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x63, 0x6c,
    0x69, 0x65, 0x6e, 0x74, 0x00, 0x24, 0x00, 0x04, 0x6e, 0x00, 0x01, 0xff, 0x80, 0x29, 0x00, 0x08, 0x93, 0x2f,
    0xf9, 0xb1, 0x51, 0x26, 0x3b, 0x36, 0x00, 0x06, 0x00, 0x09, 0x65, 0x76, 0x74, 0x6a, 0x3a, 0x68, 0x36, 0x76,
    0x59, 0x20, 0x20, 0x20, 0x00, 0x08, 0x00, 0x14, 0x9a, 0xea, 0xa7, 0x0c, 0xbf, 0xd8, 0xcb, 0x56, 0x78, 0x1e,
    0xf2, 0xb5, 0xb2, 0xd3, 0xf2, 0x49, 0xc1, 0xb5, 0x71, 0xa2, 0x80, 0x28, 0x00, 0x04, 0xe5, 0x7a, 0x3b, 0xcf};

// RFC 5769 section 2.2: the sample IPv4 response (mapped address 192.0.2.1 port 32853).
static const std::vector<std::uint8_t> kSampleResponse{
    0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86,
    0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63,
    0x74, 0x6f, 0x72, 0x20, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43,
    0x00, 0x08, 0x00, 0x14, 0x2b, 0x91, 0xf5, 0x99, 0xfd, 0x9e, 0x90, 0xc3, 0x8c, 0x74, 0x89, 0xf9,
    0x2a, 0xf9, 0xba, 0x53, 0xf0, 0x6b, 0xe7, 0xd7, 0x80, 0x28, 0x00, 0x04, 0xc0, 0x7d, 0x4c, 0x96};

static const std::string kPassword = "VOkJxbRl1RmTxUk/WvJxBt";

//------------------------------------------------------------------------------
// RFC 5769 section 2.1: the request's fields, its integrity under the password, and both attributes reproduced.
static void Rfc5769_2_1_SampleRequest() {
  const auto message = mcx::stun::decode(kSampleRequest);
  expect(message.has_value(), "sample request decoded (its FINGERPRINT matches)");
  expect(message->type == mcx::stun::Class::Request && message->has_fingerprint, "a Binding request");
  expect(message->username == "evtj:h6vY", "USERNAME");
  expect(message->priority == 0x6e0001ff, "PRIORITY");
  expect(message->ice_controlled == 0x932ff9b151263b36ull && !message->ice_controlling, "ICE-CONTROLLED");
  expect(!message->use_candidate && message->unknown_required.empty(), "no other attribute");
  expect(mcx::stun::check_integrity(kSampleRequest, *message, kPassword), "MESSAGE-INTEGRITY under the password");
  expect(!mcx::stun::check_integrity(kSampleRequest, *message, "wrong"), "not under another password");
  std::vector<std::uint8_t> rebuilt(kSampleRequest.begin(), kSampleRequest.begin() + 76);
  mcx::stun::append_integrity(rebuilt, kPassword);
  mcx::stun::append_fingerprint(rebuilt);
  expect(rebuilt == kSampleRequest, "MESSAGE-INTEGRITY and FINGERPRINT reproduced");
}

//------------------------------------------------------------------------------
// RFC 5769 section 2.2: the response's XOR-MAPPED-ADDRESS, integrity and both attributes reproduced.
static void Rfc5769_2_2_SampleIpv4Response() {
  const auto message = mcx::stun::decode(kSampleResponse);
  expect(message.has_value() && message->type == mcx::stun::Class::Success, "a Binding success response");
  expect(message->xor_mapped == mcx::stun::Address{0xc0000201, 32853}, "XOR-MAPPED-ADDRESS 192.0.2.1:32853");
  expect(mcx::stun::check_integrity(kSampleResponse, *message, kPassword), "MESSAGE-INTEGRITY");
  std::vector<std::uint8_t> rebuilt(kSampleResponse.begin(), kSampleResponse.begin() + 48);
  mcx::stun::append_integrity(rebuilt, kPassword);
  mcx::stun::append_fingerprint(rebuilt);
  expect(rebuilt == kSampleResponse, "MESSAGE-INTEGRITY and FINGERPRINT reproduced");
  // The XOR-MAPPED-ADDRESS as the builder writes it.
  const auto built = mcx::stun::Builder(mcx::stun::Class::Success, message->transaction)
                         .xor_mapped({0xc0000201, 32853})
                         .finish(kPassword);
  expect(std::equal(built.begin() + 20, built.begin() + 32, kSampleResponse.begin() + 36), "XOR-MAPPED-ADDRESS built");
}

//------------------------------------------------------------------------------
// RFC 8445 section 7.2.4: a check as the agent builds it reads back with every attribute; an error response too.
static void Rfc8445_7_2_4_CheckRoundTrip() {
  const mcx::stun::TransactionId id{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  const auto bytes = mcx::stun::Builder(mcx::stun::Class::Request, id)
                         .username("peer:mine")
                         .priority(1845501695)
                         .ice_controlling(0x0102030405060708ull)
                         .use_candidate()
                         .finish("secret-password-of-24ch");
  const auto message = mcx::stun::decode(bytes);
  expect(message && message->transaction == id && message->username == "peer:mine", "username and transaction");
  expect(message->priority == 1845501695u && message->use_candidate, "PRIORITY and USE-CANDIDATE");
  expect(message->ice_controlling == 0x0102030405060708ull, "ICE-CONTROLLING");
  expect(mcx::stun::check_integrity(bytes, *message, "secret-password-of-24ch"), "integrity");
  const auto error = mcx::stun::Builder(mcx::stun::Class::Error, id).error(487, "Role Conflict").finish("k");
  const auto decoded = mcx::stun::decode(error);
  expect(decoded && decoded->type == mcx::stun::Class::Error && decoded->error_code == 487u, "ERROR-CODE 487");
}

//------------------------------------------------------------------------------
// RFC 5389 sections 7.3 and 15.5: a damaged octet breaks the FINGERPRINT; a wrong length, cookie or method is no
// Binding message; an unknown comprehension-required attribute is reported.
static void Rfc5389_7_3_DamagedMessages() {
  auto damaged = kSampleRequest;
  damaged[30] ^= 0x01;
  expect(!mcx::stun::decode(damaged), "a changed octet breaks the FINGERPRINT");
  auto truncated = kSampleRequest;
  truncated.pop_back();
  expect(!mcx::stun::decode(truncated), "length mismatch");
  auto other_method = kSampleRequest;
  other_method[1] = 0x03; // Allocate (RFC 5766)
  expect(!mcx::stun::decode(other_method), "not a Binding message");
  std::vector<std::uint8_t> unknown{0x00, 0x01, 0x00, 0x08, 0x21, 0x12, 0xa4, 0x42, 0,    0,    0, 0, 0, 0,
                                    0,    0,    0,    0,    0,    0,    0x00, 0x33, 0x00, 0x04, 1, 2, 3, 4};
  const auto message = mcx::stun::decode(unknown);
  expect(message && message->unknown_required == std::vector<std::uint16_t>{0x0033}, "unknown attribute 0x0033");
}

int main() {
  const std::vector<std::pair<const char *, void (*)()>> tests = {
      {"Rfc5769_2_1_SampleRequest", Rfc5769_2_1_SampleRequest},
      {"Rfc5769_2_2_SampleIpv4Response", Rfc5769_2_2_SampleIpv4Response},
      {"Rfc8445_7_2_4_CheckRoundTrip", Rfc8445_7_2_4_CheckRoundTrip},
      {"Rfc5389_7_3_DamagedMessages", Rfc5389_7_3_DamagedMessages},
  };
  int failures = 0;
  for (const auto &[name, test] : tests) {
    try {
      test();
    } catch (const std::exception &error) {
      std::cerr << name << ": " << error.what() << '\n';
      ++failures;
    }
  }
  if (failures == 0) std::cout << tests.size() << " STUN tests passed\n";
  return failures == 0 ? 0 : 1;
}
