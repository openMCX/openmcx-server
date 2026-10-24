//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The IPsec ESP security associations of an IMS AKA UE in the Linux kernel (XFRM), written over a raw NETLINK_XFRM
// socket: one unidirectional SA in transport mode with its security policy per direction and port pair, anti-replay
// on, the SIP application controlling the lifetime.
//
// Specifications: TS 33.203 V19.1.0 (Rel-19) clauses 6.2, 6.3, 7.1 and annex I, RFC 4301, RFC 4303.
#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace mcx::xfrm {

//------------------------------------------------------------------------------
// Helper: an XFRM failure; a refusal for lack of privilege says "IMS AKA needs CAP_NET_ADMIN".
class XfrmError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

//------------------------------------------------------------------------------
// TS 33.203 clause 7.1: one unidirectional SA and its policy: the selectors (source and destination IP address and
// port, any transport protocol: "The transport protocol selector shall allow UDP and TCP"), the SPI, ESP in transport
// mode, the integrity algorithm with IK_ESP and the encryption algorithm with CK_ESP of annex I.
struct SecurityAssociation {
  std::string source, destination; // numeric IPv4 or IPv6 addresses
  std::uint16_t source_port = 0, destination_port = 0;
  std::uint32_t spi = 0;
  // Annex H names: "hmac-sha-1-96"; "aes-cbc" or "null".
  std::string alg, ealg;
  std::vector<std::uint8_t> integrity_key, encryption_key;
  // Outbound: an OUT policy (packets from this host are protected with the SA); inbound: an IN policy (packets of the
  // selectors that did not arrive protected with this SA are dropped, TS 33.203 clause 7.1 rule 7 at the IP layer).
  bool outbound = false;
};

//------------------------------------------------------------------------------
// TS 33.203 clauses 6.3 and 7.1: the kernel's SA database (SAD) and policy database (SPD) of this network namespace.
class Xfrm {
public:
  // Opens the NETLINK_XFRM socket; throws XfrmError ("IMS AKA needs CAP_NET_ADMIN") without that capability.
  Xfrm();
  ~Xfrm();
  Xfrm(const Xfrm &) = delete;
  Xfrm &operator=(const Xfrm &) = delete;

  // Adds the SA (XFRM_MSG_NEWSA: ESP, transport mode, replay window 32, no byte or packet limit: TS 33.203 clause 7.1
  // "SA duration ... 2^32-1", the lifetime being the SIP application's, clause 7.4) and its policy
  // (XFRM_MSG_NEWPOLICY). An SA or policy that exists already is an error. Logs the SA and its keys with debug_line
  // at log level debug (for ESP decryption in a capture).
  void add(const SecurityAssociation &sa);
  // Deletes the SA and its policy; one that is gone already is no error.
  void remove(const SecurityAssociation &sa) noexcept;

private:
  void transact(void *message, std::size_t length, bool missing_ok);
  int socket_ = -1;
  std::uint32_t sequence_ = 0;
};

} // namespace mcx::xfrm
