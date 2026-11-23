//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The transports of IMS AKA on reSIProcate (TS 33.203 clause 7.1):
//   - every message received on them passes a filter before the transaction layer (rules 4 and 7: a message not on
//     its security association is "rejected or silently discarded");
//   - the TCP transports of the protected client port port_uc (one per set of security associations) and of the
//     unprotected port open their connections from their own port (reSIProcate's "symmetric connections");
//   - UDP: the transport on port_uc of a set sends that set's requests; the transport on the protected server port
//     port_us receives everything, and what the stack sends on it (responses to the P-CSCF's requests) leaves from
//     port_uc of the set in use (ProtectedUdpTransport).
//
// Private to src/sip/.
//
// Specifications: TS 33.203 V19.1.0 (Rel-19) clause 7.1, TS 24.229 V19.7.0 (Rel-19) clause 4.2A.
#pragma once

#include "resip/stack/SendData.hxx"
#include "resip/stack/SipMessage.hxx"
#include "resip/stack/TcpTransport.hxx"
#include "resip/stack/UdpTransport.hxx"

#include <netinet/in.h>

#include <functional>
#include <memory>
#include <string>

namespace mcx::resip_engine {

// Whether a message received on a transport of the given local port may go up to the transaction layer.
using ReceiveFilter = std::function<bool(const resip::SipMessage &message, int local_port)>;

// A TCP transport whose received messages pass the filter.
class FilteredTcpTransport : public resip::TcpTransport {
public:
  FilteredTcpTransport(resip::Fifo<resip::TransactionMessage> &fifo, int port, const std::string &address,
                       unsigned flags, ReceiveFilter filter);

protected:
  void pushRxMsgUp(resip::SipMessage *message) override;

private:
  ReceiveFilter filter_;
};

// A UDP transport whose received messages pass the filter; its socket is what ProtectedUdpTransport sends from.
class FilteredUdpTransport : public resip::UdpTransport {
public:
  FilteredUdpTransport(resip::Fifo<resip::TransactionMessage> &fifo, int port, const std::string &address,
                       ReceiveFilter filter);

  [[nodiscard]] int socket() const { return mFd; }

protected:
  void pushRxMsgUp(resip::SipMessage *message) override;

private:
  ReceiveFilter filter_;
};

// TS 33.203 clause 7.1, UDP case: the transport on port_us. "The UE sends requests and responses protected with ESP
// on the port port_uc": what the stack sends on it leaves from the UDP socket of port_uc of the set in use to the
// P-CSCF's port_ps; without a set nothing is sent (no unprotected messages on these ports).
class ProtectedUdpTransport : public FilteredUdpTransport {
public:
  using FilteredUdpTransport::FilteredUdpTransport;

  // The set in use: the socket of its port_uc and the P-CSCF's port_ps; a negative socket for none.
  void use(int socket, const std::string &pcscf, int port_ps);

  void send(std::unique_ptr<resip::SendData> data) override;

private:
  int egress_ = -1;
  sockaddr_in destination_{};
};

} // namespace mcx::resip_engine
