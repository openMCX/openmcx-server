//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The transports of IMS AKA on reSIProcate (aka_transports.hpp).
//
// Specifications: TS 33.203 V19.1.0 (Rel-19) clause 7.1.

#include "aka_transports.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>

#include <stdexcept>

namespace mcx::resip_engine {

FilteredTcpTransport::FilteredTcpTransport(resip::Fifo<resip::TransactionMessage> &fifo, int port,
                                           const std::string &address, unsigned flags, ReceiveFilter filter)
    : TcpTransport(fifo, port, resip::V4, resip::Data(address), nullptr, resip::Compression::Disabled, flags),
      filter_(std::move(filter)) {}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.1 rules 4 and 7: a message the filter refuses is discarded before the transaction layer.
void FilteredTcpTransport::pushRxMsgUp(resip::SipMessage *message) {
  std::unique_ptr<resip::SipMessage> owned(message);
  bool accepted = false;
  try {
    accepted = !filter_ || filter_(*owned, port());
  } catch (...) {
    accepted = false; // a message the filter cannot read is not taken
  }
  if (accepted) TcpTransport::pushRxMsgUp(owned.release());
}

FilteredUdpTransport::FilteredUdpTransport(resip::Fifo<resip::TransactionMessage> &fifo, int port,
                                           const std::string &address, ReceiveFilter filter)
    : UdpTransport(fifo, port, resip::V4, resip::StunDisabled, resip::Data(address)), filter_(std::move(filter)) {}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.1 rules 4 and 7 (as FilteredTcpTransport::pushRxMsgUp).
void FilteredUdpTransport::pushRxMsgUp(resip::SipMessage *message) {
  std::unique_ptr<resip::SipMessage> owned(message);
  bool accepted = false;
  try {
    accepted = !filter_ || filter_(*owned, port());
  } catch (...) {
    accepted = false;
  }
  if (accepted) UdpTransport::pushRxMsgUp(owned.release());
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.1, UDP case: the set in use for what this transport sends.
void ProtectedUdpTransport::use(int socket, const std::string &pcscf, int port_ps) {
  egress_ = socket;
  if (socket < 0) return;
  destination_ = {};
  destination_.sin_family = AF_INET;
  destination_.sin_port = htons(static_cast<std::uint16_t>(port_ps));
  if (inet_pton(AF_INET, pcscf.c_str(), &destination_.sin_addr) != 1)
    throw std::invalid_argument("IMS AKA over UDP needs an IPv4 P-CSCF address");
}

//------------------------------------------------------------------------------
// The stack's send on port_us: out from port_uc of the set in use to port_ps instead, or not at all without a set.
void ProtectedUdpTransport::send(std::unique_ptr<resip::SendData> data) {
  if (data->command != resip::SendData::NoCommand || egress_ < 0) return;
  (void)::sendto(egress_, data->data.data(), data->data.size(), 0, reinterpret_cast<const sockaddr *>(&destination_),
                 sizeof destination_);
}

} // namespace mcx::resip_engine
