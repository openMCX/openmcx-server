//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// SipEngine::Impl on reSIProcate: configuration, start and stop, the transports (TLS with the TLS profile, or debug
// TCP), and poll, one epoll wait for the stack and the dispatch of what its transaction user received.
//
// Specifications: RFC 3261 sections 18 and 26.2, TS 33.180 V19.4.0 (Rel-19) clause 6.1, TS 33.210 V19.3.0 clause 6.2.

#include "resip_impl.hpp"
#include "tls_security.hpp"

#include "rutil/Log.hxx"

#include <stdexcept>

namespace mcx {

//------------------------------------------------------------------------------
// The transaction user's name in reSIProcate's log.
const resip::Data &ResipUser::name() const {
  static const resip::Data user_name("openmcx-sip-engine");
  return user_name;
}

//------------------------------------------------------------------------------
// The next SIP message of the queue (other messages, such as transaction terminations, are dropped).
std::unique_ptr<resip::SipMessage> ResipUser::next() {
  while (mFifo.messageAvailable()) {
    std::unique_ptr<resip::Message> message(mFifo.getNext());
    if (auto *sip = dynamic_cast<resip::SipMessage *>(message.get())) {
      message.release();
      return std::unique_ptr<resip::SipMessage>(sip);
    }
  }
  return nullptr;
}

//------------------------------------------------------------------------------
// Helper: stores and validates the configuration and callbacks (the checks of src/sip_common).
SipEngine::Impl::Impl(SipConfig value, SipCallbacks handlers)
    : config(std::move(value)), callbacks(std::move(handlers)) {
  sip_detail::validate_config(config);
}

SipEngine::Impl::~Impl() { stop(); }

//------------------------------------------------------------------------------
// RFC 3261 section 18 and TS 33.180 clause 6.1: starts the stack in its own epoll poll group with the TLS transport
// (the TLS profile, a client certificate required, the server's verified against the CA) or the debug TCP transport,
// on the listen address and port.
void SipEngine::Impl::start() {
  if (started) return;
  if (config.aka.enabled)
    throw std::logic_error("IMS AKA on reSIProcate: prototype/resiprocate/PLAN.md phase 3b");
  static const bool logging = [] {
    resip::Log::initialize(resip::Log::Cerr, resip::Log::Err, "openmcx");
    return true;
  }();
  (void)logging;
  poll_group.reset(resip::FdPollGrp::create("epoll"));
  resip::SipStackOptions options;
  options.mPollGrp = poll_group.get();
  if (config.tls.enabled) {
    auto security = std::make_unique<resip_engine::ProfileSecurity>();
    security->addCAFile(resip::Data(config.tls.ca_file));
    options.mSecurity = security.release(); // owned by the stack
  }
  stack = std::make_unique<resip::SipStack>(options);
  const resip::Data interface(config.listen_address);
  if (config.tls.enabled) {
    stack->addTransport(resip::TLS, config.listen_port, resip::V4, resip::StunDisabled, interface,
                        resip::Data(config.advertise_address), resip::Data::Empty, resip::SecurityTypes::SSLv23, 0,
                        resip::Data(config.tls.cert_file), resip::Data(config.tls.key_file),
                        resip::SecurityTypes::Mandatory);
  } else {
    stack->addTransport(resip::TCP, config.listen_port, resip::V4, resip::StunDisabled, interface);
  }
  stack->registerTransactionUser(user);
  started = true;
}

//------------------------------------------------------------------------------
// Stops the stack: its transactions and connections go with it; requests still pending get no response.
void SipEngine::Impl::stop() noexcept {
  if (!started) return;
  try {
    stack->unregisterTransactionUser(user);
  } catch (...) {
    // Nothing is left to tell: the stack goes.
  }
  stack.reset();
  poll_group.reset();
  pending.clear();
  deferred.clear();
  started = false;
}

//------------------------------------------------------------------------------
// Throws std::logic_error unless the engine is started.
void SipEngine::Impl::ensure_started() const {
  if (!started || !stack) throw std::logic_error("SIP engine is not started");
}

//------------------------------------------------------------------------------
// One wait of at most the timeout for the stack's sockets and timers (a signal ends it early), then every request
// and response its transaction user received.
void SipEngine::Impl::poll(std::chrono::milliseconds timeout) {
  ensure_started();
  if (timeout.count() < 0) throw std::invalid_argument("invalid SIP poll timeout");
  stack->process(static_cast<unsigned>(timeout.count()));
  while (auto message = user.next()) {
    if (message->isRequest())
      receive_request(*message);
    else
      receive_response(*message);
  }
}

//------------------------------------------------------------------------------
// Helper: passes an error text to the application's error callback, ignoring its exceptions.
void SipEngine::Impl::report_error(std::string_view error) const noexcept {
  if (!callbacks.on_error) return;
  try {
    callbacks.on_error(error);
  } catch (...) {
    // The application's error callback failed: nothing more can be reported.
  }
}

} // namespace mcx
