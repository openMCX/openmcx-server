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

#include <algorithm>
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
  if (config.aka.enabled) {
    // TS 33.203 clause 7: IMS AKA, its transports and security associations (ims_aka.cpp).
    try {
      aka_start();
    } catch (...) {
      aka_stop();
      stack.reset();
      poll_group.reset();
      throw;
    }
  } else if (config.tls.enabled) {
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
  // What was handed to the stack last (a final answer just before stop, as pjsip sends at once) is written first: the
  // stack sends from its own processing.
  try {
    for (int round = 0; round < 10; ++round) stack->process(10);
  } catch (...) {
    // Stopping goes on regardless.
  }
  // The IMS AKA security associations go first, while the stack and its transports exist.
  aka_stop();
  try {
    stack->unregisterTransactionUser(user);
  } catch (...) {
    // Nothing is left to tell: the stack goes.
  }
  stack.reset();
  poll_group.reset();
  pending.clear();
  deferred.clear();
  registration.reset();
  ending_flow.reset();
  dialogs.clear();
  timers.clear();
  transactions.clear();
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
  // The wait ends at the engine's next timer at the latest (the stack bounds it by its own).
  auto wait = timeout;
  const auto now = Clock::now();
  for (const auto &[timer, due] : timers) {
    (void)timer;
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(due - now);
    wait = std::min(wait, std::max(left, std::chrono::milliseconds(0)));
  }
  stack->process(static_cast<unsigned>(wait.count()));
  while (auto message = user.next()) {
    if (message->isRequest())
      receive_request(*message);
    else
      receive_response(*message);
  }
  // The timers due now, each once.
  std::vector<TimerKey> due;
  for (const auto &[timer, at] : timers)
    if (at <= Clock::now()) due.push_back(timer);
  for (const auto &timer : due) {
    timers.erase(timer);
    try {
      fire(timer.first, timer.second);
    } catch (const std::exception &error) {
      report_error(error.what());
    } catch (...) {
      report_error("unknown SIP timer error");
    }
  }
}

//------------------------------------------------------------------------------
// Helper: (re)starts one of the engine's timers.
void SipEngine::Impl::schedule(Timer timer, std::chrono::milliseconds delay, const std::string &key) {
  timers[{timer, key}] = Clock::now() + delay;
}

//------------------------------------------------------------------------------
// Helper: stops one of the engine's timers.
void SipEngine::Impl::cancel(Timer timer, const std::string &key) noexcept { timers.erase({timer, key}); }

//------------------------------------------------------------------------------
// The engine's timers: the refresh of a digest registration (RFC 3261 section 10.2.1), the end of a registration's
// connection (registration_ended), and the IMS AKA timers: the refresh (TS 24.229 clause 5.1.1.4.1), the end of the
// temporary set (reg-await-auth, clause 5.1.1.5.1), the end of the old set (TS 33.203 clause 7.4.1a) and the end of
// the set in use at its lifetime ("The UE shall delete any SA whose lifetime is exceeded").
void SipEngine::Impl::fire(Timer timer, const std::string &key) {
  switch (timer) {
  case Timer::registration_refresh:
    if (registration && registration->expires != 0) register_digest(registration->expires, {}, {}, registration->handler);
    break;
  case Timer::flow_end:
    end_registration();
    break;
  case Timer::aka_refresh:
    if (aka && !aka->busy && aka->current) aka_register(aka->expires, {}, {}, aka->handler);
    break;
  case Timer::aka_pending:
    if (aka) aka_delete(aka->pending);
    break;
  case Timer::aka_old:
    if (aka) aka_old_check();
    break;
  case Timer::aka_expiry:
    if (aka) {
      aka_delete(aka->old);
      aka_delete(aka->current);
      aka_use(nullptr);
      report_error("IMS AKA: the security associations expired; the registration has ended");
    }
    break;
  case Timer::answer_retransmit:
    if (const auto found = dialogs.find(key); found != dialogs.end() && !found->second->answer_text.empty()) {
      auto &dialog = *found->second;
      // RFC 3261 section 13.3.1.4: the 2xx again, the interval doubling up to T2 (4 s).
      const resip::Data wire(dialog.answer_text);
      if (std::unique_ptr<resip::SipMessage> again(resip::SipMessage::make(wire, false)); again)
        stack->send(std::move(again), &user);
      dialog.answer_interval = std::min(dialog.answer_interval * 2, std::chrono::milliseconds(4000));
      schedule(Timer::answer_retransmit, dialog.answer_interval, key);
    }
    break;
  case Timer::answer_timeout:
    // RFC 3261 section 13.3.1.4: no ACK within 64*T1: the session ends with BYE.
    if (const auto found = dialogs.find(key); found != dialogs.end() && found->second->pending_ack_cseq) {
      report_error("SIP: no ACK for the 2xx of dialog " + key + " (RFC 3261 section 13.3.1.4)");
      found->second->answer_text.clear();
      cancel(Timer::answer_retransmit, key);
      found->second->pending_ack_cseq.reset();
      end_dialog(key, {}, {}, {});
    }
    break;
  case Timer::session_refresh:
    refresh_session(key);
    break;
  case Timer::session_expiry:
    // RFC 4028 section 10: the session was not refreshed in time: this side ends it with BYE.
    if (dialogs.contains(key)) {
      report_error("SIP: session of dialog " + key + " expired without refresh (RFC 4028 section 10)");
      end_dialog(key, {}, {}, {});
    }
    break;
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
