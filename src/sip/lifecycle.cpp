//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// SipEngine::Impl on reSIProcate: configuration, start and stop, the transports (TLS with the TLS profile, or debug
// TCP), the SIP message log of log level debug, and poll, one epoll wait for the stack and the dispatch of what its
// transaction user received.
//
// Specifications: RFC 3261 sections 18 and 26.2, TS 33.180 V19.4.0 (Rel-19) clause 6.1, TS 33.210 V19.3.0 clause 6.2.

#include "resip_impl.hpp"
#include "tls_security.hpp"

#include "mcx/runtime.hpp"

#include "resip/stack/Transport.hxx"
#include "rutil/DataStream.hxx"
#include "rutil/Log.hxx"

#include <sys/epoll.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <stdexcept>

namespace mcx {
namespace {

//------------------------------------------------------------------------------
// Helper: what a SIP message is, for the log: the method and Request-URI, or the status.
std::string trace_what(const resip::SipMessage &message) {
  if (message.isRequest()) {
    return std::string(message.methodStr().c_str()) + " " +
           resip::Data::from(message.const_header(resip::h_RequestLine).uri()).c_str();
  }
  return std::to_string(message.const_header(resip::h_StatusLine).responseCode());
}

//------------------------------------------------------------------------------
// Helper: the dialog fields of a SIP message for the log, " | " separated: From, To, Call-ID and CSeq; never the body
// (it may carry keys and access tokens).
std::string trace_fields(const resip::SipMessage &message) {
  std::string out;
  if (message.exists(resip::h_From))
    out += std::string(" | from <") + resip::Data::from(message.const_header(resip::h_From).uri()).c_str() + ">";
  if (message.exists(resip::h_To))
    out += std::string(" | to <") + resip::Data::from(message.const_header(resip::h_To).uri()).c_str() + ">";
  if (message.exists(resip::h_CallId))
    out += std::string(" | call-id ") + message.const_header(resip::h_CallId).value().c_str();
  if (message.exists(resip::h_CSeq)) {
    const auto &cseq = message.const_header(resip::h_CSeq);
    const auto &method =
        cseq.method() == resip::UNKNOWN ? cseq.unknownMethodName() : resip::getMethodName(cseq.method());
    out += " | cseq " + std::to_string(cseq.sequence()) + " " + method.c_str();
  }
  return out;
}

//------------------------------------------------------------------------------
// Helper: the peer's address and the transport of a message, and its size as encoded.
std::string trace_peer(const resip::Tuple &peer, const resip::SipMessage &message) {
  resip::Data encoded;
  {
    resip::DataStream stream(encoded);
    message.encode(stream);
  }
  return std::string(" | ") + resip::Tuple::inet_ntop(peer).c_str() + ":" + std::to_string(peer.getPort()) + " " +
         resip::toData(peer.getType()).c_str() + " | " + std::to_string(encoded.size()) + " bytes";
}

//------------------------------------------------------------------------------
// The SIP message log (log level debug), on every transport of the stack: a line on stderr per message received
// (before the transaction layer) and sent (after the body protection), without its body:
// "SIP <- INVITE sip:... | from <...> | to <...> | call-id ... | cseq 2 INVITE | 172.31.19.10:5061 TLS | 2310 bytes".
// Retransmissions of the transaction layer are not logged.
class SipTrace : public resip::Transport::SipMessageLoggingHandler {
public:
  void outboundMessage(const resip::Tuple &, const resip::Tuple &destination,
                       const resip::SipMessage &message) override {
    try {
      debug_line("SIP -> " + trace_what(message) + trace_fields(message) + trace_peer(destination, message));
    } catch (...) {
      // the log never stops a message
    }
  }

  void inboundMessage(const resip::Tuple &source, const resip::Tuple &, const resip::SipMessage &message) override {
    try {
      debug_line("SIP <- " + trace_what(message) + trace_fields(message) + trace_peer(source, message));
    } catch (...) {
      // the log never stops a message
    }
  }
};

} // namespace

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
  // Before any transport is added: the stack hands the log to each, the IMS AKA ones included (ims_aka.cpp).
  if (log_level() == LogLevel::debug) stack->setTransportSipMessageLoggingHandler(std::make_shared<SipTrace>());
  // PLAN.md phase 4: the set of the application's sockets, waited on with the stack's.
  wake_epoll = ::epoll_create1(EPOLL_CLOEXEC);
  if (wake_epoll < 0) throw std::runtime_error("cannot create the SIP engine's wake set");
  wake_handle = poll_group->addPollItem(wake_epoll, FPEM_Read, &wake_item);
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
  // What was handed to the stack last (a final answer just before stop) is written first: the
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
  if (wake_handle != nullptr) poll_group->delPollItem(wake_handle);
  wake_handle = nullptr;
  if (wake_epoll >= 0) ::close(wake_epoll);
  wake_epoll = -1;
  wake_sockets.clear();
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
// reSIProcate's SipStack::process(timeout) runs the transaction layer and then waits, and its wait does not count the
// messages a transaction user has queued: a message the stack had read reaches this engine's queue at the start of a
// process whose wait then still runs its full length before the application sees the message (an answer to an
// INVITE a poll timeout after its 100). So the stack first runs without waiting while it has work due now (drain),
// the wait is left out when the queue then holds a message, the stack drains again over what the wait read, and
// once more after the application's callbacks and the timers, for what they sent.
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
  drain();
  if (!user.pending()) {
    run_stack(static_cast<unsigned>(wait.count()));
    drain();
  }
  while (auto message = user.next()) {
    // The message in hand, named in what is reported meanwhile (report_error).
    handling = message->isRequest()
                   ? std::string(message->methodStr().c_str())
                   : std::to_string(message->header(resip::h_StatusLine).statusCode()) + " to " +
                         std::string(resip::getMethodName(message->header(resip::h_CSeq).method()).c_str());
    handling += " of " + std::string(message->header(resip::h_CallId).value().c_str());
    try {
      if (message->isRequest())
        receive_request(*message);
      else
        receive_response(*message);
    } catch (const std::exception &error) {
      report_error(error.what());
    }
    handling.clear();
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
  // What the callbacks and timers sent leaves now, not at the start of the next poll (transmit sends most at once).
  drain();
}

//------------------------------------------------------------------------------
void SipEngine::Impl::run_stack(unsigned wait_ms) {
  struct Running {
    bool &flag;
    explicit Running(bool &value) : flag(value) { flag = true; }
    ~Running() { flag = false; }
  } running(stack_running);
  stack->process(wait_ms);
}

//------------------------------------------------------------------------------
// A message passes the transaction layer, the target's resolution and the transport's queue, one process each: the
// stack runs without waiting while it has work due now (getTimeTillNextProcessMS 0), a few rounds at most.
void SipEngine::Impl::drain() {
  for (int round = 0; round < 8; ++round) {
    run_stack(0);
    if (stack->getTimeTillNextProcessMS() != 0) break;
  }
}

//------------------------------------------------------------------------------
void SipEngine::Impl::transmit() {
  if (!stack_running && stack) drain();
}

//------------------------------------------------------------------------------
// PLAN.md phase 4: the wake set becomes the given sockets: new ones (or a descriptor now naming another socket) are
// added, readable level-triggered; those no longer given are removed (an error for one that was closed meanwhile, and
// so already left the set, is ignored).
void SipEngine::Impl::watch(std::span<const int> sockets) {
  ensure_started();
  std::map<int, unsigned long> wanted;
  for (const int fd : sockets) {
    struct stat status {};
    if (fd >= 0 && ::fstat(fd, &status) == 0) wanted[fd] = static_cast<unsigned long>(status.st_ino);
  }
  for (auto known = wake_sockets.begin(); known != wake_sockets.end();) {
    const auto found = wanted.find(known->first);
    if (found != wanted.end() && found->second == known->second) {
      ++known;
      continue;
    }
    (void)::epoll_ctl(wake_epoll, EPOLL_CTL_DEL, known->first, nullptr);
    known = wake_sockets.erase(known);
  }
  for (const auto &[fd, inode] : wanted) {
    if (wake_sockets.contains(fd)) continue;
    epoll_event event{};
    event.events = EPOLLIN;
    event.data.fd = fd;
    if (::epoll_ctl(wake_epoll, EPOLL_CTL_ADD, fd, &event) != 0 && errno == EEXIST)
      (void)::epoll_ctl(wake_epoll, EPOLL_CTL_MOD, fd, &event);
    wake_sockets[fd] = inode;
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
    if (handling.empty())
      callbacks.on_error(error);
    else
      callbacks.on_error(std::string(error) + " (handling " + handling + ")");
  } catch (...) {
    // The application's error callback failed: nothing more can be reported.
  }
}

} // namespace mcx
