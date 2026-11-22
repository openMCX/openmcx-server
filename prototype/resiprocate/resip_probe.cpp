//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Prototype (not part of any program): reSIProcate 1.14 as the SIP stack of OpenMCX, driven from one OpenMCX-owned
// event loop. Two user agents (alice, bob) on loopback TCP run, in one process and one epoll poll group:
//   - an INVITE with reliable provisional responses (RFC 3262: 183 with RSeq and Require: 100rel, PRACK) and session
//     timers (RFC 4028: Session-Expires negotiated, with --refresh the refresh is awaited), answer, ACK, BYE;
//   - a subscription (RFC 6665: SUBSCRIBE, 200, NOTIFY with a body, a second NOTIFY, termination);
// while an OpenMCX-style UDP media socket, registered in the same poll group, receives a packet every 20 ms from a
// sender thread: the delay from sending to handling shows whether media still waits for the SIP stack (the PJSIP loop
// of src/server/server.cpp waits up to 5 ms; measured median 2.75 ms per relayed packet).
//
// Specifications: RFC 3261, RFC 3262, RFC 4028, RFC 6665.

#include "resip/dum/ClientInviteSession.hxx"
#include "resip/dum/ClientSubscription.hxx"
#include "resip/dum/DialogUsageManager.hxx"
#include "resip/dum/InviteSessionHandler.hxx"
#include "resip/dum/MasterProfile.hxx"
#include "resip/dum/ServerInviteSession.hxx"
#include "resip/dum/ServerSubscription.hxx"
#include "resip/dum/SubscriptionHandler.hxx"
#include "resip/stack/PlainContents.hxx"
#include "resip/stack/SdpContents.hxx"
#include "resip/stack/SipMessage.hxx"
#include "resip/stack/SipStack.hxx"
#include "rutil/FdPoll.hxx"
#include "rutil/Log.hxx"

#include <unistd.h>

#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;

// Loopback ports of the two user agents and of the media socket.
constexpr int alice_port = 15060;
constexpr int bob_port = 15070;
constexpr int media_port = 15080;
// RFC 4028 section 4: the smallest Session-Expires (Min-SE default 90 s); the refresh comes at half of it.
constexpr unsigned session_expires_s = 90;
// The media packet interval of AMR-WB speech (TS 26.114 clause 7.4.2: 20 ms frames).
constexpr auto media_interval = std::chrono::milliseconds(20);
// The time allowed for the call and subscription flows, and for a session refresh with --refresh.
constexpr auto flow_timeout = std::chrono::seconds(10);
constexpr auto refresh_timeout = std::chrono::seconds(60);
// The longest single wait of the event loop: the stacks' own timers shorten it.
constexpr unsigned loop_wait_ms = 50;

int failures = 0;

//------------------------------------------------------------------------------
// With PROBE_TRACE=1, prints a callback and the Subscription-State of its NOTIFY.
void trace(const char *callback, const resip::SipMessage *message) {
  static const bool enabled = std::getenv("PROBE_TRACE") != nullptr;
  if (!enabled) return;
  std::cout << "  trace: " << callback;
  if (message && message->exists(resip::h_SubscriptionState))
    std::cout << ", Subscription-State " << message->header(resip::h_SubscriptionState).value();
  if (message) std::cout << ", " << message->brief();
  std::cout << '\n';
}

//------------------------------------------------------------------------------
// Records a check: a failure is counted and printed, a success printed.
void check(bool condition, const std::string &text) {
  std::cout << (condition ? "  ok   " : "  FAIL ") << text << '\n';
  if (!condition) ++failures;
}

// A minimal SDP offer or answer for an audio stream on a port. reSIProcate parses contents lazily from the buffer it
// was given, so the text is kept alive with the contents.
struct Sdp {
  resip::Data text;
  resip::HeaderFieldValue value;
  resip::SdpContents contents;

  explicit Sdp(int port)
      : text("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio " + resip::Data(port) +
             " RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000/1\r\n"),
        value(text.data(), static_cast<unsigned>(text.size())), contents(value, resip::Mime("application", "sdp")) {}
};

// What the two user agents observed, for the checks.
struct Observed {
  bool reliable_183 = false;     // alice: a 183 with RSeq and Require: 100rel
  bool prack_received = false;   // bob: the PRACK of the reliable 183
  bool invite_has_timer = false; // bob: Session-Expires in the INVITE
  bool answer_has_timer = false; // alice: Session-Expires with a refresher in the 200
  bool connected = false;        // alice: the 200 (OK)
  bool ack_received = false;     // bob: the ACK
  bool refresh_sent = false;     // alice: a session refresh (re-INVITE or UPDATE in the dialog)
  bool call_ended = false;       // bob: the BYE
  int notifies = 0;              // alice: NOTIFYs with a body
  std::string last_notify_body;
  bool subscription_ended = false; // bob: the subscription terminated
};

// alice's and bob's INVITE handling (DUM callbacks); bob answers with a reliable 183, then 200.
class CallHandler : public resip::InviteSessionHandler {
public:
  CallHandler(Observed &observed, bool is_callee) : observed_(observed), is_callee_(is_callee) {}

  //------------------------------------------------------------------------------
  // RFC 4028 section 9: bob, the UAS, checks the timer of the INVITE; the offer follows in onOffer.
  void onNewSession(resip::ServerInviteSessionHandle session, resip::InviteSession::OfferAnswerType,
                    const resip::SipMessage &message) override {
    observed_.invite_has_timer = message.exists(resip::h_SessionExpires);
    server_session_ = session;
  }

  //------------------------------------------------------------------------------
  // RFC 3262 section 4: alice, the UAC, receives the 183; DUM sends the PRACK.
  void onProvisional(resip::ClientInviteSessionHandle, const resip::SipMessage &message) override {
    if (message.header(resip::h_StatusLine).statusCode() != 183) return;
    const bool requires_100rel = message.exists(resip::h_Requires) &&
                                 message.header(resip::h_Requires).find(resip::Token(resip::Symbols::C100rel));
    observed_.reliable_183 = message.exists(resip::h_RSeq) && requires_100rel;
  }

  //------------------------------------------------------------------------------
  // RFC 3262 section 5: the INVITE carried the offer, so bob's first reliable provisional response carries the
  // answer: a 183 with SDP, sent reliably (DUM adds RSeq and Require: 100rel in the UAS "Required" mode).
  void onOffer(resip::InviteSessionHandle, const resip::SipMessage &, const resip::SdpContents &) override {
    if (!is_callee_ || !server_session_.isValid()) return;
    answer_ = std::make_unique<Sdp>(bob_port + 2);
    server_session_->provideAnswer(answer_->contents);
    server_session_->provisional(183, true);
  }

  //------------------------------------------------------------------------------
  // RFC 3262 section 3: bob receives the PRACK of the 183, then accepts the call with 200 (OK).
  void onPrack(resip::ServerInviteSessionHandle session, const resip::SipMessage &) override {
    observed_.prack_received = true;
    session->accept();
  }

  //------------------------------------------------------------------------------
  // RFC 4028 section 10: alice's 200 (OK) carries the negotiated Session-Expires and its refresher.
  void onConnected(resip::ClientInviteSessionHandle session, const resip::SipMessage &message) override {
    observed_.connected = true;
    client_session_ = session;
    observed_.answer_has_timer =
        message.exists(resip::h_SessionExpires) && message.header(resip::h_SessionExpires).exists(resip::p_refresher);
  }

  void onConnected(resip::InviteSessionHandle, const resip::SipMessage &) override {}

  //------------------------------------------------------------------------------
  // RFC 3261 section 13.2.2.4: bob receives the ACK.
  void onConnectedConfirmed(resip::InviteSessionHandle, const resip::SipMessage &) override {
    observed_.ack_received = true;
  }

  //------------------------------------------------------------------------------
  // RFC 4028 section 10: a request alice sends inside the established dialog that is not the BYE is the refresh.
  void onReadyToSend(resip::InviteSessionHandle, resip::SipMessage &message) override {
    if (!message.isRequest() || !observed_.connected) return;
    const auto method = message.header(resip::h_RequestLine).method();
    if (method == resip::UPDATE || method == resip::INVITE) observed_.refresh_sent = true;
  }

  void onTerminated(resip::InviteSessionHandle, resip::InviteSessionHandler::TerminatedReason,
                    const resip::SipMessage *) override {
    if (is_callee_) observed_.call_ended = true;
  }

  // Alice ends the call when the checks are done.
  void hang_up() {
    if (client_session_.isValid()) client_session_->end();
  }

  // The callbacks this prototype does not need.
  void onNewSession(resip::ClientInviteSessionHandle, resip::InviteSession::OfferAnswerType,
                    const resip::SipMessage &) override {}

  void onFailure(resip::ClientInviteSessionHandle, const resip::SipMessage &) override {}

  void onEarlyMedia(resip::ClientInviteSessionHandle, const resip::SipMessage &, const resip::SdpContents &) override {}

  void onForkDestroyed(resip::ClientInviteSessionHandle) override {}

  void onRedirected(resip::ClientInviteSessionHandle, const resip::SipMessage &) override {}

  void onAnswer(resip::InviteSessionHandle, const resip::SipMessage &, const resip::SdpContents &) override {}

  void onOfferRequired(resip::InviteSessionHandle, const resip::SipMessage &) override {}

  void onOfferRejected(resip::InviteSessionHandle, const resip::SipMessage *) override {}

  void onInfo(resip::InviteSessionHandle session, const resip::SipMessage &) override { session->acceptNIT(); }

  void onInfoSuccess(resip::InviteSessionHandle, const resip::SipMessage &) override {}

  void onInfoFailure(resip::InviteSessionHandle, const resip::SipMessage &) override {}

  void onMessage(resip::InviteSessionHandle session, const resip::SipMessage &) override { session->acceptNIT(); }

  void onMessageSuccess(resip::InviteSessionHandle, const resip::SipMessage &) override {}

  void onMessageFailure(resip::InviteSessionHandle, const resip::SipMessage &) override {}

  void onRefer(resip::InviteSessionHandle, resip::ServerSubscriptionHandle, const resip::SipMessage &) override {}

  void onReferNoSub(resip::InviteSessionHandle, const resip::SipMessage &) override {}

  void onReferRejected(resip::InviteSessionHandle, const resip::SipMessage &) override {}

  void onReferAccepted(resip::InviteSessionHandle, resip::ClientSubscriptionHandle,
                       const resip::SipMessage &) override {}

private:
  Observed &observed_;
  bool is_callee_;
  std::unique_ptr<Sdp> answer_;
  resip::ServerInviteSessionHandle server_session_;
  resip::ClientInviteSessionHandle client_session_;
};

// The event package of the prototype's subscription.
const resip::Data probe_event("org.openmcx.probe");

// alice, the subscriber: counts the NOTIFYs and answers each with 200 (OK).
class Subscriber : public resip::ClientSubscriptionHandler {
public:
  explicit Subscriber(Observed &observed) : observed_(observed) {}

  //------------------------------------------------------------------------------
  // RFC 6665 section 4.1.3: a NOTIFY of the active subscription; its body is the state.
  void onUpdateActive(resip::ClientSubscriptionHandle subscription, const resip::SipMessage &notify, bool) override {
    trace("onUpdateActive", &notify);
    if (notify.getContents()) {
      ++observed_.notifies;
      observed_.last_notify_body = notify.getContents()->getBodyData().c_str();
    }
    subscription->acceptUpdate();
    subscription_ = subscription;
  }

  void onUpdatePending(resip::ClientSubscriptionHandle subscription, const resip::SipMessage &notify, bool) override {
    trace("onUpdatePending", &notify);
    subscription->acceptUpdate();
  }

  void onUpdateExtension(resip::ClientSubscriptionHandle subscription, const resip::SipMessage &notify, bool) override {
    trace("onUpdateExtension", &notify);
    subscription->acceptUpdate();
  }

  int onRequestRetry(resip::ClientSubscriptionHandle, int, const resip::SipMessage &message) override {
    trace("onRequestRetry", &message);
    return -1;
  }

  void onTerminated(resip::ClientSubscriptionHandle, const resip::SipMessage *message) override {
    if (message) std::cout << "  subscription terminated by: " << message->brief() << '\n';
  }

  void onNewSubscription(resip::ClientSubscriptionHandle, const resip::SipMessage &notify) override {
    trace("onNewSubscription (client)", &notify);
  }

  // Alice ends the subscription (RFC 6665 section 4.1.2.3: SUBSCRIBE with Expires: 0).
  void unsubscribe() {
    if (subscription_.isValid()) subscription_->end();
  }

private:
  Observed &observed_;
  resip::ClientSubscriptionHandle subscription_;
};

// bob, the notifier: accepts the subscription and sends the state, then a changed state.
class Notifier : public resip::ServerSubscriptionHandler {
public:
  explicit Notifier(Observed &observed) : observed_(observed) {}

  //------------------------------------------------------------------------------
  // RFC 6665 sections 4.2.1.1 and 4.2.2: accept with 200 and send the initial NOTIFY with the current state, with
  // Subscription-State: active (DUM sends what the notifier sets; accept() alone leaves it unset). With
  // notify_first, the NOTIFY is sent first and the 200 only once the subscriber has answered the NOTIFY: the
  // subscriber then always has the NOTIFY before the 200, the order it "MUST be prepared" for (RFC 6665 section
  // 4.1.2.4), which happens when the NOTIFY overtakes the 200 on another TCP connection.
  void onNewSubscription(resip::ServerSubscriptionHandle subscription, const resip::SipMessage &) override {
    subscription_ = subscription;
    subscription->setSubscriptionState(resip::Active);
    if (notify_first) {
      held_accept_ = subscription->accept(200);
      notify("state=1");
      return;
    }
    subscription->send(subscription->accept(200));
    notify("state=1");
  }

  //------------------------------------------------------------------------------
  // The subscriber accepted the early NOTIFY: now the 200 to the SUBSCRIBE.
  void onNotifyAccepted(resip::ServerSubscriptionHandle subscription, const resip::SipMessage &) override {
    if (held_accept_) subscription->send(std::move(held_accept_));
  }

  //------------------------------------------------------------------------------
  // The subscriber refused the NOTIFY (an unpatched DUM answers the early NOTIFY with 481).
  void onNotifyRejected(resip::ServerSubscriptionHandle, const resip::SipMessage &response) override {
    std::cout << "  the subscriber refused the NOTIFY: " << response.header(resip::h_StatusLine).statusCode() << '\n';
    held_accept_.reset();
  }

  bool notify_first = false;

  void onTerminated(resip::ServerSubscriptionHandle) override { observed_.subscription_ended = true; }

  // RFC 6665 section 4.2.2: a NOTIFY with a changed state.
  void notify(const char *state) {
    if (!subscription_.isValid()) return;
    const resip::PlainContents body{resip::Data(state)};
    subscription_->send(subscription_->update(&body));
  }

private:
  Observed &observed_;
  resip::ServerSubscriptionHandle subscription_;
  std::shared_ptr<resip::SipMessage> held_accept_;
};

// An OpenMCX-style UDP media socket in the poll group: each datagram carries its send time; the handler records the
// delay from sending to handling.
class MediaSocket : public resip::FdPollItemIf {
public:
  MediaSocket(resip::FdPollGrp &group, int port) : group_(group) {
    fd_ = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(static_cast<std::uint16_t>(port));
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd_ < 0 || bind(fd_, reinterpret_cast<sockaddr *>(&address), sizeof address) != 0)
      throw std::runtime_error("media socket");
    handle_ = group_.addPollItem(fd_, FPEM_Read, this);
  }

  ~MediaSocket() override {
    group_.delPollItem(handle_);
    close(fd_);
  }

  //------------------------------------------------------------------------------
  // The poll group found the socket readable: read every datagram and record its delay.
  void processPollEvent(resip::FdPollEventMask) override {
    std::int64_t sent_ns = 0;
    while (recv(fd_, &sent_ns, sizeof sent_ns, 0) == static_cast<ssize_t>(sizeof sent_ns)) {
      const auto now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch()).count();
      delays_us_.push_back(static_cast<double>(now_ns - sent_ns) / 1000.0);
    }
  }

  std::vector<double> &delays_us() { return delays_us_; }

private:
  resip::FdPollGrp &group_;
  int fd_ = -1;
  resip::FdPollItemHandle handle_ = nullptr;
  std::vector<double> delays_us_;
};

// The media sender thread, stopped and joined when it goes out of scope (also on an exception).
class MediaSender {
public:
  MediaSender();

  ~MediaSender() {
    running_ = false;
    thread_.join();
  }

private:
  std::atomic<bool> running_{true};
  std::thread thread_;
};

//------------------------------------------------------------------------------
// The media sender thread: one datagram with its send time every 20 ms, asynchronous to the event loop.
void send_media(const std::atomic<bool> &running) {
  const int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  sockaddr_in target{};
  target.sin_family = AF_INET;
  target.sin_port = htons(media_port);
  target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  auto next = Clock::now();
  while (running) {
    next += media_interval;
    std::this_thread::sleep_until(next);
    const std::int64_t sent_ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch()).count();
    sendto(fd, &sent_ns, sizeof sent_ns, 0, reinterpret_cast<sockaddr *>(&target), sizeof target);
  }
  close(fd);
}

MediaSender::MediaSender() : thread_(send_media, std::cref(running_)) {}

// A user agent: its SIP stack (TCP and UDP on loopback, in the shared poll group) and DUM with its profile.
struct Agent {
  resip::SipStack stack;
  std::unique_ptr<resip::DialogUsageManager> dum;
  std::shared_ptr<resip::MasterProfile> profile = std::make_shared<resip::MasterProfile>();

  //------------------------------------------------------------------------------
  // RFC 3262 and RFC 4028 profile: 100rel and timer supported, Session-Expires 90 s with the caller refreshing; the
  // probe's event package and text/plain NOTIFY bodies.
  Agent(resip::FdPollGrp &group, const char *user, int port, resip::MasterProfile::ReliableProvisionalMode uas_mode)
      : stack(options(group)) {
    stack.addTransport(resip::TCP, port, resip::V4, resip::StunDisabled, "127.0.0.1");
    stack.addTransport(resip::UDP, port, resip::V4, resip::StunDisabled, "127.0.0.1");
    dum = std::make_unique<resip::DialogUsageManager>(stack);
    profile->setDefaultFrom(resip::NameAddr(resip::Data("sip:") + user + "@127.0.0.1:" + resip::Data(port)));
    profile->setUacReliableProvisionalMode(resip::MasterProfile::Supported);
    profile->setUasReliableProvisionalMode(uas_mode);
    profile->addSupportedOptionTag(resip::Token(resip::Symbols::Timer));
    profile->setDefaultSessionTime(session_expires_s);
    profile->setDefaultSessionTimerMode(resip::Profile::PreferCallerRefreshes);
    profile->addSupportedMethod(resip::SUBSCRIBE);
    profile->addSupportedMethod(resip::NOTIFY);
    profile->addSupportedMethod(resip::PRACK);
    profile->addSupportedMethod(resip::UPDATE);
    profile->addSupportedMimeType(resip::NOTIFY, resip::PlainContents::getStaticType());
    profile->addAllowedEvent(resip::Token(probe_event));
    dum->setMasterProfile(profile);
  }

  static resip::SipStackOptions options(resip::FdPollGrp &group) {
    resip::SipStackOptions result;
    result.mPollGrp = &group;
    return result;
  }
};

//------------------------------------------------------------------------------
// One turn of the OpenMCX event loop: one epoll wait for everything (both stacks' sockets and the media socket), then
// each stack's timers and each DUM's queue.
void turn(Agent &alice, Agent &bob, unsigned wait_ms) {
  alice.stack.process(wait_ms);
  bob.stack.process(0);
  while (alice.dum->process()) {}
  while (bob.dum->process()) {}
}

//------------------------------------------------------------------------------
// Runs the event loop until the condition holds or the time is up; returns whether it held.
template <class Condition> bool run_until(Agent &alice, Agent &bob, Condition &&condition, std::chrono::seconds limit) {
  const auto deadline = Clock::now() + limit;
  while (!condition() && Clock::now() < deadline) turn(alice, bob, loop_wait_ms);
  return condition();
}

//------------------------------------------------------------------------------
// Prints the delay distribution of the media packets handled by the loop.
void report_media(std::vector<double> &delays_us) {
  if (delays_us.empty()) {
    check(false, "media packets were handled by the event loop");
    return;
  }
  std::sort(delays_us.begin(), delays_us.end());
  const auto at = [&](double quantile) {
    return delays_us[std::min(delays_us.size() - 1, static_cast<std::size_t>(quantile * delays_us.size()))];
  };
  std::cout << "  media: " << delays_us.size() << " packets, send-to-handle delay median " << at(0.5) << " us, p90 "
            << at(0.9) << " us, p99 " << at(0.99) << " us, max " << delays_us.back() << " us\n";
  check(at(0.99) < 1000.0, "media p99 under 1 ms with SIP and media in one epoll (PJSIP loop: median 2.75 ms)");
}

} // namespace

int main(int argc, char **argv) {
  const bool wait_for_refresh = argc > 1 && std::string(argv[1]) == "--refresh";
  // PROBE_LOG=Info (or Debug, Stack) shows reSIProcate's own log.
  const char *log_level = std::getenv("PROBE_LOG");
  resip::Log::initialize(resip::Log::Cout, log_level ? resip::Log::toLevel(log_level) : resip::Log::Warning, argv[0]);
  try {
    std::unique_ptr<resip::FdPollGrp> group(resip::FdPollGrp::create("epoll"));
    std::cout << "poll group: " << group->getImplName() << '\n';
    Observed observed;
    MediaSocket media(*group, media_port);
    {
      const MediaSender sender;
      Agent alice(*group, "alice", alice_port, resip::MasterProfile::Required);
      Agent bob(*group, "bob", bob_port, resip::MasterProfile::Required);
      CallHandler caller(observed, false);
      CallHandler callee(observed, true);
      Subscriber subscriber(observed);
      Notifier notifier(observed);
      alice.dum->setInviteSessionHandler(&caller);
      bob.dum->setInviteSessionHandler(&callee);
      alice.dum->addClientSubscriptionHandler(probe_event, &subscriber);
      bob.dum->addServerSubscriptionHandler(probe_event, &notifier);

      std::cout << "INVITE with 100rel and session timers over TCP\n";
      const resip::NameAddr bob_uri("sip:bob@127.0.0.1:15070;transport=tcp");
      const Sdp offer(alice_port + 2);
      alice.dum->send(alice.dum->makeInviteSession(bob_uri, &offer.contents));
      const bool established =
          run_until(alice, bob, [&] { return observed.connected && observed.ack_received; }, flow_timeout);
      check(observed.invite_has_timer, "RFC 4028: the INVITE carries Session-Expires");
      check(observed.reliable_183, "RFC 3262: the 183 carries RSeq and Require: 100rel");
      check(observed.prack_received, "RFC 3262: the callee receives the PRACK");
      check(established, "RFC 3261: 200 (OK) and ACK");
      check(observed.answer_has_timer, "RFC 4028: the 200 (OK) carries Session-Expires with a refresher");
      if (wait_for_refresh) {
        std::cout << "waiting up to " << refresh_timeout.count() << " s for the session refresh\n";
        check(run_until(
                  alice, bob, [&] { return observed.refresh_sent; }, refresh_timeout),
              "RFC 4028 section 10: the caller refreshes the session at half the interval");
      }

      for (const bool notify_first : {false, true}) {
        std::cout << (notify_first ? "SUBSCRIBE, the initial NOTIFY before its 200 (RFC 6665 section 4.1.2.4)\n"
                                   : "SUBSCRIBE and NOTIFY over TCP\n");
        observed.notifies = 0;
        observed.subscription_ended = false;
        notifier.notify_first = notify_first;
        alice.dum->send(alice.dum->makeSubscription(bob_uri, probe_event));
        check(run_until(
                  alice, bob, [&] { return observed.notifies >= 1; }, flow_timeout),
              "RFC 6665: 200 and the initial NOTIFY with the state");
        notifier.notify("state=2");
        check(run_until(
                  alice, bob, [&] { return observed.notifies >= 2; }, flow_timeout) &&
                  observed.last_notify_body == "state=2",
              "RFC 6665: a NOTIFY with the changed state");
        subscriber.unsubscribe();
        check(run_until(
                  alice, bob, [&] { return observed.subscription_ended; }, flow_timeout),
              "RFC 6665: the subscription ends");
      }

      caller.hang_up();
      check(run_until(alice, bob, [&] { return observed.call_ended; }, flow_timeout), "RFC 3261: BYE ends the call");
      run_until(alice, bob, [] { return false; }, std::chrono::seconds(1));
    }
    report_media(media.delays_us());
  } catch (const std::exception &error) {
    std::cerr << "FAIL: " << error.what() << '\n';
    return 1;
  }
  std::cout << (failures == 0 ? "PASS" : "FAIL") << ": reSIProcate prototype, " << failures << " failed checks\n";
  return failures == 0 ? 0 : 1;
}
