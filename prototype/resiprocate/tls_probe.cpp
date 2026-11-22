//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Prototype (not part of any program): SIP over TLS on reSIProcate 1.14 with OpenMCX's TLS profile, TS 33.210 clause
// 6.2 (include/mcx/tls_profile.hpp), as src/sip/lifecycle.cpp sets it on pjsip's TLS transport: TLS 1.2 and TLS 1.3
// only, for TLS 1.2 only the ECDHE AEAD suites, the groups of the profile (no ffdhe), the server requiring a client
// certificate, the client verifying the server's. ProfileSecurity applies the profile to every SSL_CTX the stack
// creates (its own and each TLS transport's).
//
//   tls_probe serve --certs DIR --name NAME --port PORT --seconds N   a TLS listener answering 200 to every request
//   tls_probe call  --certs DIR --name NAME --target sip:...          an OPTIONS over TLS; exit 0 on a 200
//
// DIR holds ca.pem and NAME.pem / NAME.key (prototype/resiprocate/run-tls-probe.sh makes them).
//
// Specifications: TS 33.210 V19.3.0 clause 6.2, TS 33.180 V19.4.0 (Rel-19) clause 6.1, RFC 3261 section 26.2.

#include "mcx/tls_profile.hpp"
#include "resip/stack/Helper.hxx"
#include "resip/stack/SipMessage.hxx"
#include "resip/stack/SipStack.hxx"
#include "resip/stack/TransactionUser.hxx"
#include "resip/stack/ssl/Security.hxx"
#include "rutil/FdPoll.hxx"
#include "rutil/Log.hxx"

#include <openssl/ssl.h>

#include <chrono>
#include <iostream>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>

namespace {

using Clock = std::chrono::steady_clock;

// How long a call waits for the final response.
constexpr auto call_timeout = std::chrono::seconds(10);

//------------------------------------------------------------------------------
// TS 33.210 clause 6.2 (mcx/tls_profile.hpp): on one SSL_CTX: TLS 1.2 to TLS 1.3, the TLS 1.2 suites, the groups.
void apply_profile(SSL_CTX *ctx) {
  if (ctx == nullptr) return;
  if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1 ||
      SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1 ||
      SSL_CTX_set_cipher_list(ctx, mcx::tls_profile::tls12_ciphers) != 1 ||
      SSL_CTX_set1_groups_list(ctx, mcx::tls_profile::groups) != 1)
    throw std::runtime_error("cannot apply the TLS profile");
}

// reSIProcate's Security with the TLS profile on every SSL_CTX: the stack's own (client side) and each TLS transport's
// domain context (server side, made for its certificate).
class ProfileSecurity : public resip::Security {
public:
  ProfileSecurity() : Security(resip::BaseSecurity::CipherList(mcx::tls_profile::tls12_ciphers)) {
    apply_profile(getTlsCtx());
    apply_profile(getSslCtx());
  }

  SSL_CTX *createDomainCtx(const SSL_METHOD *method, const resip::Data &domain, const resip::Data &certificate,
                           const resip::Data &key, const resip::Data &passphrase) override {
    SSL_CTX *ctx = Security::createDomainCtx(method, domain, certificate, key, passphrase);
    apply_profile(ctx);
    return ctx;
  }
};

// Answers 200 to every request; keeps the final response of the probe's own request.
class User : public resip::TransactionUser {
public:
  const resip::Data &name() const override {
    static const resip::Data user_name("openmcx-tls-probe");
    return user_name;
  }

  //------------------------------------------------------------------------------
  // Takes the queue: requests are answered, a final response is kept.
  void drain(resip::SipStack &stack) {
    while (mFifo.messageAvailable()) {
      std::unique_ptr<resip::Message> message(mFifo.getNext());
      auto *sip = dynamic_cast<resip::SipMessage *>(message.get());
      if (sip == nullptr) continue;
      if (sip->isRequest()) {
        ++requests;
        if (sip->method() == resip::ACK) continue;
        std::unique_ptr<resip::SipMessage> response(resip::Helper::makeResponse(*sip, 200));
        stack.send(std::move(response), this);
      } else if (sip->header(resip::h_StatusLine).statusCode() >= 200) {
        final_status = sip->header(resip::h_StatusLine).statusCode();
      }
    }
  }

  int final_status = 0;
  unsigned requests = 0;
};

//------------------------------------------------------------------------------
// Helper: the options of the command line, --name value.
std::map<std::string, std::string> options(int argc, char **argv) {
  std::map<std::string, std::string> result;
  for (int index = 2; index + 1 < argc; index += 2) result[argv[index]] = argv[index + 1];
  return result;
}

//------------------------------------------------------------------------------
// The stack: one epoll poll group, ProfileSecurity with the CA, and a TLS transport with NAME's certificate that
// requires a client certificate (TS 33.180 clause 6.1: mutual authentication).
struct Stack {
  std::unique_ptr<resip::FdPollGrp> group{resip::FdPollGrp::create("epoll")};
  ProfileSecurity *security = nullptr;
  std::unique_ptr<resip::SipStack> stack;
  User user;

  Stack(const std::string &certs, const std::string &name, int port) {
    auto owned = std::make_unique<ProfileSecurity>();
    security = owned.get();
    security->addCAFile(resip::Data(certs + "/ca.pem"));
    resip::SipStackOptions options;
    options.mPollGrp = group.get();
    options.mSecurity = owned.release(); // owned by the stack
    stack = std::make_unique<resip::SipStack>(options);
    stack->addTransport(resip::TLS, port, resip::V4, resip::StunDisabled, resip::Data("127.0.0.1"),
                        resip::Data("localhost"), resip::Data::Empty, resip::SecurityTypes::SSLv23, 0,
                        resip::Data(certs + "/" + name + ".pem"), resip::Data(certs + "/" + name + ".key"),
                        resip::SecurityTypes::Mandatory);
    stack->registerTransactionUser(user);
  }

  void run_for(std::chrono::milliseconds duration) {
    const auto deadline = Clock::now() + duration;
    while (Clock::now() < deadline) {
      stack->process(50);
      user.drain(*stack);
    }
  }
};

//------------------------------------------------------------------------------
// serve: a TLS listener on the port for the given seconds.
int serve(const std::map<std::string, std::string> &option) {
  Stack sip(option.at("--certs"), option.at("--name"), std::stoi(option.at("--port")));
  std::cout << "serving TLS on 127.0.0.1:" << option.at("--port") << '\n' << std::flush;
  sip.run_for(std::chrono::seconds(std::stoi(option.at("--seconds"))));
  std::cout << "served " << sip.user.requests << " requests\n";
  return 0;
}

//------------------------------------------------------------------------------
// call: an OPTIONS to the target over TLS (RFC 3261 section 11); 0 on a 200, 1 otherwise.
int call(const std::map<std::string, std::string> &option) {
  Stack sip(option.at("--certs"), option.at("--name"), 0);
  const resip::NameAddr target{resip::Data(option.at("--target"))};
  const resip::NameAddr from{resip::Data("sip:" + option.at("--name") + "@localhost")};
  std::unique_ptr<resip::SipMessage> request(resip::Helper::makeRequest(target, from, resip::OPTIONS));
  sip.stack->send(std::move(request), &sip.user);
  const auto deadline = Clock::now() + call_timeout;
  while (Clock::now() < deadline && sip.user.final_status == 0) {
    sip.stack->process(50);
    sip.user.drain(*sip.stack);
  }
  std::cout << "OPTIONS over TLS to " << option.at("--target") << ": " << sip.user.final_status << '\n';
  return sip.user.final_status == 200 ? 0 : 1;
}

} // namespace

int main(int argc, char **argv) {
  const char *log_level = std::getenv("PROBE_LOG");
  resip::Log::initialize(resip::Log::Cout, log_level ? resip::Log::toLevel(log_level) : resip::Log::Warning, argv[0]);
  try {
    const std::string mode = argc > 1 ? argv[1] : "";
    if (mode == "serve") return serve(options(argc, argv));
    if (mode == "call") return call(options(argc, argv));
    std::cerr << "usage: tls_probe serve|call --certs DIR --name NAME (--port P --seconds N | --target URI)\n";
  } catch (const std::exception &error) {
    std::cerr << "FAIL: " << error.what() << '\n';
  }
  return 2;
}
