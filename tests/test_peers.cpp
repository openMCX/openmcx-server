// The peers of an MC server and their registration (src/server/parts/peers.hpp, peer_registration.hpp): the peer
// configuration, the SPK, the source address match, the routes, and peer registration both ways against a fake host.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19), RFC 3261.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "parts/peer_registration.hpp"
#include "parts/peers.hpp"

#include <cassert>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
using namespace mcx;

namespace {
//------------------------------------------------------------------------------
// Helper: whether the call throws std::runtime_error with the text.
template <typename Call> bool refuses(Call call, const std::string &text) {
  try {
    call();
  } catch (const std::runtime_error &error) {
    return error.what() == text;
  }
  return false;
}

// An SPK with purpose tag 3, its key and RAND (TS 33.180 clause 5.5).
const Json spk = {{"id", 0x30000001U}, {"key", std::string(32, 'a')}, {"rand", std::string(32, 'b')}};

//------------------------------------------------------------------------------
// TS 23.379 clause 7.5.2.4: a peer from the configuration: route and hosts, the media host, the controlling role and
// the floor-control SPK with its RAND.
void Clause_7_5_2_4_ConfiguredPeer() {
  const Json entry = {{"host", "10.0.0.2"}, {"service_uri", "sip:mcx@b.example"}, {"media_host", "10.0.1.2"},
                      {"controlling", true}, {"spk", spk}};
  const auto peer = configured_peer("b", entry, false);
  assert(peer.route == "sip:10.0.0.2:5061;transport=tls" && peer.host == "10.0.0.2");
  assert(peer.media_host == "10.0.1.2" && peer.controlling && peer.spk && peer.spk_key);
  assert(peer.spk_key->random[0] == 0xbb && peer.spk_key->properties);
  const auto plain = configured_peer("b", {{"host", "10.0.0.2"}, {"service_uri", "sip:mcx@b.example"}}, true);
  assert(plain.route == "sip:10.0.0.2:5060;transport=tcp" && plain.media_host == "10.0.0.2" && !plain.controlling);
  assert(!plain.spk && !plain.spk_key);
}

//------------------------------------------------------------------------------
// TS 33.180 clause 5.5: an SPK-ID has purpose tag 3, and the SPK and its RAND 128 bits.
void Clause_5_5_ConfiguredSpk() {
  assert(refuses([] { (void)configured_spk({{"id", 0x10000001U}, {"key", ""}}, "b"); }, "an SPK-ID has purpose tag 3"));
  assert(refuses([] { (void)configured_spk({{"id", 0x30000001U}, {"key", "ab"}, {"rand", "ab"}}, "b"); },
                 "an SPK and its RAND are 128 bits"));
  assert(refuses(
      [] { (void)configured_spk({{"id", 0x30000001U}, {"key", std::string(32, 'a')}, {"rand", "ab"}}, "b"); },
      "an SPK and its RAND are 128 bits"));
  assert(configured_spk(spk, "b").properties->text == "SPK b");
}

//------------------------------------------------------------------------------
// Helpers: the peer of a source address (by its SIP host or its media host, and an unresolved host matching an empty
// address) and the loose Route.
void PeerLookups() {
  PeerMap peers;
  peers["one"].host = "127.0.0.2";
  peers["one"].media_host = "127.0.0.3";
  peers["one"].service_uri = "sip:mcx@one.example";
  peers["one"].route = "sip:127.0.0.2:5061;transport=tls";
  peers["two"].host = "";
  peers["two"].media_host = "";
  peers["two"].service_uri = "sip:mcx2@one.example";
  peers["two"].controlling = true;
  assert(peer_at(peers, "127.0.0.2") == "one");
  assert(peer_at(peers, "127.0.0.3") == "one");
  assert(peer_at(peers, "") == "two");
  assert(peer_media(peers.at("one"), "127.0.0.3") && !peer_media(peers.at("one"), "127.0.0.2"));
  const auto headers = peer_route(peers, "one", {{"Event", "presence"}});
  assert(headers.size() == 2 && headers.back().value == "<sip:127.0.0.2:5061;transport=tls;lr>");
}

//------------------------------------------------------------------------------
// A request the service published.
struct Published {
  std::string uri, body;
  std::vector<SipHeader> headers;
  SipResponseHandler handler;
};

//------------------------------------------------------------------------------
// The fake server: peers, users and group rules set by the test; what it publishes and what the hooks were asked is
// recorded.
class FakeHost final : public PeerRegistrationHost {
public:
  PeerMap peers;
  std::map<std::string, PeerUser> users; // by public user identity
  std::map<std::string, std::string> controllers;
  std::set<std::string> allowed_groups;
  std::vector<Published> published;
  std::vector<std::string> calls;
  bool publish_fails = false;
  std::optional<int> refusal;
  Affiliation received;
  std::uint64_t received_expires = 3600;
  std::uint64_t refresh_ms = 0;

  std::vector<BodyPart> seal_for_client(const std::string & /*sip*/, std::vector<BodyPart> parts) override {
    return parts;
  }

  std::vector<BodyPart> seal_for_peer(const std::string &peer, std::vector<BodyPart> parts) override {
    calls.push_back("seal " + peer);
    return parts;
  }

  [[nodiscard]] bool peer_known(const std::string &peer) const override { return peers.contains(peer); }

  [[nodiscard]] std::string peer_uri(const std::string &peer) const override { return peers.at(peer).service_uri; }

  [[nodiscard]] std::vector<SipHeader> route_to(const std::string &peer,
                                                std::vector<SipHeader> headers) const override {
    return peer_route(peers, peer, std::move(headers));
  }

  [[nodiscard]] std::string service_uri() const override { return "sip:mcx@home.example"; }

  Json common_document(const std::string & /*role*/, const std::string & /*path*/) override { return {}; }

  Json introspect(const std::string & /*token*/) override { return {}; }

  void send_message(const std::string & /*uri*/, const std::string & /*type*/, const std::string & /*body*/,
                    const std::vector<SipHeader> & /*headers*/, SipResponseHandler /*handler*/) override {}

  void publish(const std::string &uri, const std::string & /*type*/, const std::string &body,
               const std::vector<SipHeader> &headers, SipResponseHandler handler) override {
    if (publish_fails) throw std::runtime_error("no route");
    published.push_back({uri, body, headers, std::move(handler)});
  }

  void respond(const std::string & /*transaction*/, const SipResponse & /*response*/) override {}

  void schedule(std::function<void()> task) override { task(); }

  [[nodiscard]] const PeerMap &peer_table() const override { return peers; }

  std::string registration_group_controller(const std::string &group) override {
    const auto found = controllers.find(group);
    return found == controllers.end() ? std::string{} : found->second;
  }

  [[nodiscard]] std::uint64_t registration_refresh_ms() const override { return refresh_ms; }

  void each_registration_user(const std::function<void(const PeerUser &)> &visit) override {
    for (const auto &[sip, user] : users) visit(user);
  }

  std::optional<int> registration_refusal(const SipMessage & /*message*/, Affiliation &affiliation,
                                          std::uint64_t &expires_s) override {
    affiliation = received;
    expires_s = received_expires;
    return refusal;
  }

  std::optional<PeerUser> registration_user(const std::string &sip) override {
    const auto found = users.find(sip);
    return found == users.end() ? std::nullopt : std::optional(found->second);
  }

  std::optional<PeerUser> registration_user_by_id(const std::string &id) override {
    for (const auto &[sip, user] : users)
      if (user.id == id) return user;
    return std::nullopt;
  }

  bool registration_group_allowed(const std::string &group, const std::string & /*id*/,
                                  const std::string & /*peer*/) override {
    return allowed_groups.contains(group);
  }

  void withdraw_peer_user(const std::string &sip, const std::string &id) override {
    users.at(sip).expires = 0;
    calls.push_back("withdraw " + id);
  }

  void update_peer_user(const std::string &sip, const Affiliation &affiliation, const std::string &peer,
                        const std::set<std::string> & /*groups*/, std::uint64_t expires_s) override {
    auto &user = users[sip];
    user.id = affiliation.user_id;
    user.client = affiliation.client_id;
    user.sip = sip;
    user.peer = peer;
    user.expires = std::time(nullptr) + static_cast<std::int64_t>(expires_s);
  }

  void peer_user_changed(const std::string &sip, const std::optional<PeerUser> &previous,
                         std::set<std::string> groups) override {
    calls.push_back(std::string("changed ") + (previous ? "known" : "new"));
    users.at(sip).groups = std::move(groups);
  }
};

//------------------------------------------------------------------------------
// The event lines written to stdout while it lives.
class EventLog {
public:
  EventLog() : previous_(std::cout.rdbuf(lines_.rdbuf())) {}

  ~EventLog() { std::cout.rdbuf(previous_); }

  EventLog(const EventLog &) = delete;
  EventLog &operator=(const EventLog &) = delete;

  // The last event of the kind, or null; and how many there were.
  Json last(const std::string &kind) const {
    Json found;
    std::istringstream input(lines_.str());
    for (std::string line; std::getline(input, line);)
      if (const auto event = Json::parse(line, nullptr, false); event.is_object() && event.value("event", "") == kind)
        found = event;
    return found;
  }

private:
  std::ostringstream lines_;
  std::streambuf *previous_;
};

//------------------------------------------------------------------------------
// The service under test with its fake host: MCPTT on the core.
struct Fixture {
  Fixture() : profile(mcptt_service), service(host, profile) {
    host.peers["ctl"].service_uri = "sip:ctl@b.example";
    host.peers["ctl"].route = "sip:10.0.0.2:5061;transport=tls";
    host.peers["ctl"].controlling = true;
    host.peers["part"].service_uri = "sip:part@c.example";
    host.peers["part"].route = "sip:10.0.0.3:5061;transport=tls";
    host.controllers = {{"group-b", "ctl"}};
    alice = {"sip:alice@mcx.example",   "client-a", "sip:alice@home.example", "", std::time(nullptr) + 600,
             {"group-b", "group-here"}, true};
  }

  [[nodiscard]] std::string event(const std::string &suffix) const { return profile.event_prefix + suffix; }

  const ServiceProfile &profile;
  FakeHost host;
  PeerRegistration service;
  PeerUser alice;
};

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.2.6: the core publishes a served user to its controlling servers, with the affiliations to
// the groups that peer controls; a final answer is reported unless it answers a refresh that succeeded.
void Clause_9_2_2_2_6_Publish() {
  Fixture fixture;
  EventLog events;
  fixture.service.publish(fixture.alice);
  assert(fixture.host.published.size() == 1U);
  const auto &to_controller = fixture.host.published.front();
  assert(to_controller.uri == "sip:ctl@b.example");
  assert(std::string(get_header(to_controller.headers, "P-Asserted-Identity")) == "<sip:alice@home.example>");
  const auto affiliation = parse_affiliation(to_controller.body);
  assert(affiliation.groups.size() == 1 && affiliation.groups.front() == "group-b" && !affiliation.mcdata);
  SipResponse ok;
  ok.status_code = 200;
  to_controller.handler(ok);
  assert(events.last(fixture.event("peer_registration")).at("groups") == Json::array({"group-b"}));
  // A user whose affiliations are not current registers without groups; a withdrawal has Expires 0.
  fixture.alice.affiliations_current = false;
  fixture.service.publish(fixture.alice, true);
  assert(parse_affiliation(fixture.host.published.back().body).groups.empty());
  assert(std::string(get_header(fixture.host.published.back().headers, "Expires")) == "0");
  fixture.host.publish_fails = true;
  fixture.service.publish(fixture.alice);
  assert(events.last(fixture.event("peer_registration_failed")).at("reason") == "no route");
  fixture.alice.peer = "ctl";
  const auto before = fixture.host.published.size();
  fixture.host.publish_fails = false;
  fixture.service.publish(fixture.alice);
  assert(fixture.host.published.size() == before);
}

//------------------------------------------------------------------------------
// Helper: the registrations are repeated every registration_refresh_ms for the live users served here only.
void RegistrationRefresh() {
  Fixture fixture;
  fixture.host.users[fixture.alice.sip] = fixture.alice;
  auto remote = fixture.alice;
  remote.sip = "sip:bob@b.example";
  remote.peer = "ctl";
  fixture.host.users[remote.sip] = remote;
  fixture.service.refresh(1000000);
  assert(fixture.host.published.empty());
  fixture.host.refresh_ms = 60000;
  fixture.service.refresh(1000000);
  const auto first = fixture.host.published.size();
  assert(first == 1U);
  fixture.service.refresh(1030000);
  assert(fixture.host.published.size() == first);
  fixture.service.refresh(1060000);
  assert(fixture.host.published.size() == 2 * first);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.3.3: a peer's registration: refused by the server's checks, for a
// user served here, for an ID another identity holds, or for a group not allowed; a new or changed user takes its
// affiliations, an unchanged refresh only extends it; Expires 0 withdraws it.
void Clause_9_2_2_3_3_Receive() {
  Fixture fixture;
  EventLog events;
  SipMessage message;
  message.headers = {{"P-Asserted-Identity", "<sip:bob@b.example>"}};
  fixture.host.received = {"sip:bob@mcx.example", "client-b", "p1", {"group-1"}, {"affiliated"}};
  fixture.host.refusal = 400;
  assert(fixture.service.receive(message, "ctl").status_code == 400);
  fixture.host.refusal.reset();
  assert(fixture.service.receive(message, "ctl").status_code == 403); // group-1 not allowed
  fixture.host.allowed_groups = {"group-1"};
  auto response = fixture.service.receive(message, "ctl");
  assert(response.status_code == 200 && std::string(get_header(response.headers, "Expires")) == "3600");
  assert(fixture.host.calls == std::vector<std::string>({"changed new"}));
  assert(events.last(fixture.event("peer_user_registered")).at("groups") == Json::array({"group-1"}));
  fixture.host.calls.clear();
  assert(fixture.service.receive(message, "ctl").status_code == 200);
  assert(fixture.host.calls.empty());
  SipMessage served = message;
  served.headers = {{"P-Asserted-Identity", "<sip:carol@home.example>"}};
  fixture.host.users["sip:carol@home.example"] = {
      "sip:carol@mcx.example", "c", "sip:carol@home.example", "", std::time(nullptr) + 600, {}, true};
  assert(fixture.service.receive(served, "ctl").status_code == 403);
  fixture.host.received.user_id = "sip:carol@mcx.example";
  served.headers = {{"P-Asserted-Identity", "<sip:dave@b.example>"}};
  assert(fixture.service.receive(served, "ctl").status_code == 403);
  fixture.host.received.user_id = "sip:bob@mcx.example";
  fixture.host.received_expires = 0;
  response = fixture.service.receive(message, "other");
  assert(std::string(get_header(response.headers, "Expires")) == "0" && fixture.host.calls.empty());
  response = fixture.service.receive(message, "ctl");
  assert(fixture.host.calls.back() == "withdraw sip:bob@mcx.example");
  assert(events.last(fixture.event("peer_user_withdrawn")).at("server") == "ctl");
}
} // namespace

//------------------------------------------------------------------------------
int main() {
  Clause_7_5_2_4_ConfiguredPeer();
  Clause_5_5_ConfiguredSpk();
  PeerLookups();
  Clause_9_2_2_2_6_Publish();
  RegistrationRefresh();
  Clause_9_2_2_3_3_Receive();
  std::cout << "peers: all checks passed\n";
}
