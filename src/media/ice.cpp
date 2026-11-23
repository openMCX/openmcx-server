//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// ICE for a pre-established session (include/mcx/ice.hpp): OpenMCX's own full agent with host candidates, one check
// list per stream, the connectivity checks of RFC 8445 section 7 over STUN (src/media/stun.hpp) and regular
// nomination, driven from the caller's poll loop.
//
// Values chosen where RFC 8445 leaves them configurable (those of the pjnath agent this one replaced, so that the
// sessions behave as before): Ta 20 ms between checks (section 14.2: configurable, at least 5 ms); a check retransmitted after 100 ms, doubling,
// seven transmissions and a last wait of 1.6 s (RFC 5389 section 7.2.1 with Rc 7 and Rm 16, an RTO below the
// 500 ms of RFC 8445 section 14.3); keep-alives every 15 s (section 11); a controlled agent whose peer has not
// nominated 10 s after its checks ended completes on its best valid pairs (as pjnath did).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), RFC 8445, RFC 8839, RFC 5389, RFC 7983.

#include "mcx/ice.hpp"

#include "stun.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <deque>
#include <stdexcept>
#include <string>
#include <vector>

namespace mcx {
namespace {

using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

// RFC 5389 section 6: the magic cookie of every STUN message, in octets 4 to 7.
constexpr std::array<std::uint8_t, 4> kMagicCookie{0x21, 0x12, 0xa4, 0x42};
// RFC 5389 section 6: the 20-octet header; RFC 7983 section 7: STUN starts with 0 to 3.
constexpr std::size_t kStunHeader = 20;
constexpr std::uint8_t kStunFirstOctetMaximum = 3;

// RFC 8445 section 5.3: the username fragment carries at least 24 bits of randomness and the password at least 128;
// eight and twenty-four ice-char of six bits each (RFC 8839 section 5.4 bounds them at 4 and 22).
constexpr std::size_t kUfragLength = 8, kPwdLength = 24;

// RFC 8445 section 5.1.2.2: the recommended type preferences; section 5.1.2.1: the local preference of the only
// host candidate of a component.
constexpr std::uint32_t kHostPreference = 126, kPeerReflexivePreference = 110, kLocalPreference = 65535;

// The pacing and the transaction timers (the file comment).
constexpr auto kTa = 20ms;
constexpr auto kInitialRto = 100ms;
constexpr auto kLastWait = 1600ms;
constexpr int kTransmissions = 7;
constexpr auto kKeepAlive = 15s;
constexpr auto kNominationWait = 10s;
// RFC 8445 section 8.1.1: how long the controlling agent waits, once every component has a valid pair, for checks
// of higher-priority pairs before it nominates.
constexpr auto kNominationDelay = 1s;
// RFC 8445 section 6.1.2.5: the limit on the pairs of a check list.
constexpr std::size_t kMaximumPairs = 100;

//------------------------------------------------------------------------------
// RFC 8839 section 5.4: random ice-char (ALPHA / DIGIT / "+" / "/"), six bits each.
std::string random_ice_chars(std::size_t length) {
  static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::vector<unsigned char> bytes(length);
  if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1)
    throw std::runtime_error("ICE: no random credentials");
  std::string out;
  for (const auto byte : bytes) out += alphabet[byte & 0x3f];
  return out;
}

template <typename T> T random_value() {
  T value{};
  if (RAND_bytes(reinterpret_cast<unsigned char *>(&value), sizeof value) != 1)
    throw std::runtime_error("ICE: no random value");
  return value;
}

//------------------------------------------------------------------------------
// Helper: a numeric IPv4 address and port; nullopt when the host is not one.
std::optional<stun::Address> ipv4(const std::string &host, std::uint16_t port) {
  in_addr parsed{};
  if (inet_pton(AF_INET, host.c_str(), &parsed) != 1) return std::nullopt;
  return stun::Address{ntohl(parsed.s_addr), port};
}

std::string host_of(const stun::Address &address) {
  in_addr raw{htonl(address.ip)};
  std::array<char, INET_ADDRSTRLEN> text{};
  inet_ntop(AF_INET, &raw, text.data(), text.size());
  return text.data();
}

//------------------------------------------------------------------------------
// RFC 8445 section 5.1.1.3: the same foundation for candidates of one type, base address and transport (here a hash
// of them, eight hex digits: ice-char).
std::string foundation_of(std::string_view type, const stun::Address &base) {
  std::uint32_t hash = 2166136261u; // FNV-1a
  const auto mix = [&hash](std::uint8_t octet) { hash = (hash ^ octet) * 16777619u; };
  for (const char character : type) mix(static_cast<std::uint8_t>(character));
  for (int shift = 24; shift >= 0; shift -= 8) mix(static_cast<std::uint8_t>(base.ip >> shift));
  std::array<char, 9> text{};
  std::snprintf(text.data(), text.size(), "%08x", hash);
  return text.data();
}

// RFC 8445 section 5.1.2.1.
std::uint32_t candidate_priority(std::uint32_t type_preference, unsigned component) {
  return (type_preference << 24) | (kLocalPreference << 8) | (256 - component);
}

// RFC 8445 section 6.1.2.3: G the controlling agent's candidate priority, D the controlled agent's.
std::uint64_t pair_priority(std::uint32_t controlling, std::uint32_t controlled) {
  const std::uint64_t low = std::min(controlling, controlled), high = std::max(controlling, controlled);
  return (low << 32) + 2 * high + (controlling > controlled ? 1 : 0);
}

} // namespace

//------------------------------------------------------------------------------
// RFC 7983 section 7 and RFC 5389 section 6.
bool is_stun_packet(std::span<const std::uint8_t> datagram) noexcept {
  return datagram.size() >= kStunHeader && datagram[0] <= kStunFirstOctetMaximum &&
         std::equal(kMagicCookie.begin(), kMagicCookie.end(), datagram.begin() + 4);
}

//------------------------------------------------------------------------------
// The check lists of the streams, the STUN transactions in flight and the role.
struct IceAgent::Impl {
  struct Candidate {
    std::string foundation;
    unsigned component = 1;
    std::uint32_t priority = 0;
    stun::Address address;
    bool host = true; // local: host, else peer reflexive (RFC 8445 section 7.2.5.3.1)
  };

  // RFC 8445 section 6.1.2.6: the states of a candidate pair.
  enum class PairState { Frozen, Waiting, InProgress, Succeeded, Failed };

  struct Pair {
    std::size_t local = 0, remote = 0;
    std::string foundation;
    std::uint64_t priority = 0;
    PairState state = PairState::Frozen;
    bool nominate_on_success = false; // controlled: USE-CANDIDATE received while the check was pending (7.3.1.5)
  };

  // RFC 8445 section 7.2.5.3.2: a valid pair, from the pair whose check produced it.
  struct Valid {
    std::size_t local = 0, remote = 0, checked = 0;
    std::uint64_t priority = 0;
    bool nominated = false;
  };

  struct Triggered {
    std::size_t pair = 0;
    bool use_candidate = false;
  };

  struct Stream {
    IceStream id = IceStream::Audio;
    unsigned components = 0;
    std::vector<std::uint16_t> ports;
    std::vector<Candidate> local, remote;
    std::vector<Pair> pairs;
    std::vector<Valid> valid;
    std::deque<Triggered> triggered;
    bool complete = false, failed = false, nominating = false;
    std::optional<Clock::time_point> all_valid_since, checks_ended_at;
    Clock::time_point next_keep_alive{};
    unsigned peer_reflexive_count = 0;
  };

  struct Transaction {
    stun::TransactionId id{};
    std::size_t stream = 0, pair = 0;
    bool use_candidate = false, controlling = false;
    std::vector<std::uint8_t> packet;
    int sent = 0;
    Clock::duration rto = kInitialRto;
    Clock::time_point next{};
  };

  // A check received before the peer's description (RFC 8445 section 7.3: answered, its pair formed at start).
  struct Early {
    std::size_t stream = 0;
    unsigned component = 1;
    stun::Address source;
    std::uint32_t priority = 0;
    bool use_candidate = false;
  };

  IceAgent *agent;
  IceSender sender;
  IceLocalSockets sockets;
  IceDescription local;
  std::string remote_ufrag, remote_pwd;
  bool controlling;
  bool started = false;
  std::uint64_t tie_breaker = random_value<std::uint64_t>();
  std::vector<Stream> streams;
  std::vector<Transaction> transactions;
  std::vector<Early> early;
  Clock::time_point next_check{};
  std::size_t next_stream = 0;
  std::optional<IceState> outcome; // Completed or Failed, for the next tick

  Impl(IceAgent *owner, bool is_controlling, IceLocalSockets local_sockets, IceSender send)
      : agent(owner), sender(std::move(send)), sockets(std::move(local_sockets)), controlling(is_controlling) {}

  //------------------------------------------------------------------------------
  // RFC 8445 sections 5.1.1.1 and 5.1.2: a host candidate per component.
  void add_stream(IceStream id, std::vector<std::uint16_t> ports) {
    const auto address = *ipv4(sockets.address, 0);
    Stream &stream = streams.emplace_back();
    stream.id = id;
    stream.components = static_cast<unsigned>(ports.size());
    stream.ports = std::move(ports);
    auto &described = id == IceStream::Audio ? local.audio : local.control;
    for (unsigned component = 1; component <= stream.components; ++component) {
      Candidate candidate{foundation_of("host", address),
                          component,
                          candidate_priority(kHostPreference, component),
                          {address.ip, stream.ports[component - 1]},
                          true};
      described.push_back({candidate.foundation,
                           component,
                           "UDP",
                           candidate.priority,
                           sockets.address,
                           stream.ports[component - 1],
                           "host",
                           {},
                           0});
      stream.local.push_back(std::move(candidate));
    }
  }

  //------------------------------------------------------------------------------
  // RFC 8445 section 6.1.2.3: a pair's priority from this agent's role.
  std::uint64_t priority_of(const Stream &stream, std::size_t local_index, std::size_t remote_index) const {
    const auto mine = stream.local[local_index].priority, theirs = stream.remote[remote_index].priority;
    return controlling ? pair_priority(mine, theirs) : pair_priority(theirs, mine);
  }

  void recompute_priorities() {
    for (auto &stream : streams) {
      for (auto &pair : stream.pairs) pair.priority = priority_of(stream, pair.local, pair.remote);
      for (auto &valid : stream.valid) valid.priority = priority_of(stream, valid.local, valid.remote);
    }
  }

  std::size_t host_of_component(const Stream &stream, unsigned component) const {
    for (std::size_t index = 0; index < stream.local.size(); ++index)
      if (stream.local[index].host && stream.local[index].component == component) return index;
    throw std::logic_error("ICE: no host candidate");
  }

  std::optional<std::size_t> find_pair(const Stream &stream, std::size_t local_index, std::size_t remote_index) const {
    for (std::size_t index = 0; index < stream.pairs.size(); ++index)
      if (stream.pairs[index].local == local_index && stream.pairs[index].remote == remote_index) return index;
    return std::nullopt;
  }

  std::size_t add_pair(Stream &stream, std::size_t local_index, std::size_t remote_index, PairState state) {
    Pair pair{local_index,
              remote_index,
              stream.local[local_index].foundation + ":" + stream.remote[remote_index].foundation,
              priority_of(stream, local_index, remote_index),
              state,
              false};
    stream.pairs.push_back(std::move(pair));
    return stream.pairs.size() - 1;
  }

  //------------------------------------------------------------------------------
  // RFC 8445 sections 6.1.2.2 to 6.1.2.6: the peer's numeric IPv4 UDP candidates of each stream paired with the
  // host candidates of their component, duplicates pruned, at most 100 pairs; the first check list's pair of each
  // foundation with the lowest component (then the highest priority) Waiting, the others Frozen.
  void form_check_lists(const IceDescription &remote) {
    for (auto &stream : streams) stream.remote.clear(); // a description refused before leaves nothing behind
    for (auto &stream : streams) {
      const auto &candidates = stream.id == IceStream::Audio ? remote.audio : remote.control;
      for (const auto &candidate : candidates) {
        const auto address = ipv4(candidate.address, candidate.port);
        const bool known_type = candidate.type == "host" || candidate.type == "srflx" || candidate.type == "prflx" ||
                                candidate.type == "relay";
        std::string transport = candidate.transport;
        std::transform(transport.begin(), transport.end(), transport.begin(),
                       [](unsigned char character) { return static_cast<char>(std::toupper(character)); });
        if (!address || !known_type || transport != "UDP" || candidate.component == 0 ||
            candidate.component > stream.components)
          continue;
        const bool duplicate = std::any_of(stream.remote.begin(), stream.remote.end(), [&](const Candidate &seen) {
          return seen.component == candidate.component && seen.address == *address;
        });
        if (duplicate) continue;
        stream.remote.push_back({candidate.foundation, candidate.component, candidate.priority, *address, true});
      }
      for (unsigned component = 1; component <= stream.components; ++component)
        if (std::none_of(stream.remote.begin(), stream.remote.end(),
                         [component](const Candidate &candidate) { return candidate.component == component; }))
          throw std::invalid_argument("ICE: the peer gives no IPv4 UDP candidate for component " +
                                      std::to_string(component));
    }
    for (auto &stream : streams) {
      for (std::size_t remote_index = 0; remote_index < stream.remote.size(); ++remote_index) {
        if (stream.pairs.size() == kMaximumPairs) break;
        add_pair(stream, host_of_component(stream, stream.remote[remote_index].component), remote_index,
                 PairState::Frozen);
      }
    }
    auto &first = streams.front();
    std::vector<std::size_t> order(first.pairs.size());
    for (std::size_t index = 0; index < order.size(); ++index) order[index] = index;
    std::sort(order.begin(), order.end(), [&first](std::size_t left, std::size_t right) {
      const auto left_component = first.local[first.pairs[left].local].component;
      const auto right_component = first.local[first.pairs[right].local].component;
      return left_component != right_component ? left_component < right_component
                                               : first.pairs[left].priority > first.pairs[right].priority;
    });
    std::vector<std::string> seen;
    for (const auto index : order)
      if (std::find(seen.begin(), seen.end(), first.pairs[index].foundation) == seen.end()) {
        seen.push_back(first.pairs[index].foundation);
        first.pairs[index].state = PairState::Waiting;
      }
  }

  //------------------------------------------------------------------------------
  // RFC 8445 section 7.2.4: a Binding request for a pair, with the peer's username fragment first, the priority a
  // peer-reflexive candidate would have (section 7.1.1), the role and its tie-breaker, USE-CANDIDATE when
  // nominating; signed with the peer's password.
  void send_check(std::size_t stream_index, std::size_t pair_index, bool use_candidate) {
    auto &stream = streams[stream_index];
    auto &pair = stream.pairs[pair_index];
    const auto &local_candidate = stream.local[pair.local];
    Transaction transaction;
    transaction.id = random_value<stun::TransactionId>();
    transaction.stream = stream_index;
    transaction.pair = pair_index;
    transaction.use_candidate = use_candidate && controlling;
    transaction.controlling = controlling;
    stun::Builder builder(stun::Class::Request, transaction.id);
    builder.username(remote_ufrag + ":" + local.ufrag)
        .priority(candidate_priority(kPeerReflexivePreference, local_candidate.component));
    if (controlling)
      builder.ice_controlling(tie_breaker);
    else
      builder.ice_controlled(tie_breaker);
    if (transaction.use_candidate) builder.use_candidate();
    transaction.packet = builder.finish(remote_pwd);
    pair.state = PairState::InProgress;
    transmit(stream, local_candidate.component, transaction.packet, stream.remote[pair.remote].address);
    transaction.sent = 1;
    transaction.next = Clock::now() + transaction.rto;
    transactions.push_back(std::move(transaction));
  }

  void transmit(const Stream &stream, unsigned component, std::span<const std::uint8_t> packet,
                const stun::Address &destination) {
    try {
      sender(stream.id, component, packet, host_of(destination), destination.port);
    } catch (...) {
      // a lost transmission: the retransmissions (or the peer's checks) recover
    }
  }

  //------------------------------------------------------------------------------
  // RFC 8445 section 6.1.4.2: the next check of a check list: a triggered check, else the highest-priority Waiting
  // pair, else a Frozen pair whose foundation has no Waiting or In-Progress pair in any check list. Returns whether a
  // check was sent.
  bool check_once(std::size_t stream_index) {
    auto &stream = streams[stream_index];
    if (stream.complete || stream.failed) return false;
    while (!stream.triggered.empty()) {
      const auto next = stream.triggered.front();
      stream.triggered.pop_front();
      const auto state = stream.pairs[next.pair].state;
      if (state == PairState::InProgress || (state == PairState::Succeeded && !next.use_candidate)) continue;
      send_check(stream_index, next.pair, next.use_candidate);
      return true;
    }
    std::optional<std::size_t> best;
    for (std::size_t index = 0; index < stream.pairs.size(); ++index)
      if (stream.pairs[index].state == PairState::Waiting &&
          (!best || stream.pairs[index].priority > stream.pairs[*best].priority))
        best = index;
    if (!best) {
      for (std::size_t index = 0; index < stream.pairs.size(); ++index) {
        const auto &pair = stream.pairs[index];
        if (pair.state != PairState::Frozen || foundation_active(pair.foundation)) continue;
        if (!best || pair.priority > stream.pairs[*best].priority) best = index;
      }
    }
    if (!best) return false;
    send_check(stream_index, *best, false);
    return true;
  }

  bool foundation_active(const std::string &foundation) const {
    for (const auto &stream : streams)
      for (const auto &pair : stream.pairs)
        if (pair.foundation == foundation && (pair.state == PairState::Waiting || pair.state == PairState::InProgress))
          return true;
    return false;
  }

  // RFC 8445 section 7.2.5.3.3: a check that succeeded unfreezes the pairs of its foundation.
  void unfreeze(const std::string &foundation) {
    for (auto &stream : streams)
      for (auto &pair : stream.pairs)
        if (pair.state == PairState::Frozen && pair.foundation == foundation) pair.state = PairState::Waiting;
  }

  void enqueue(Stream &stream, std::size_t pair_index, bool use_candidate = false) {
    for (const auto &queued : stream.triggered)
      if (queued.pair == pair_index && queued.use_candidate == use_candidate) return;
    stream.triggered.push_back({pair_index, use_candidate});
  }

  //------------------------------------------------------------------------------
  // RFC 8445 section 7.2.5: the response to one of this agent's checks.
  void on_response(const stun::Message &message, std::span<const std::uint8_t> packet, IceStream stream_id,
                   unsigned component, const stun::Address &source) {
    const auto found = std::find_if(transactions.begin(), transactions.end(),
                                    [&message](const Transaction &sent) { return sent.id == message.transaction; });
    if (found == transactions.end()) return;
    // Success responses (and a 487) carry the peer's MESSAGE-INTEGRITY (section 7.2.5.1); others are taken as sent.
    if ((message.type == stun::Class::Success || message.has_integrity) &&
        !stun::check_integrity(packet, message, remote_pwd))
      return;
    const auto transaction = *found;
    transactions.erase(found);
    auto &stream = streams[transaction.stream];
    auto &pair = stream.pairs[transaction.pair];
    // Section 7.2.5.2.1: the response must come from where the request went, on the socket it left.
    if (stream.id != stream_id || stream.local[pair.local].component != component ||
        !(stream.remote[pair.remote].address == source)) {
      pair.state = PairState::Failed;
      update(stream);
      return;
    }
    if (message.type == stun::Class::Error) {
      // Section 7.2.5.1: a 487 (Role Conflict) switches the role, unless it already changed, and retries.
      if (message.error_code == 487) {
        if (transaction.controlling == controlling) switch_role();
        pair.state = PairState::Waiting;
        enqueue(stream, transaction.pair, transaction.use_candidate && controlling);
      } else {
        pair.state = PairState::Failed;
        if (transaction.use_candidate) nomination_failed(stream, transaction.pair);
      }
      update(stream);
      return;
    }
    if (!message.xor_mapped) {
      pair.state = PairState::Failed;
      update(stream);
      return;
    }
    // Section 7.2.5.3.1: a mapped address that is no local candidate is a peer-reflexive local candidate.
    std::optional<std::size_t> local_index;
    for (std::size_t index = 0; index < stream.local.size(); ++index)
      if (stream.local[index].component == component && stream.local[index].address == *message.xor_mapped)
        local_index = index;
    if (!local_index) {
      stream.local.push_back({foundation_of("prflx", *message.xor_mapped), component,
                              candidate_priority(kPeerReflexivePreference, component), *message.xor_mapped, false});
      local_index = stream.local.size() - 1;
    }
    pair.state = PairState::Succeeded;
    // Section 7.2.5.3.2: the valid pair.
    auto valid = std::find_if(stream.valid.begin(), stream.valid.end(), [&](const Valid &known) {
      return known.local == *local_index && known.remote == pair.remote;
    });
    if (valid == stream.valid.end()) {
      stream.valid.push_back(
          {*local_index, pair.remote, transaction.pair, priority_of(stream, *local_index, pair.remote), false});
      valid = stream.valid.end() - 1;
    }
    unfreeze(pair.foundation);
    // Section 8.1.1 (the controlling agent's check with USE-CANDIDATE) and 7.3.1.5 (the controlled agent's check of
    // a pair the peer nominated).
    if (transaction.use_candidate || (!controlling && pair.nominate_on_success)) valid->nominated = true;
    update(stream);
  }

  //------------------------------------------------------------------------------
  // RFC 8445 section 7.3.1.1: the role conflict of a received check. Returns true when it is answered 487.
  bool role_conflict(const stun::Message &message) {
    if (controlling && message.ice_controlling) {
      if (tie_breaker >= *message.ice_controlling) return true;
      switch_role();
    } else if (!controlling && message.ice_controlled) {
      if (tie_breaker >= *message.ice_controlled) {
        switch_role();
      } else {
        return true;
      }
    }
    return false;
  }

  void switch_role() {
    controlling = !controlling;
    recompute_priorities();
  }

  //------------------------------------------------------------------------------
  // RFC 8445 section 7.3 with RFC 5389 sections 7.3.1 and 10.1.2: a Binding request of the peer: authenticated with
  // this agent's credentials, its role conflict resolved, answered from the socket it reached; then the triggered
  // check of its pair (section 7.3.1.4) and the nomination it carries (section 7.3.1.5).
  void on_request(const stun::Message &message, std::span<const std::uint8_t> packet, std::size_t stream_index,
                  unsigned component, const stun::Address &source) {
    const auto &stream = streams[stream_index];
    const auto reply = [&](stun::Builder &builder, bool signed_reply) {
      const auto bytes = builder.finish(signed_reply ? std::optional<std::string_view>(local.pwd) : std::nullopt);
      transmit(stream, component, bytes, source);
    };
    if (!message.username || !message.has_integrity || !message.priority) {
      stun::Builder builder(stun::Class::Error, message.transaction);
      builder.error(400, "Bad Request");
      reply(builder, false);
      return;
    }
    const auto &username = *message.username;
    if (!username.starts_with(local.ufrag + ":") || !stun::check_integrity(packet, message, local.pwd)) {
      stun::Builder builder(stun::Class::Error, message.transaction);
      builder.error(401, "Unauthorized");
      reply(builder, false);
      return;
    }
    if (!message.unknown_required.empty()) {
      stun::Builder builder(stun::Class::Error, message.transaction);
      builder.error(420, "Unknown Attribute").unknown_attributes(message.unknown_required);
      reply(builder, true);
      return;
    }
    if (role_conflict(message)) {
      stun::Builder builder(stun::Class::Error, message.transaction);
      builder.error(487, "Role Conflict");
      reply(builder, true);
      return;
    }
    stun::Builder builder(stun::Class::Success, message.transaction);
    builder.xor_mapped(source);
    reply(builder, true);
    if (!started) {
      early.push_back({stream_index, component, source, *message.priority, message.use_candidate});
      return;
    }
    triggered_by_request(stream_index, component, source, *message.priority, message.use_candidate);
  }

  void triggered_by_request(std::size_t stream_index, unsigned component, const stun::Address &source,
                            std::uint32_t priority, bool use_candidate) {
    auto &stream = streams[stream_index];
    if (stream.complete || stream.failed) return;
    // Section 7.3.1.3: a source that is no remote candidate is a peer-reflexive remote candidate.
    std::optional<std::size_t> remote_index;
    for (std::size_t index = 0; index < stream.remote.size(); ++index)
      if (stream.remote[index].component == component && stream.remote[index].address == source) remote_index = index;
    if (!remote_index) {
      stream.remote.push_back(
          {"prflx" + std::to_string(++stream.peer_reflexive_count), component, priority, source, false});
      remote_index = stream.remote.size() - 1;
    }
    const auto local_index = host_of_component(stream, component);
    auto pair_index = find_pair(stream, local_index, *remote_index);
    if (!pair_index) {
      if (stream.pairs.size() == kMaximumPairs) return;
      pair_index = add_pair(stream, local_index, *remote_index, PairState::Waiting);
      enqueue(stream, *pair_index);
    } else {
      auto &pair = stream.pairs[*pair_index];
      if (pair.state == PairState::Frozen || pair.state == PairState::Waiting || pair.state == PairState::Failed) {
        pair.state = PairState::Waiting;
        enqueue(stream, *pair_index);
      }
    }
    if (use_candidate && !controlling) {
      auto &pair = stream.pairs[*pair_index];
      bool marked = false;
      for (auto &valid : stream.valid)
        if (valid.checked == *pair_index) valid.nominated = marked = true;
      if (!marked) pair.nominate_on_success = true;
    }
    update(stream);
  }

  //------------------------------------------------------------------------------
  // RFC 8445 sections 8.1.1 to 8.1.3: nomination by the controlling agent, the completion and the failure of a
  // stream.
  std::optional<std::size_t> best_valid(const Stream &stream, unsigned component, bool nominated) const {
    std::optional<std::size_t> best;
    for (std::size_t index = 0; index < stream.valid.size(); ++index) {
      const auto &valid = stream.valid[index];
      if (stream.local[valid.local].component != component || (nominated && !valid.nominated)) continue;
      if (!best || valid.priority > stream.valid[*best].priority) best = index;
    }
    return best;
  }

  static bool unchecked(PairState state) {
    return state == PairState::Frozen || state == PairState::Waiting || state == PairState::InProgress;
  }

  bool pending(const Stream &stream) const {
    if (!stream.triggered.empty()) return true;
    return std::any_of(stream.pairs.begin(), stream.pairs.end(),
                       [](const Pair &pair) { return unchecked(pair.state); });
  }

  bool in_flight(std::size_t stream_index) const {
    return std::any_of(transactions.begin(), transactions.end(),
                       [stream_index](const Transaction &sent) { return sent.stream == stream_index; });
  }

  void update(Stream &stream) {
    if (stream.complete || stream.failed) return;
    const auto stream_index = static_cast<std::size_t>(&stream - streams.data());
    const auto now = Clock::now();
    bool all_nominated = true, all_valid = true;
    for (unsigned component = 1; component <= stream.components; ++component) {
      all_nominated = all_nominated && best_valid(stream, component, true).has_value();
      all_valid = all_valid && best_valid(stream, component, false).has_value();
    }
    if (all_nominated) {
      complete(stream);
      return;
    }
    const bool checks_pending = pending(stream) || in_flight(stream_index);
    if (checks_pending)
      stream.checks_ended_at.reset();
    else if (!stream.checks_ended_at)
      stream.checks_ended_at = now;
    if (!all_valid) {
      stream.all_valid_since.reset();
      if (!checks_pending) fail(stream);
      return;
    }
    if (!stream.all_valid_since) stream.all_valid_since = now;
    if (controlling && !stream.nominating) {
      // Section 8.1.1: nominate once no pair above the best valid one of a component is still to be checked.
      bool higher_pending = false;
      for (unsigned component = 1; component <= stream.components; ++component) {
        const auto best = stream.valid[*best_valid(stream, component, false)].priority;
        for (const auto &pair : stream.pairs)
          if (stream.local[pair.local].component == component && pair.priority > best && unchecked(pair.state))
            higher_pending = true;
      }
      if (!higher_pending || now - *stream.all_valid_since >= kNominationDelay) {
        stream.nominating = true;
        for (unsigned component = 1; component <= stream.components; ++component)
          enqueue(stream, stream.valid[*best_valid(stream, component, false)].checked, true);
      }
    } else if (controlling && stream.nominating && !checks_pending) {
      // A nomination check failed: nominate again from what is valid.
      stream.nominating = false;
    } else if (!controlling && stream.checks_ended_at && now - *stream.checks_ended_at >= kNominationWait) {
      // The peer never nominated: the best valid pairs (the file comment).
      for (unsigned component = 1; component <= stream.components; ++component)
        stream.valid[*best_valid(stream, component, false)].nominated = true;
      complete(stream);
    }
  }

  // RFC 8445 section 8.1.1: a nomination check that failed (no response, or an error other than 487) takes its valid
  // pairs out; the next update nominates from the others, or fails the stream when none is left.
  void nomination_failed(Stream &stream, std::size_t pair_index) {
    std::erase_if(stream.valid, [pair_index](const Valid &valid) { return valid.checked == pair_index; });
  }

  void complete(Stream &stream) {
    stream.complete = true;
    stream.triggered.clear();
    for (auto &pair : stream.pairs)
      if (pair.state == PairState::Frozen || pair.state == PairState::Waiting) pair.state = PairState::Failed;
    const auto index = static_cast<std::size_t>(&stream - streams.data());
    std::erase_if(transactions, [index](const Transaction &sent) { return sent.stream == index; });
    stream.next_keep_alive = Clock::now() + kKeepAlive;
    update_state();
  }

  void fail(Stream &stream) {
    stream.failed = true;
    update_state();
  }

  // RFC 8445 section 8.1.3: the agent completes when every stream did, and fails when one failed. The outcome is
  // taken into state() by tick only (include/mcx/ice.hpp: callers look for the change around tick).
  void update_state() {
    bool all = true;
    for (const auto &stream : streams) {
      if (stream.failed) {
        outcome = IceState::Failed;
        return;
      }
      all = all && stream.complete;
    }
    if (all) outcome = IceState::Completed;
  }

  //------------------------------------------------------------------------------
  // RFC 5389 section 7.2.1: the retransmissions; a transaction without a response after the last fails its pair.
  void retransmit(Clock::time_point now) {
    for (std::size_t index = 0; index < transactions.size();) {
      auto &transaction = transactions[index];
      if (now < transaction.next) {
        ++index;
        continue;
      }
      auto &stream = streams[transaction.stream];
      if (transaction.sent >= kTransmissions) {
        stream.pairs[transaction.pair].state = PairState::Failed;
        if (transaction.use_candidate) nomination_failed(stream, transaction.pair);
        transactions.erase(transactions.begin() + static_cast<std::ptrdiff_t>(index));
        continue;
      }
      const auto &pair = stream.pairs[transaction.pair];
      transmit(stream, stream.local[pair.local].component, transaction.packet, stream.remote[pair.remote].address);
      ++transaction.sent;
      transaction.rto *= 2;
      transaction.next = now + (transaction.sent == kTransmissions ? Clock::duration(kLastWait) : transaction.rto);
      ++index;
    }
  }

  // RFC 8445 section 11 (RFC 6263): a Binding indication on each nominated pair of a completed stream.
  void keep_alive(Clock::time_point now) {
    for (auto &stream : streams) {
      if (!stream.complete || now < stream.next_keep_alive) continue;
      stream.next_keep_alive = now + kKeepAlive;
      for (unsigned component = 1; component <= stream.components; ++component) {
        const auto best = best_valid(stream, component, true);
        if (!best) continue;
        stun::Builder builder(stun::Class::Indication, random_value<stun::TransactionId>());
        transmit(stream, component, builder.finish(std::nullopt), stream.remote[stream.valid[*best].remote].address);
      }
    }
  }

  void tick() {
    const auto now = Clock::now();
    retransmit(now);
    if (started && now >= next_check) {
      // Section 6.1.4.2: one check every Ta, the check lists in turn.
      for (std::size_t tried = 0; tried < streams.size(); ++tried) {
        const auto index = (next_stream + tried) % streams.size();
        if (check_once(index)) {
          next_stream = index + 1;
          break;
        }
      }
      next_check = now + kTa;
    }
    if (started)
      for (auto &stream : streams) update(stream);
    keep_alive(now);
    if (outcome) agent->state_ = *outcome;
  }

  Stream *find(IceStream id) {
    for (auto &stream : streams)
      if (stream.id == id) return &stream;
    return nullptr;
  }

  const Stream *find(IceStream id) const {
    for (const auto &stream : streams)
      if (stream.id == id) return &stream;
    return nullptr;
  }
};

//------------------------------------------------------------------------------
// RFC 8445 sections 5.1.1.1 and 5.3: the credentials and the host candidates of the speech and control sockets.
IceAgent::IceAgent(bool controlling, IceLocalSockets sockets, IceSender sender)
    : impl_(std::make_unique<Impl>(this, controlling, std::move(sockets), std::move(sender))) {
  auto &impl = *impl_;
  if (!ipv4(impl.sockets.address, 0) || !impl.sockets.rtp_port || !impl.sockets.rtcp_port)
    throw std::invalid_argument("ICE: an IPv4 address and the RTP and RTCP ports are required");
  impl.local.ufrag = random_ice_chars(kUfragLength);
  impl.local.pwd = random_ice_chars(kPwdLength);
  impl.add_stream(IceStream::Audio, {impl.sockets.rtp_port, impl.sockets.rtcp_port});
  if (impl.sockets.control_port) impl.add_stream(IceStream::Control, {impl.sockets.control_port});
}

IceAgent::~IceAgent() = default;

const IceDescription &IceAgent::local_description() const noexcept { return impl_->local; }

//------------------------------------------------------------------------------
// RFC 8445 sections 6.1.2 and 6.1.4: the check lists of the streams, the checks received early, then the first check.
void IceAgent::start(const IceDescription &remote) {
  auto &impl = *impl_;
  if (state_ != IceState::Gathered) throw std::logic_error("ICE: the checks have already started");
  if (remote.lite && !impl.controlling)
    throw std::invalid_argument("ICE: a lite peer needs this agent controlling (RFC 8445 section 6.1.1)");
  impl.form_check_lists(remote);
  impl.remote_ufrag = remote.ufrag;
  impl.remote_pwd = remote.pwd;
  impl.started = true;
  state_ = IceState::Checking;
  for (const auto &check : impl.early)
    impl.triggered_by_request(check.stream, check.component, check.source, check.priority, check.use_candidate);
  impl.early.clear();
  impl.next_check = Clock::now();
  impl.tick();
}

//------------------------------------------------------------------------------
// RFC 8445 section 7: a STUN packet received on a stream's component socket from the address.
bool IceAgent::receive(IceStream stream, unsigned component, std::span<const std::uint8_t> packet,
                       const std::string &host, std::uint16_t port) {
  auto &impl = *impl_;
  const auto *found = impl.find(stream);
  if (found == nullptr || component == 0 || component > found->components || !is_stun_packet(packet)) return false;
  const auto source = ipv4(host, port);
  const auto message = stun::decode(packet);
  if (!source || !message) return false;
  const auto stream_index = static_cast<std::size_t>(found - impl.streams.data());
  switch (message->type) {
  case stun::Class::Request: impl.on_request(*message, packet, stream_index, component, *source); break;
  case stun::Class::Success:
  case stun::Class::Error: impl.on_response(*message, packet, stream, component, *source); break;
  case stun::Class::Indication: break; // RFC 8445 section 11: a keep-alive
  }
  return true;
}

//------------------------------------------------------------------------------
// The paced checks, the retransmissions, nomination and the keep-alives due by now.
void IceAgent::tick() { impl_->tick(); }

//------------------------------------------------------------------------------
// RFC 8445 section 8.1.1: the nominated pair's remote address.
std::optional<std::pair<std::string, std::uint16_t>> IceAgent::selected(IceStream stream, unsigned component) const {
  const auto *found = impl_->find(stream);
  if (found == nullptr || !found->complete || component == 0 || component > found->components) return std::nullopt;
  const auto best = impl_->best_valid(*found, component, true);
  if (!best) return std::nullopt;
  const auto &address = found->remote[found->valid[*best].remote].address;
  return std::pair{host_of(address), address.port};
}

//------------------------------------------------------------------------------
// RFC 8445 section 8.1.2: a nominated local candidate other than the component's host candidate (the default).
bool IceAgent::needs_updated_offer() const {
  for (const auto &stream : impl_->streams) {
    if (!stream.complete) continue;
    for (unsigned component = 1; component <= stream.components; ++component) {
      const auto best = impl_->best_valid(stream, component, true);
      if (best && !stream.local[stream.valid[*best].local].host) return true;
    }
  }
  return false;
}

} // namespace mcx
