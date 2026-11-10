//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// ICE for a pre-established session (include/mcx/ice.hpp): a pjnath ICE session per media section on the caller's
// sockets, driven from the caller's poll loop.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), RFC 8445, RFC 8839, RFC 5389, RFC 7983.

#include "mcx/ice.hpp"

#include <openssl/rand.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <pjnath.h>

#include <algorithm>
#include <array>
#include <stdexcept>
#include <string>
#include <vector>

namespace mcx {
namespace {

// RFC 5389 section 6: the magic cookie of every STUN message, in octets 4 to 7.
constexpr std::array<std::uint8_t, 4> kMagicCookie{0x21, 0x12, 0xa4, 0x42};
// RFC 5389 section 6: the 20-octet header; RFC 7983 section 7: STUN starts with 0 to 3.
constexpr std::size_t kStunHeader = 20;
constexpr std::uint8_t kStunFirstOctetMaximum = 3;

// RFC 8445 section 5.3: the username fragment carries at least 24 bits of randomness and the password at least 128;
// eight and twenty-four ice-char of six bits each (RFC 8839 section 5.4 bounds them at 4 and 22).
constexpr std::size_t kUfragLength = 8, kPwdLength = 24;

// RFC 8445 section 5.1.2.1: the local preference of the only host candidate of a component.
constexpr pj_uint16_t kHostLocalPreference = 65535;

// The components of each stream (include/mcx/ice.hpp).
constexpr unsigned kAudioComponents = 2, kControlComponents = 1;

// pjnath's timer heap holds the check pacing, the STUN retransmissions and the keep-alives of the sessions.
constexpr pj_size_t kTimerCount = 64;
constexpr pj_size_t kPoolSize = 4000;
// pjlib's log level 3: errors, warnings and information.
constexpr int kLogLevel = 3;

//------------------------------------------------------------------------------
// Helper: throws when pjlib reports a failure.
void require(pj_status_t status, const char *what) {
  if (status != PJ_SUCCESS) {
    std::array<char, PJ_ERR_MSG_SIZE> text{};
    pj_strerror(status, text.data(), text.size());
    throw std::runtime_error(std::string("ICE: ") + what + ": " + text.data());
  }
}

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

//------------------------------------------------------------------------------
// Helper: a pjlib string over a std::string (which must outlive it).
pj_str_t pj_text(const std::string &text) {
  return pj_str(const_cast<char *>(text.c_str())); // NOLINT(cppcoreguidelines-pro-type-const-cast): pj_str is read
}

//------------------------------------------------------------------------------
// Helper: an IPv4 socket address.
pj_sockaddr ipv4(const std::string &host, std::uint16_t port) {
  pj_sockaddr address{};
  auto text = pj_text(host);
  require(pj_sockaddr_init(pj_AF_INET(), &address, &text, port), "IPv4 address");
  return address;
}

//------------------------------------------------------------------------------
// Helper: the numeric host and the port of a socket address.
std::pair<std::string, std::uint16_t> host_port(const pj_sockaddr_t *address) {
  std::array<char, PJ_INET6_ADDRSTRLEN> text{};
  pj_sockaddr_print(address, text.data(), static_cast<int>(text.size()), 0);
  return {text.data(), pj_sockaddr_get_port(address)};
}

//------------------------------------------------------------------------------
// RFC 8839 section 5.1: the candidate type of a candidate line.
std::optional<pj_ice_cand_type> candidate_type(const std::string &type) {
  if (type == "host") return PJ_ICE_CAND_TYPE_HOST;
  if (type == "srflx") return PJ_ICE_CAND_TYPE_SRFLX;
  if (type == "prflx") return PJ_ICE_CAND_TYPE_PRFLX;
  if (type == "relay") return PJ_ICE_CAND_TYPE_RELAYED;
  return std::nullopt;
}

//------------------------------------------------------------------------------
// Helper: whether a connection-address is a numeric IPv4 address (the agent pairs only those).
bool numeric_ipv4(const std::string &address) {
  pj_in_addr parsed{};
  auto text = pj_text(address);
  return pj_inet_aton(&text, &parsed) != 0;
}

} // namespace

//------------------------------------------------------------------------------
// RFC 7983 section 7 and RFC 5389 section 6.
bool is_stun_packet(std::span<const std::uint8_t> datagram) noexcept {
  return datagram.size() >= kStunHeader && datagram[0] <= kStunFirstOctetMaximum &&
         std::equal(kMagicCookie.begin(), kMagicCookie.end(), datagram.begin() + 4);
}

//------------------------------------------------------------------------------
// The pjlib runtime and the ICE sessions of an agent.
struct IceAgent::Impl {
  struct Stream {
    Impl *owner = nullptr;
    IceStream id = IceStream::Audio;
    pj_ice_sess *session = nullptr;
    unsigned components = 0;
    std::vector<std::uint16_t> ports; // the local port of each component
    bool complete = false, failed = false;
  };

  IceAgent *agent;
  IceSender sender;
  IceLocalSockets sockets;
  IceDescription local;
  bool controlling;
  bool pj_initialized = false, cache_initialized = false;
  pj_caching_pool cache{};
  pj_pool_t *pool = nullptr;
  pj_timer_heap_t *timer_heap = nullptr;
  pj_stun_config stun_config{};
  std::vector<Stream> streams;
  // Strings pjnath points into (remote credentials and foundations), kept for the sessions' lifetime.
  std::vector<std::string> remote_strings;
  inline static thread_local pj_thread_desc thread_description{};

  Impl(IceAgent *owner, bool is_controlling, IceLocalSockets local_sockets, IceSender send)
      : agent(owner), sender(std::move(send)), sockets(std::move(local_sockets)), controlling(is_controlling) {}

  ~Impl() { release(); }

  //------------------------------------------------------------------------------
  // Helper: pjlib, pjlib-util and pjnath, the pool and the timer heap (pj_init counts its callers).
  void start_runtime() {
    require(pj_init(), "initialise pjlib");
    pj_initialized = true;
    if (!pj_thread_is_registered()) {
      pj_thread_t *thread = nullptr;
      require(pj_thread_register("mcx-ice", thread_description, &thread), "register thread");
    }
    // As the SIP engine does (src/sip/lifecycle.cpp): warnings and errors only, not every STUN message.
    if (pj_log_get_level() > kLogLevel) pj_log_set_level(kLogLevel);
    require(pjlib_util_init(), "initialise pjlib-util");
    (void)pjnath_init(); // registers pjnath's error texts; a second agent finds them registered
    pj_caching_pool_init(&cache, &pj_pool_factory_default_policy, 0);
    cache_initialized = true;
    pool = pj_pool_create(&cache.factory, "mcx-ice", kPoolSize, kPoolSize, nullptr);
    if (pool == nullptr) throw std::runtime_error("ICE: no memory pool");
    require(pj_timer_heap_create(pool, kTimerCount, &timer_heap), "create timer heap");
    pj_stun_config_init(&stun_config, &cache.factory, 0, nullptr, timer_heap);
  }

  //------------------------------------------------------------------------------
  // RFC 8445 sections 5.1.1.1 and 5.1.2: one ICE session per stream with a host candidate per component; the
  // candidates' foundation and priority as pjnath computed them.
  void add_stream(IceStream id, std::vector<std::uint16_t> ports) {
    Stream &stream = streams.emplace_back();
    stream.owner = this;
    stream.id = id;
    stream.components = static_cast<unsigned>(ports.size());
    stream.ports = std::move(ports);
  }

  void create_sessions() {
    static const pj_ice_sess_cb callbacks{nullptr, &Impl::on_complete, &Impl::on_transmit, &Impl::on_data};
    auto ufrag = pj_text(local.ufrag);
    auto pwd = pj_text(local.pwd);
    for (auto &stream : streams) {
      const auto name = stream.id == IceStream::Audio ? "ice-audio" : "ice-control";
      require(pj_ice_sess_create(&stun_config, name,
                                 controlling ? PJ_ICE_SESS_ROLE_CONTROLLING : PJ_ICE_SESS_ROLE_CONTROLLED,
                                 stream.components, &callbacks, &ufrag, &pwd, nullptr, &stream.session),
              "create session");
      stream.session->user_data = &stream;
      pj_ice_sess_options options{};
      require(pj_ice_sess_get_options(stream.session, &options), "read options");
      options.aggressive = PJ_FALSE; // RFC 8445 section 8.1.1: regular nomination only
      require(pj_ice_sess_set_options(stream.session, &options), "set options");
      auto &described = stream.id == IceStream::Audio ? local.audio : local.control;
      for (unsigned component = 1; component <= stream.components; ++component)
        described.push_back(add_host_candidate(stream, component));
    }
  }

  IceCandidate add_host_candidate(Stream &stream, unsigned component) {
    const auto address = ipv4(sockets.address, stream.ports[component - 1]);
    pj_str_t foundation{};
    pj_ice_calc_foundation(pool, &foundation, PJ_ICE_CAND_TYPE_HOST, &address);
    unsigned id = 0;
    require(pj_ice_sess_add_cand(stream.session, component, 0, PJ_ICE_CAND_TYPE_HOST, kHostLocalPreference,
                                 &foundation, &address, &address, nullptr, pj_sockaddr_get_len(&address), &id),
            "add host candidate");
    const auto &added = stream.session->lcand[id];
    return {std::string(added.foundation.ptr, static_cast<std::size_t>(added.foundation.slen)), component, "UDP",
            added.prio, sockets.address, stream.ports[component - 1], "host", {}, 0};
  }

  //------------------------------------------------------------------------------
  // RFC 8445 section 6.1.2.2: the peer's candidates of a stream as pjnath takes them; only numeric IPv4 UDP ones of
  // a known type are paired.
  std::vector<pj_ice_sess_cand> remote_candidates(const std::vector<IceCandidate> &candidates, unsigned components) {
    std::vector<pj_ice_sess_cand> out;
    for (const auto &candidate : candidates) {
      const auto type = candidate_type(candidate.type);
      const auto transport = pj_text(candidate.transport);
      if (!type || candidate.component > components || !numeric_ipv4(candidate.address) ||
          pj_stricmp2(&transport, "UDP") != 0 || out.size() == PJ_ICE_MAX_CAND)
        continue;
      pj_ice_sess_cand remote{};
      remote.comp_id = static_cast<pj_uint8_t>(candidate.component);
      remote.type = *type;
      remote_strings.push_back(candidate.foundation);
      remote.foundation = pj_text(remote_strings.back());
      remote.prio = candidate.priority;
      remote.addr = ipv4(candidate.address, candidate.port);
      remote.base_addr = remote.addr;
      out.push_back(remote);
    }
    for (unsigned component = 1; component <= components; ++component)
      if (std::none_of(out.begin(), out.end(), [component](const auto &remote) { return remote.comp_id == component; }))
        throw std::invalid_argument("ICE: the peer gives no IPv4 UDP candidate for component " +
                                    std::to_string(component));
    return out;
  }

  //------------------------------------------------------------------------------
  // RFC 8445 section 8.1.3: the agent completes when every stream did, and fails when one failed.
  void update_state() {
    bool all = true;
    for (const auto &stream : streams) {
      if (stream.failed) {
        agent->state_ = IceState::Failed;
        return;
      }
      all = all && stream.complete;
    }
    if (all) agent->state_ = IceState::Completed;
  }

  static void on_complete(pj_ice_sess *session, pj_status_t status) {
    auto *stream = static_cast<Stream *>(session->user_data);
    (status == PJ_SUCCESS ? stream->complete : stream->failed) = true;
    stream->owner->update_state();
  }

  static pj_status_t on_transmit(pj_ice_sess *session, unsigned component, unsigned, const void *packet,
                                 pj_size_t size, const pj_sockaddr_t *destination, unsigned) {
    auto *stream = static_cast<Stream *>(session->user_data);
    const auto [host, port] = host_port(destination);
    try {
      stream->owner->sender(stream->id, component, {static_cast<const std::uint8_t *>(packet), size}, host, port);
    } catch (...) {
      return PJ_EUNKNOWN; // pjnath counts it as a failed transmission
    }
    return PJ_SUCCESS;
  }

  // Data that is not STUN never reaches the session: the caller tells them apart (is_stun_packet).
  static void on_data(pj_ice_sess *, unsigned, unsigned, void *, pj_size_t, const pj_sockaddr_t *, unsigned) {}

  Stream *find(IceStream id) {
    for (auto &stream : streams)
      if (stream.id == id) return &stream;
    return nullptr;
  }

  const Stream *find(IceStream id) const { return const_cast<Impl *>(this)->find(id); }

  void release() noexcept {
    for (auto &stream : streams)
      if (stream.session != nullptr) {
        (void)pj_ice_sess_destroy(stream.session);
        stream.session = nullptr;
      }
    if (timer_heap != nullptr) {
      pj_timer_heap_poll(timer_heap, nullptr); // the group locks' last references
      pj_timer_heap_destroy(timer_heap);
      timer_heap = nullptr;
    }
    if (pool != nullptr) pj_pool_release(pool);
    pool = nullptr;
    if (cache_initialized) pj_caching_pool_destroy(&cache);
    cache_initialized = false;
    if (pj_initialized) pj_shutdown();
    pj_initialized = false;
  }
};

//------------------------------------------------------------------------------
// RFC 8445 sections 5.1.1.1 and 5.3: the credentials and the host candidates of the speech and control sockets.
IceAgent::IceAgent(bool controlling, IceLocalSockets sockets, IceSender sender)
    : impl_(std::make_unique<Impl>(this, controlling, std::move(sockets), std::move(sender))) {
  auto &impl = *impl_;
  if (!numeric_ipv4(impl.sockets.address) || !impl.sockets.rtp_port || !impl.sockets.rtcp_port)
    throw std::invalid_argument("ICE: an IPv4 address and the RTP and RTCP ports are required");
  impl.start_runtime();
  impl.local.ufrag = random_ice_chars(kUfragLength);
  impl.local.pwd = random_ice_chars(kPwdLength);
  impl.add_stream(IceStream::Audio, {impl.sockets.rtp_port, impl.sockets.rtcp_port});
  if (impl.sockets.control_port) impl.add_stream(IceStream::Control, {impl.sockets.control_port});
  static_assert(kAudioComponents == 2 && kControlComponents == 1, "the components of include/mcx/ice.hpp");
  impl.create_sessions();
}

IceAgent::~IceAgent() = default;

const IceDescription &IceAgent::local_description() const noexcept { return impl_->local; }

//------------------------------------------------------------------------------
// RFC 8445 sections 6.1.2 and 6.1.4: the check lists of the streams, then the checks.
void IceAgent::start(const IceDescription &remote) {
  auto &impl = *impl_;
  if (state_ != IceState::Gathered) throw std::logic_error("ICE: the checks have already started");
  if (remote.lite && !impl.controlling)
    throw std::invalid_argument("ICE: a lite peer needs this agent controlling (RFC 8445 section 6.1.1)");
  impl.remote_strings.reserve(remote.audio.size() + remote.control.size() + 2);
  impl.remote_strings.push_back(remote.ufrag);
  auto ufrag = pj_text(impl.remote_strings.back());
  impl.remote_strings.push_back(remote.pwd);
  auto pwd = pj_text(impl.remote_strings.back());
  for (auto &stream : impl.streams) {
    const auto candidates =
        impl.remote_candidates(stream.id == IceStream::Audio ? remote.audio : remote.control, stream.components);
    require(pj_ice_sess_create_check_list(stream.session, &ufrag, &pwd, static_cast<unsigned>(candidates.size()),
                                          candidates.data()),
            "create check list");
  }
  state_ = IceState::Checking;
  for (auto &stream : impl.streams) require(pj_ice_sess_start_check(stream.session), "start checks");
}

//------------------------------------------------------------------------------
// RFC 8445 section 7.3: a received STUN packet goes to its stream's session.
bool IceAgent::receive(IceStream stream, unsigned component, std::span<const std::uint8_t> packet,
                       const std::string &host, std::uint16_t port) {
  auto *found = impl_->find(stream);
  if (found == nullptr || component == 0 || component > found->components || !is_stun_packet(packet)) return false;
  std::vector<std::uint8_t> copy(packet.begin(), packet.end()); // pjnath may rewrite the buffer
  const auto source = ipv4(host, port);
  return pj_ice_sess_on_rx_pkt(found->session, component, 0, copy.data(), copy.size(), &source,
                               pj_sockaddr_get_len(&source)) == PJ_SUCCESS;
}

//------------------------------------------------------------------------------
// pjnath's timers: check pacing, STUN retransmissions, nomination and keep-alives.
void IceAgent::tick() { pj_timer_heap_poll(impl_->timer_heap, nullptr); }

//------------------------------------------------------------------------------
// RFC 8445 section 8.1.1: the nominated pair's remote address.
std::optional<std::pair<std::string, std::uint16_t>> IceAgent::selected(IceStream stream, unsigned component) const {
  const auto *found = impl_->find(stream);
  if (found == nullptr || !found->complete || component == 0 || component > found->components) return std::nullopt;
  const auto *check = found->session->comp[component - 1].nominated_check;
  if (check == nullptr) check = found->session->comp[component - 1].valid_check;
  if (check == nullptr || check->rcand == nullptr) return std::nullopt;
  return host_port(&check->rcand->addr);
}

//------------------------------------------------------------------------------
// RFC 8445 section 8.1.2: a nominated local candidate other than the component's host candidate (the default).
bool IceAgent::needs_updated_offer() const {
  for (const auto &stream : impl_->streams) {
    if (!stream.complete) continue;
    for (unsigned component = 1; component <= stream.components; ++component) {
      const auto *check = stream.session->comp[component - 1].nominated_check;
      if (check != nullptr && check->lcand != nullptr &&
          (check->lcand->type != PJ_ICE_CAND_TYPE_HOST ||
           pj_sockaddr_get_port(&check->lcand->addr) != stream.ports[component - 1]))
        return true;
    }
  }
  return false;
}

} // namespace mcx
