//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The media protection state of one MC client call: the SRTCP contexts of floor or transmission control under the
// CSK, the SRTP contexts of group media under each GMK epoch (with GUK-ID diversity) and of private calls under their
// PCK, as TS 33.180 clauses 7.4, 7.5 and 9.4 derive and use them.
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), RFC 3550, RFC 3711, RFC 7714.

#pragma once
#include "mcx/keying.hpp"
#include "mcx/security.hpp"

#include <ctime>
#include <exception>
#include <limits>
#include <map>
#include <optional>
#include <memory>
#include <set>
#include <stdexcept>
#include <type_traits>
#include <string>

namespace mcx {
//------------------------------------------------------------------------------
// RFC 3550 section 5.1 (RTP) and section 6.4.1 (RTCP): the SSRC of a packet, which selects its crypto context
// (RFC 3711 section 3.2.3); the version must be 2.
inline std::uint32_t wire_ssrc(std::span<const std::uint8_t> bytes, bool rtcp) {
  const std::size_t offset = rtcp ? 4 : 8;
  if (bytes.size() < offset + 4 || (bytes[0] >> 6) != 2) throw std::invalid_argument("invalid protected packet header");
  return (std::uint32_t(bytes[offset]) << 24) | (std::uint32_t(bytes[offset + 1]) << 16) |
         (std::uint32_t(bytes[offset + 2]) << 8) | bytes[offset + 3];
}

//------------------------------------------------------------------------------
// TS 33.180 annex E.6.10: "The 'Expiry time' element shall define the time in UTC at which the associated key shall
// no longer be used". A packet refused because the Expiry time of its PCK has passed: it is neither protected nor
// unprotected (not sent, or dropped); the call is left as it is.
struct PacketKeyExpired : std::runtime_error {
  using std::runtime_error::runtime_error;
};

//------------------------------------------------------------------------------
// TS 33.180 clauses 7.4, 7.5 and 9.4: the SRTP and SRTCP crypto contexts of one MC client call, keyed by the CSK
// (floor or transmission control), the GMK epochs of the group and the PCKs of private calls.
class ProtectedCall {
  // An MCVideo call's streams (audio, video and transmission control) take the MCVideo
  // CS-IDs of TS 33.180 table E.1.3-1; the RTP streams are told apart by SSRC.
  bool mcvideo_ = false;
  // The clock of the key times (Unix seconds); tests set their own (set_clock).
  using Clock = std::uint64_t (*)();

  static std::uint64_t system_now() { return std::uint64_t(std::time(nullptr)); }

  Clock clock_ = system_now;

  std::uint64_t now() const { return clock_(); }

  using StreamId = std::pair<std::uint32_t, std::string>;

  // RFC 3711 section 3.2: the crypto context of one SRTP stream, and when it was last used (for eviction).
  struct MediaStream {
    std::unique_ptr<SecureStream> stream;
    std::uint64_t last_used;
  };

  // TS 33.180 clause 7.4.2: the streams of one GMK (one GMK-ID), and the SSRCs retired under it, which are never
  // reused so that no SRTP packet index restarts under the same key.
  struct GroupEpoch {
    keying::KeyMessage key;
    std::map<StreamId, MediaStream> audio;
    std::set<StreamId> retired;
    std::uint64_t uses = 0;
  };

  std::optional<keying::KeyMessage> floor_key_;
  std::map<std::uint32_t, std::unique_ptr<SecureStream>> floors_;
  // Selection is separate from epoch lifetime. Switching away must preserve
  // both receiver replay windows and sender packet indices until key expiry.
  std::optional<std::uint32_t> active_group_;
  // TS 33.180 annex E.6.4: a GMK received ahead of its Activation time while the selected one is still usable
  // (the next key of a key change); it is selected once that time comes.
  std::optional<std::uint32_t> next_group_;
  std::map<std::uint32_t, GroupEpoch> group_epochs_;

  // TS 33.180 clause 7.4.1: one PCK per private call. The context lives until the call
  // ends, so a call that is set aside and resumed never restarts a packet index.
  struct PrivateContext {
    keying::KeyMessage key;
    bool local_initiator;
    std::map<std::uint32_t, std::unique_ptr<SecureStream>> sent, received;
  };

  std::optional<std::uint32_t> active_private_;
  std::map<std::uint32_t, PrivateContext> private_contexts_;

  // RFC 7714 section 8.4 (TS 33.180 clauses 7.5 and 9.4 use AES-GCM SRTP and SRTCP): "each originating endpoint MUST
  // maintain a history of outbound SSRC identifiers that it has issued within the lifetime of the current master
  // key, and when a new SSRC requests an SSRC identifier it MUST NOT be given an identifier that has been previously
  // issued". The SSRCs this endpoint has issued (issue_ssrc), kept for the lifetime of this object, which spans the
  // lifetime of each of its keys (the CSK, the GMK epochs, the PCKs): a new key's history then starts with the
  // SSRCs still in use, and an SSRC is issued once for all of them.
  std::set<std::uint32_t> issued_ssrcs_;
  // Implementation limits, not from TS 33.180: they bound the memory that packets with attacker-chosen SSRCs or a
  // stream of new keys can claim. A call has one PCK at a time, plus those of calls set aside (ambient listening);
  // a few GMK epochs overlap during rekeying; a group sender uses one SSRC per stream (audio, video) and a handful
  // after restarts; floor control has one SSRC per participant and the controlling function.
  static constexpr std::size_t private_capacity = 4;
  static constexpr std::size_t group_epoch_capacity = 16;
  static constexpr std::size_t media_per_sender = 8;
  static constexpr std::size_t media_capacity = 256;
  static constexpr std::size_t retirement_capacity = 65536;
  static constexpr std::size_t floor_capacity = 1024;

  // TS 33.180 annex E.6.10: the Expiry time of a key as a comparable instant: 0 means the key never expires.
  static std::uint64_t expiry_of(const keying::KeyProperties &properties) {
    return properties.expiry_unix_seconds == 0 ? std::numeric_limits<std::uint64_t>::max()
                                               : properties.expiry_unix_seconds;
  }

  // TS 33.180 annex E.6.4: the Activation time of a key, 0 meaning the timestamp of its I_MESSAGE.
  static std::uint64_t activation_of(const keying::KeyMessage &key) {
    const auto activation = key.properties ? key.properties->activation_unix_seconds : 0;
    return activation ? activation : key.ntp_seconds - 2208988800ULL;
  }

  // The epoch in use: the waiting next one once its Activation time has come, else the selected one.
  std::optional<std::uint32_t> selected_group() const {
    if (next_group_) {
      const auto next = group_epochs_.find(*next_group_);
      if (next != group_epochs_.end() && activation_of(next->second.key) <= now()) return next_group_;
    }
    return active_group_;
  }

  // Selects [id], or, when its Activation time is still to come and the selected epoch is usable now, keeps that
  // one until then (TS 33.180 clause 5.7 and annex E.6.4).
  void select_group(std::uint32_t id) {
    if (activation_of(group_epochs_.at(id).key) > now() && active_group_ && *active_group_ != id) {
      try {
        valid(group_epochs_.at(*active_group_).key);
        next_group_ = id;
        return;
      } catch (...) {}
    }
    active_group_ = id;
    next_group_.reset();
  }

  // TS 33.180 annex E.6.9 (Status bit 0: not revoked), annex E.6.4 (Activation time) and annex E.6.10 (Expiry
  // time, 0 never expires): throws unless the key may be used now.
  void valid(const keying::KeyMessage &key) const {
    const auto at = now();
    if (!key.properties || !(key.properties->status & 1) || key.properties->activation_unix_seconds > at ||
        expiry_of(*key.properties) <= at)
      throw std::runtime_error("protected call key expired or revoked");
  }

  // TS 33.180 clause 9.4.6 and clause 9.4.7: SRTCP protection of floor or transmission control under the CSK, one
  // context per SSRC.
  std::vector<std::uint8_t> floor(std::span<const std::uint8_t> packet, bool protect) {
    if (!floor_key_) throw std::runtime_error("floor key unavailable");
    valid(*floor_key_);
    const auto ssrc = wire_ssrc(packet, true);
    auto it = floors_.find(ssrc);
    if (it != floors_.end()) return protect ? it->second->protect_rtcp(packet) : it->second->unprotect_rtcp(packet);
    if (floors_.size() >= floor_capacity) throw std::runtime_error("floor context capacity; CSK rotation required");
    auto stream = std::make_unique<SecureStream>(
        derive_floor_security(floor_key_->key, floor_key_->random, floor_key_->csb_id, mcvideo_), ssrc);
    auto output = protect ? stream->protect_rtcp(packet) : stream->unprotect_rtcp(packet);
    // Invalid packets cannot consume slots or change existing replay state.
    floors_.emplace(ssrc, std::move(stream));
    return output;
  }

  // TS 33.180 clause 7.4.1 and clause 7.5: SRTP of a private call under its PCK, with the CS-ID of table E.1.3-1.
  std::vector<std::uint8_t> private_audio(std::span<const std::uint8_t> packet, bool protect) {
    if (!active_private_) throw std::runtime_error("private call key unavailable");
    auto &context = private_contexts_.at(*active_private_);
    // TS 33.180 annex E.6.10 (and E.6.9, Status) at each packet: a PCK received with Key Parameters (annex E.1.2) is
    // not used past its non-zero Expiry time, in either direction; a PCK without them has no Expiry time. Only the
    // packet is refused (PacketKeyExpired): private_ready() and so the call are left as they are.
    try {
      keying::require_in_use(context.key, now());
    } catch (const std::exception &error) {
      throw PacketKeyExpired(std::string("private call key: ") + error.what());
    }
    const auto ssrc = wire_ssrc(packet, false);
    auto &streams = protect ? context.sent : context.received;
    auto it = streams.find(ssrc);
    if (it != streams.end()) return protect ? it->second->protect_rtp(packet) : it->second->unprotect_rtp(packet);
    // One sender per direction; a new SSRC is a new stream under the same key.
    if (streams.size() >= media_per_sender) throw std::runtime_error("private call SSRC capacity reached");
    // The initiator's streams use CS-ID 0 and the receiver's CS-ID 1, or 2 and 3 for MCVideo (TS 33.180 table
    // E.1.3-1).
    const bool from_initiator = protect == context.local_initiator;
    auto stream = std::make_unique<SecureStream>(
        derive_private_security(context.key.key, context.key.random, context.key.csb_id, from_initiator, mcvideo_),
        ssrc);
    auto output = protect ? stream->protect_rtp(packet) : stream->unprotect_rtp(packet);
    streams.emplace(ssrc, std::move(stream));
    return output;
  }

  // TS 33.180 clause 7.4.2 and clause 7.5: SRTP of group media under the selected GMK, diversified per sender by
  // the GUK-ID (clause 5.2.3, annex F.1.3); a private call's PCK takes precedence.
  std::vector<std::uint8_t> audio(std::span<const std::uint8_t> packet, const std::string &sender, bool protect) {
    if (active_private_) return private_audio(packet, protect);
    if (const auto selected = selected_group(); selected != active_group_) {
      active_group_ = selected;
      next_group_.reset();
    }
    if (!active_group_ || sender.empty()) throw std::runtime_error("group media key or sender unavailable");
    auto &epoch = group_epochs_.at(*active_group_);
    auto *group_key_ = &epoch.key;
    auto &audio_ = epoch.audio;
    auto &retired_audio_ = epoch.retired;
    auto &media_use_ = epoch.uses;
    valid(*group_key_);

    const auto ssrc = wire_ssrc(packet, false);
    const StreamId id{ssrc, sender};
    if (retired_audio_.contains(id)) throw std::runtime_error("retired media SSRC cannot be reused in this GMK epoch");
    auto it = audio_.find(id);
    if (it != audio_.end()) {
      auto output = protect ? it->second.stream->protect_rtp(packet) : it->second.stream->unprotect_rtp(packet);
      it->second.last_used = ++media_use_;
      return output;
    }

    auto victim = audio_.end();
    std::size_t sender_streams = 0;
    for (auto current = audio_.begin(); current != audio_.end(); ++current) {
      if (current->first.second != sender) continue;
      ++sender_streams;
      if (victim == audio_.end() || current->second.last_used < victim->second.last_used) victim = current;
    }
    if (sender_streams < media_per_sender) {
      victim = audio_.end();
      if (audio_.size() >= media_capacity) {
        for (auto current = audio_.begin(); current != audio_.end(); ++current)
          if (victim == audio_.end() || current->second.last_used < victim->second.last_used) victim = current;
      }
    }
    if (victim != audio_.end() && retired_audio_.size() >= retirement_capacity)
      throw std::runtime_error("media retirement capacity; GMK rotation required");

    const auto guk = derive_guk_id(group_key_->key, group_key_->csb_id, sender);
    auto stream = std::make_unique<SecureStream>(
        derive_group_security(group_key_->key, group_key_->random, group_key_->csb_id, guk, mcvideo_), ssrc);
    auto output = protect ? stream->protect_rtp(packet) : stream->unprotect_rtp(packet);
    // Authenticate before retiring another stream: forged SSRCs must not
    // evict a legitimate peer's replay window or consume the retirement budget.
    if (victim != audio_.end()) {
      retired_audio_.insert(victim->first);
      audio_.erase(victim);
    }
    audio_.emplace(id, MediaStream{std::move(stream), ++media_use_});
    return output;
  }

public:
  ProtectedCall() = default;

  // RFC 7714 section 8.4: whether the SSRC was issued by this endpoint, or is one of the streams it holds a context
  // for under its keys (the peer's too: the CSK protects SRTCP in both directions, so a peer's SSRC under it is not
  // given out either).
  bool ssrc_taken(std::uint32_t ssrc) const {
    if (issued_ssrcs_.contains(ssrc) || floors_.contains(ssrc)) return true;
    for (const auto &[id, epoch] : group_epochs_)
      for (const auto &[stream, media] : epoch.audio)
        if (stream.first == ssrc) return true;
    for (const auto &[id, context] : private_contexts_)
      if (context.sent.contains(ssrc) || context.received.contains(ssrc)) return true;
    return false;
  }

  // Records an SSRC this endpoint issued (RFC 7714 section 8.4).
  void record_ssrc(std::uint32_t ssrc) { issued_ssrcs_.insert(ssrc); }

  // RFC 7714 section 8.4: a new outbound SSRC from draw (RFC 3550 section 8.1, random), drawn again until it is one
  // not taken (ssrc_taken) nor [reserved], and recorded. [reserved]: SSRCs negotiated under the key for streams
  // that have not carried a packet yet, so have no context (the other side's SSRCs of the calls under way, the one
  // offered for the stream being set up): RFC 7714 section 9.1 forms the SRTCP IV from the SSRC and the index, so
  // this endpoint's new stream on such an SSRC would repeat the IVs of the other direction's stream under the key.
  template <class Draw> std::uint32_t issue_ssrc(Draw draw, const std::set<std::uint32_t> &reserved = {}) {
    std::uint32_t ssrc;
    do ssrc = draw();
    while (ssrc_taken(ssrc) || reserved.contains(ssrc));
    record_ssrc(ssrc);
    return ssrc;
  }

  explicit ProtectedCall(bool mcvideo) : mcvideo_(mcvideo) {}

  // Replaces the clock of the key times (Unix seconds), for tests.
  void set_clock(Clock clock) { clock_ = clock; }

  bool mcvideo() const { return mcvideo_; }

  // TS 33.180 clause 9.4.6: selects the CSK of floor or transmission control; a re-delivery of the same CSK-ID
  // only updates its properties. A new CSK re-keys the streams that go on ([continuing]: the SSRCs of the calls that
  // continue, in either direction): RFC 3711 section 3.4 (through TS 33.180 clauses 9.4.7 and 9.4.8), "after a
  // re-key, the SRTCP index MUST NOT be reset to zero again", so each keeps its crypto context, SRTCP index and
  // replay list under the new master key (SecureStream::rekey). The contexts of other SSRCs end with the old key: a
  // stream that starts under the new key starts at SRTCP index 0 (section 3.4). Only one floor key is held: packets
  // still in flight under the old MKI are no longer accepted.
  void set_floor(const keying::KeyMessage &key, const std::set<std::uint32_t> &continuing = {}) {
    // The replacement is made complete first and then published by a move, which does not throw: a failure while
    // copying (an allocation of the text or the groups of the properties) leaves the current key, properties and
    // contexts as they were, never new validity data over the old key's streams.
    static_assert(std::is_nothrow_move_assignable_v<keying::KeyMessage> &&
                  std::is_nothrow_move_constructible_v<keying::KeyMessage>);
    if (floor_key_ && floor_key_->csb_id == key.csb_id) {
      if (floor_key_->key != key.key || floor_key_->random != key.random) throw std::runtime_error("CSK ID collision");
      auto properties = key.properties;
      floor_key_->properties = std::move(properties);
      return;
    }
    // The SRTCP material of the new key is derived before anything changes: a failure (an invalid key, HMAC or
    // allocation) leaves the current key and its contexts as they were, never a new key over old contexts.
    const auto material = derive_floor_security(key.key, key.random, key.csb_id, mcvideo_);
    auto next = key;
    floor_key_ = std::move(next);
    std::exception_ptr failure;
    for (auto it = floors_.begin(); it != floors_.end();) {
      if (!continuing.contains(it->first)) {
        it = floors_.erase(it);
        continue;
      }
      // A context whose re-key fails refuses every later packet in both directions (SecureStream::rekey), also
      // after a re-delivery of the same CSK-ID, which only updates the properties; it is kept so that its SSRC never
      // starts again at index 0 under the new key.
      try {
        it->second->rekey(material);
      } catch (...) {
        if (!failure) failure = std::current_exception();
      }
      ++it;
    }
    if (failure) std::rethrow_exception(failure);
  }

  // Whether the SSRC has carried floor or transmission control under the current floor key, in either direction (it
  // has a context in floors_; a stream re-keyed from the previous key keeps its context). With AEAD_AES_128_GCM
  // (TS 33.180 clause 9.4.8) the SRTCP IV is the salt XOR the SSRC and the SRTCP index (RFC 7714 section 9.1), so a
  // new stream of this endpoint on such an SSRC, starting at index 0 (RFC 3711 section 3.4), would repeat an IV:
  // RFC 3711 section 9.1, "Any fixed keystream output, generated from the same key and index MUST only be used to
  // encrypt once", "the SSRC MUST be unique between all the RTP streams within the same RTP session that share the
  // same master key"; RFC 7714 section 8.4 (applied to SRTCP by section 9.4), a new SSRC "MUST NOT be given an
  // identifier that has been previously issued".
  bool floor_ssrc_used(std::uint32_t ssrc) const { return floors_.contains(ssrc); }

  // The floor key in use (set_floor), none before the first.
  const std::optional<keying::KeyMessage> &floor_key() const { return floor_key_; }

  // TS 33.180 clause 7.3.3 and clause 7.4.2: selects a GMK epoch, keeping earlier unexpired epochs and their replay
  // state; one ahead of its Activation time waits while the selected one is usable (select_group).
  void set_group(const keying::KeyMessage &key) {
    if (!key.properties) throw std::runtime_error("GMK properties unavailable");
    auto found = group_epochs_.find(key.csb_id);
    if (found != group_epochs_.end()) {
      auto &old = found->second.key;
      if (old.key != key.key || old.random != key.random) throw std::runtime_error("GMK ID collision");
      // Re-delivery may shorten lifetime or revoke an epoch, but cannot
      // extend its nonce lifetime or revive a revoked key identifier.
      if (old.properties && key.properties &&
          (expiry_of(*key.properties) > expiry_of(*old.properties) ||
           key.properties->activation_unix_seconds != old.properties->activation_unix_seconds ||
           key.properties->groups != old.properties->groups || key.properties->type != old.properties->type ||
           (!(old.properties->status & 1) && (key.properties->status & 1))))
        throw std::runtime_error("GMK epoch properties changed unsafely");
      old.properties = key.properties;
      select_group(key.csb_id);
      return;
    }

    const auto at = now();
    for (auto it = group_epochs_.begin(); it != group_epochs_.end();) {
      if (!it->second.key.properties || expiry_of(*it->second.key.properties) <= at) {
        if (active_group_ == it->first) active_group_.reset();
        if (next_group_ == it->first) next_group_.reset();
        it = group_epochs_.erase(it);
      } else
        ++it;
    }

    // Never evict an unexpired epoch to make room: doing so would permit
    // ciphertext replay or outbound nonce reuse when that group is selected.
    if (group_epochs_.size() >= group_epoch_capacity) throw std::runtime_error("unexpired GMK epoch capacity reached");
    group_epochs_.emplace(key.csb_id, GroupEpoch{key, {}, {}, 0});
    select_group(key.csb_id);
  }

  void clear_group() {
    active_group_.reset();
    next_group_.reset();
  }

  // A private call selects its PCK in place of the group key. local_initiator is
  // true for the user who initiated the call (TS 33.180 table E.1.3-1), which in a first-to-answer
  // call is not the user who generated the PCK (TS 33.180 clause 7.2.4.2). The PCK-ID purpose tag is 1
  // (TS 33.180 clause 7.4.1, annex G).
  void set_private(const keying::KeyMessage &key, bool local_initiator) {
    if ((key.csb_id >> 28) != 1) throw std::runtime_error("PCK-ID purpose tag must be one");
    auto found = private_contexts_.find(key.csb_id);
    if (found != private_contexts_.end()) {
      if (found->second.key.key != key.key || found->second.key.random != key.random ||
          found->second.local_initiator != local_initiator)
        throw std::runtime_error("PCK-ID collision");
    } else {
      if (private_contexts_.size() >= private_capacity) throw std::runtime_error("private call key capacity reached");
      private_contexts_.emplace(key.csb_id, PrivateContext{key, local_initiator, {}, {}});
    }
    active_private_ = key.csb_id;
  }

  // Deselect the PCK while its call is set aside (the ambient listening call, TS 33.180 clause 7.2.5).
  void suspend_private() { active_private_.reset(); }

  void resume_private(std::uint32_t pck_id) {
    if (!private_contexts_.contains(pck_id)) throw std::runtime_error("private call key unavailable");
    active_private_ = pck_id;
  }

  // The call ended: the PCK is never used again.
  void end_private(std::uint32_t pck_id) {
    private_contexts_.erase(pck_id);
    if (active_private_ == pck_id) active_private_.reset();
  }

  std::optional<std::uint32_t> private_key_id() const { return active_private_; }

  // Whether a PCK is selected. Its Expiry time is checked per packet (private_audio), not here: the call is not
  // ended by it.
  bool private_ready() const { return active_private_.has_value(); }

  bool group_ready() const {
    const auto selected = selected_group();
    if (!selected) return false;
    try {
      valid(group_epochs_.at(*selected).key);
      return true;
    } catch (...) {
      return false;
    }
  }

  bool floor_ready() const {
    if (!floor_key_) return false;
    try {
      valid(*floor_key_);
      return true;
    } catch (...) {
      return false;
    }
  }

  std::vector<std::uint8_t> protect_floor(std::span<const std::uint8_t> packet) { return floor(packet, true); }

  std::vector<std::uint8_t> unprotect_floor(std::span<const std::uint8_t> packet) { return floor(packet, false); }

  std::vector<std::uint8_t> protect_media(std::span<const std::uint8_t> packet, const std::string &sender) {
    return audio(packet, sender, true);
  }

  std::vector<std::uint8_t> unprotect_media(std::span<const std::uint8_t> packet, const std::string &sender) {
    return audio(packet, sender, false);
  }
};

//------------------------------------------------------------------------------
// TS 24.380 clause 4.3.3.1 (TS 24.581 clause 4.3.3.1): the SSRC [offered] that a peer allocates in its SDP for the
// floor or transmission control messages this endpoint sends ("the distant entity shall use [it] in the RTCP header
// of the floor control messages it sends in this session"). Refused: this endpoint's own SSRC for the stream
// ([own], the one it allocated for the peer's messages), and, under a floor key ([keys], null when floor control is
// not protected), an SSRC already used under it for another stream: one that carried floor control under the key
// in either direction (ProtectedCall::floor_ssrc_used) or one of another stream under way ([in_use]); a new stream
// of this endpoint on it would repeat an SRTCP IV under AEAD_AES_128_GCM (ProtectedCall::floor_ssrc_used). The
// stream going on with the SSRC it has ([current]: a re-INVITE, a later answer, a session refresh) is not a new
// stream and is kept. A relay, which passes each side's SSRC on to the other side, has no SSRC of its own: [own] is
// then the SSRC of the opposite direction, once known.
inline bool floor_ssrc_refused(std::uint32_t offered, std::optional<std::uint32_t> own,
                               std::optional<std::uint32_t> current, const ProtectedCall *keys,
                               const std::set<std::uint32_t> &in_use = {}) {
  if (own && offered == *own) return true;
  if (current && *current == offered) return false;
  return keys && (keys->floor_ssrc_used(offered) || in_use.contains(offered));
}
} // namespace mcx
