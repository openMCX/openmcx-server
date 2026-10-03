// The media protection state of one MC client call: the SRTCP contexts of floor or transmission control under the
// CSK, the SRTP contexts of group media under each GMK epoch (with GUK-ID diversity) and of private calls under their
// PCK, as TS 33.180 clauses 7.4, 7.5 and 9.4 derive and use them.
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), RFC 3550, RFC 3711.

#pragma once
#include "mcx/keying.hpp"
#include "mcx/security.hpp"

#include <ctime>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>
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
// TS 33.180 clauses 7.4, 7.5 and 9.4: the SRTP and SRTCP crypto contexts of one MC client call, keyed by the CSK
// (floor or transmission control), the GMK epochs of the group and the PCKs of private calls.
class ProtectedCall {
  // An MCVideo call's streams (audio, video and transmission control) take the MCVideo
  // CS-IDs of TS 33.180 table E.1.3-1; the RTP streams are told apart by SSRC.
  bool mcvideo_ = false;
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

  // TS 33.180 annex E.6.9 (Status bit 0: not revoked), annex E.6.4 (Activation time) and annex E.6.10 (Expiry
  // time, 0 never expires): throws unless the key may be used now.
  static void valid(const keying::KeyMessage &key) {
    const auto now = std::uint64_t(std::time(nullptr));
    if (!key.properties || !(key.properties->status & 1) || key.properties->activation_unix_seconds > now ||
        expiry_of(*key.properties) <= now)
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

  explicit ProtectedCall(bool mcvideo) : mcvideo_(mcvideo) {}

  bool mcvideo() const { return mcvideo_; }

  // TS 33.180 clause 9.4.6: selects the CSK of floor or transmission control; a re-delivery of the same CSK-ID
  // only updates its properties.
  void set_floor(const keying::KeyMessage &key) {
    if (floor_key_ && floor_key_->csb_id == key.csb_id) {
      if (floor_key_->key != key.key || floor_key_->random != key.random) throw std::runtime_error("CSK ID collision");
      floor_key_->properties = key.properties;
      return;
    }
    floor_key_ = key;
    floors_.clear();
  }

  // TS 33.180 clause 7.3.3 and clause 7.4.2: selects a GMK epoch, keeping earlier unexpired epochs and their replay
  // state.
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
      active_group_ = key.csb_id;
      return;
    }
    const auto now = std::uint64_t(std::time(nullptr));
    for (auto it = group_epochs_.begin(); it != group_epochs_.end();) {
      if (!it->second.key.properties || expiry_of(*it->second.key.properties) <= now) {
        if (active_group_ == it->first) active_group_.reset();
        it = group_epochs_.erase(it);
      } else
        ++it;
    }
    // Never evict an unexpired epoch to make room: doing so would permit
    // ciphertext replay or outbound nonce reuse when that group is selected.
    if (group_epochs_.size() >= group_epoch_capacity) throw std::runtime_error("unexpired GMK epoch capacity reached");
    group_epochs_.emplace(key.csb_id, GroupEpoch{key, {}, {}, 0});
    active_group_ = key.csb_id;
  }

  void clear_group() { active_group_.reset(); }

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

  bool private_ready() const { return active_private_.has_value(); }

  bool group_ready() const {
    if (!active_group_) return false;
    try {
      valid(group_epochs_.at(*active_group_).key);
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
} // namespace mcx
