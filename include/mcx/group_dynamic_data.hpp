//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The subscription to group dynamic data (TS 24.281 clauses 8.2.1.6, 8.2.2.2.16, 8.2.2.3.9 and 8.2.2.3.10): the
// application/pidf+xml body indicating per-group dynamic data (clause 8.3.1.2), the application/simple-filter+xml
// body indicating per-group dynamic data restrictions (clause 8.3.2.2), and the bookkeeping of the subscriptions at
// the MCVideo server owning the group, kept apart from the SIP engine so that it can be tested on its own.
//
// Where the specification leaves a point open, this coding takes:
//   - the <groupStatus> and <additionalData> elements, and the "client" and "expires" attributes of <affiliation>,
//     in the namespace of table 8.3.1.2-1 (urn:3gpp:ns:mcvideoPresInfo:1.0, prefix mcvideoPI10 of table
//     8.3.1.2-2); the filter values of clause 8.3.2.2 item 7 B name them with the "pidf" prefix, and are matched
//     on their element and attribute names only, white space ignored;
//   - the filter "indicating the MCVideo group ID" (clause 8.2.1.6 step 7, clause 8.2.2.3.9 condition 5): the
//     values of clause 8.3.2.2 carry no group ID, so a filter names a group only with an <include> of the form
//     //pidf:presence[@entity="<group>"]; when it does, the group must be the <mcvideo-request-uri> (condition 5
//     says <mcvideo-calling-user-id>, which is the subscriber's MCVideo ID);
//   - a filter with none of the values of item 7 B a) to e) selects all the dynamic data (RFC 4661 section 3.2:
//     with no <what> restriction all of it is sent).
//
// Specifications: TS 24.281 V19.6.0 (Rel-19), RFC 3856, RFC 3863, RFC 4661, RFC 6665.
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.281 clause 8.3.1.2 items 9 to 15 (per-group dynamic data): an affiliated member of the group: its <tuple>
// "id", one <affiliation> per client ("client", "expires"), and its activated functional aliases.
struct GroupDynamicDataMember {
  struct Client {
    std::string client;
    std::string expires; // xs:dateTime, empty for none
    bool operator==(const Client &) const = default;
  };

  std::string id;
  std::vector<Client> clients;
  std::vector<std::string> functional_aliases;
  bool operator==(const GroupDynamicDataMember &) const = default;
};

//------------------------------------------------------------------------------
// TS 24.281 clause 8.3.1.2 (per-group dynamic data): the <presence> "entity" (the MCVideo group ID), <groupStatus>
// ("emergency" or "in-peril", table 8.3.1.2-3; empty for none) with its "ModifiedBy", the <additionalData>
// attributes, and the affiliated members.
struct GroupDynamicDataDocument {
  std::string group;
  std::string group_status;
  std::string modified_by;
  std::string broadcast_alias;
  std::string regroup_alias;
  std::optional<bool> call_ongoing;
  std::vector<GroupDynamicDataMember> members;
  bool operator==(const GroupDynamicDataDocument &) const = default;
};

//------------------------------------------------------------------------------
// TS 24.281 clause 8.3.2.2 (per-group dynamic data restrictions), item 7 B: the dynamic data the subscriber asks
// for; `group`, the group the filter names (see the header comment), empty for none.
struct GroupDynamicDataFilter {
  bool group_status = false;    // a) //pidf:presence/pidf:groupStatus/@pidf:ModifiedBy
  bool broadcast_alias = false; // b) //pidf:presence/pidf:additionalData/@pidf:groupBroadcastAlias
  bool regroup_alias = false;   // c) //pidf:presence/pidf:additionalData/@pidf:groupRegroupAlias
  bool call_ongoing = false;    // d) //pidf:presence/pidf:additionalData/@pidf:groupCallOngoing
  bool affiliated = false;      // e) //pidf:presence/pidf:tuple/pidf:status/pidf:affiliation/@pidf:client
                                //    [@pidf:status="affiliated"]
  std::string group;
  std::string id = "gdd"; // the <filter> "id" (item 5 A)

  // Whether any item of 7 B is asked for; with none, all the dynamic data is sent.
  [[nodiscard]] bool selects() const {
    return group_status || broadcast_alias || regroup_alias || call_ongoing || affiliated;
  }

  bool operator==(const GroupDynamicDataFilter &) const = default;
};

//------------------------------------------------------------------------------
// TS 24.281 clause 8.3.2.2 item 7 B: the filter values, in the order a) to e).
inline constexpr std::string_view gdd_filter_group_status = "//pidf:presence/pidf:groupStatus/@pidf:ModifiedBy";
inline constexpr std::string_view gdd_filter_broadcast_alias =
    "//pidf:presence/pidf:additionalData/@pidf:groupBroadcastAlias";
inline constexpr std::string_view gdd_filter_regroup_alias =
    "//pidf:presence/pidf:additionalData/@pidf:groupRegroupAlias";
inline constexpr std::string_view gdd_filter_call_ongoing =
    "//pidf:presence/pidf:additionalData/@pidf:groupCallOngoing";
inline constexpr std::string_view gdd_filter_affiliated =
    "//pidf:presence/pidf:tuple/pidf:status/pidf:affiliation/@pidf:client [@pidf:status=\"affiliated\"]";

//------------------------------------------------------------------------------
// TS 24.281 clause 8.3.1.2 (per-group dynamic data) with clause 8.2.2.3.10 step 2 a: writes the PIDF; every
// <affiliation> carries its "expires" when one is known. With a filter that selects items, only those are written
// (RFC 4661 section 3.2); the <presence> "entity" always.
std::string group_dynamic_data_xml(const GroupDynamicDataDocument &document,
                                   const GroupDynamicDataFilter *filter = nullptr);
//------------------------------------------------------------------------------
// TS 24.281 clause 8.3.1.2 (per-group dynamic data): reads the PIDF (as the MCVideo client does, clause 8.2.1.6).
GroupDynamicDataDocument parse_group_dynamic_data(std::string_view xml);

//------------------------------------------------------------------------------
// TS 24.281 clause 8.3.2.2 (per-group dynamic data restrictions): writes the filter of clause 8.2.1.6 step 7.
std::string group_dynamic_data_filter_xml(const GroupDynamicDataFilter &filter);
//------------------------------------------------------------------------------
// TS 24.281 clause 8.3.2.2 (per-group dynamic data restrictions): reads the filter; none when the body is a
// simple-filter of another kind (a per-client or per-user filter, item 7 B of the other two lists: an <include> of
// //pidf:presence/pidf:tuple[@id="..."]) or names no item of 7 B a) to e) nor a group. Throws on a body that is no
// simple-filter (wrong root or namespace), or one whose <filter> carries "uri" or "domain" (items 5 B and 5 C) or
// whose <include> carries "type" (item 7 A).
std::optional<GroupDynamicDataFilter> parse_group_dynamic_data_filter(std::string_view xml);

//------------------------------------------------------------------------------
// TS 24.281 clause 8.2.1.6 steps 4 and 5 and clause 8.2.2.3.9 step 3: the Expires header field of a subscription to
// group dynamic data. RFC 6665 section 4.1.2.1 with RFC 3261 section 20.19: a decimal of at most 4294967295.
enum class GddExpires {
  subscribe, // 4294967295: the current state and the later notifications
  fetch,     // 0: the current state only, or the end of the subscription in its dialog
  too_brief, // absent, or nonzero below 4294967295: 423 with Min-Expires 4294967295 (clause 8.2.2.3.9 step 3)
  malformed, // not a decimal number of at most 4294967295: 400 (RFC 3261 section 21.4.1)
};
GddExpires classify_gdd_expires(std::optional<std::string_view> header);

inline constexpr std::string_view gdd_max_expires = "4294967295";

//------------------------------------------------------------------------------
// TS 24.281 clause 8.2.2.3.9: the answer of the MCVideo server owning the group to an initial SUBSCRIBE whose
// conditions hold: 423 (step 3), 400 for a malformed Expires, 403 for a group that does not exist (step 4) or a
// subscriber not authorised (step 5), else 200 (step 6).
int gdd_subscribe_status(GddExpires expires, bool group_exists, bool authorised);

//------------------------------------------------------------------------------
// TS 24.281 clauses 8.2.2.3.9 and 8.2.2.3.10: the subscriptions to group dynamic data at the MCVideo server owning
// the groups, by dialog: the served MCVideo group ID, the handled MCVideo ID and the filter; and the last body sent,
// so that a NOTIFY goes out on every change of the group's dynamic data and only then.
class GroupDynamicDataSubscriptions {
public:
  struct Subscription {
    std::string group, user, peer; // peer: the participating function it came through, empty for a local subscriber
    GroupDynamicDataFilter filter;
    std::string last_body;
  };

  [[nodiscard]] bool contains(const std::string &dialog) const { return subscriptions_.contains(dialog); }

  [[nodiscard]] const Subscription *find(const std::string &dialog) const;

  [[nodiscard]] std::size_t size() const { return subscriptions_.size(); }

  [[nodiscard]] const std::map<std::string, Subscription> &all() const { return subscriptions_; }

  // Clause 8.2.2.3.9 step 6: a subscription is created (or replaced in its dialog).
  void add(const std::string &dialog, Subscription subscription);
  // RFC 6665 section 4.2.1.2: the subscription ends in its dialog (Expires 0), or its subscriber is gone.
  bool erase(const std::string &dialog);

  // Clause 8.2.2.3.10: the body of the subscription now; recorded as sent. Used for the NOTIFY that an accepted
  // SUBSCRIBE or a refresh always gets (RFC 6665 section 4.2.1.2).
  template <typename BodyOf> std::string current(const std::string &dialog, BodyOf &&body_of) {
    auto &subscription = subscriptions_.at(dialog);
    subscription.last_body = body_of(subscription);
    return subscription.last_body;
  }

  // Clause 8.2.2.3.10: each subscription whose body differs from the last one sent, with the new body (recorded as
  // sent); the others are left alone.
  template <typename BodyOf> std::vector<std::pair<std::string, std::string>> changed(BodyOf &&body_of) {
    std::vector<std::pair<std::string, std::string>> out;
    for (auto &[dialog, subscription] : subscriptions_) {
      auto body = body_of(subscription);
      if (body == subscription.last_body) continue;
      subscription.last_body = body;
      out.emplace_back(dialog, std::move(body));
    }
    return out;
  }

private:
  std::map<std::string, Subscription> subscriptions_;
};

} // namespace mcx
