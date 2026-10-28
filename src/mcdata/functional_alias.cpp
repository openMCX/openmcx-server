//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Functional aliases: activation, deactivation and resolution at the combined serving and owning MCData server
// (TS 24.282 clause 22.2.2), and the MCData user profile and functional alias definitions read from the CMS
// (member functions of DataServer, declared in data_server.hpp).
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19).

#include "data_server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// Helper: the MCData user profile (TS 24.484) subset served by the CMS (see MCDataPolicy in the CMS).
Json DataServer::profile(const std::string &mcdata_id) {
  const auto user = internal("cms", "/internal/user?mcdata_id=" + url_encode(mcdata_id));
  if (user.value("mcdata_id", "") != mcdata_id) throw std::runtime_error("MCData user profile unavailable");
  return user;
}

//------------------------------------------------------------------------------
// Helper: the functional alias definition from the CMS; nullopt when the alias does not exist.
std::optional<Json> DataServer::alias_definition(const std::string &alias) {
  const auto &common = cfg_.at("common");
  const auto reply =
      http_.request("GET", common.at("cms").get<std::string>() + "/internal/functional-alias?id=" + url_encode(alias),
                    {}, {}, common.at("client_id"), common.at("secret"));
  if (reply.status == 404) return std::nullopt;
  if (reply.status != 200) throw std::runtime_error("functional alias definition unavailable");
  return reply.json();
}

//------------------------------------------------------------------------------
// TS 24.282 clause 22.2.2.2.3 at the combined serving and owning server: the participating checks answer the PUBLISH
// with a refusal (step 4: 403, step 5: 423); past them it is answered 200 (step 8), and each alias is decided as the
// owning server does (clause 22.2.2.3.3 steps 4 to 6). A nonzero Expires sets the user's active aliases to the listed
// ones that pass (step 12: the others are deactivated), Expires 0 deactivates them all (step 13). The user learns the
// outcome from the NOTIFY of its status subscription with the handled p-id-fa (steps 16 and 17, clause 22.2.2.2.5):
// an activated alias is listed "activated", one at its limit the user may take over "take-over-possible" (TS 24.282
// clause 3.1), a refused one is left out.
SipResponse DataServer::functional_alias_publish(const SipMessage &received, User &user, const BodyPart &pidf) {
  SipResponse response;
  const auto *info_part = part(received, mcdata::info_mime);
  if (!info_part || mcdata::parse_info(info_part->body).request_uri != user.id)
    return reject(403, "", user.id, "functional-alias");
  const auto request = parse_functional_alias(pidf.body);
  if (!request.mcdata || request.user_id != user.id || request.client_id != user.client)
    return reject(403, "", user.id, "functional-alias");
  const auto expires = std::string(get_header(received.headers, "Expires"));
  if (expires != "0" && expires != "4294967295") {
    response.status_code = 423; // TS 24.282 clause 22.2.2.2.3 step 5
    response.headers = {{"Min-Expires", "4294967295"}};
    return response;
  }
  const auto may_take_over = [&] {
    try {
      return profile(user.id).value("mcdata", Json::object()).value("functional_alias_takeover", false);
    } catch (const std::exception &) {
      return false;
    }
  };
  auto change = functional_aliases_.change();
  // Steps 12 b and 13: the aliases the user holds and this PUBLISH does not keep are deactivated; one listed again
  // stays as it is, in its place among the alias's activations (step 12 a).
  std::set<std::string> before;
  for (auto &[alias, users] : change.next)
    if (std::find(users.begin(), users.end(), user.id) != users.end()) before.insert(alias);
  for (const auto &alias : before)
    if (expires == "0" || std::find(request.aliases.begin(), request.aliases.end(), alias) == request.aliases.end())
      std::erase(change.next[alias], user.id);

  // TS 24.282 clause 22.2.2.3.3 steps 5 and 6: take-over needs <allow-takeover> and the user's
  // <allow-takeover-functional-alias-other-user>, read from the user's profile once the limit is reached.
  const AliasAdmissionRules rules{Service::mcdata, request.take_over, true, true, may_take_over};
  std::map<std::string, std::string> outcomes;
  if (expires != "0")
    for (const auto &alias : request.aliases) {
      const auto definition = alias_definition(alias);
      // TS 24.282 clause 22.2.2.3.3 step 4 (unknown alias) and steps 4a to 6 (admission).
      const auto admission =
          definition ? AliasRegistry::admit(change, alias, user.id, *definition, rules) : AliasAdmission::NotListed;
      if (admission == AliasAdmission::Admitted) {
        outcomes[alias] = "activated";
        continue;
      }
      const bool possible = admission == AliasAdmission::LimitReached && !request.take_over &&
                            definition->value("allow_takeover", false) && may_take_over();
      outcomes[alias] = possible ? "take-over-possible" : "refused";
    }
  for (const auto &alias : before)
    if (!outcomes.contains(alias)) outcomes[alias] = "deactivated";
  const auto taken = functional_aliases_.commit(std::move(change));
  std::set<std::string> changed{user.id};
  for (const auto &[alias, previous] : taken) {
    changed.insert(previous);
    event("mcdata_functional_alias_taken_over", {{"alias", alias}, {"from", previous}, {"by", user.id}});
  }
  auto &possible = alias_takeover_possible_[user.id];
  possible.clear();
  for (const auto &[alias, outcome] : outcomes)
    if (outcome == "take-over-possible") possible.insert(alias);
  if (possible.empty()) alias_takeover_possible_.erase(user.id);
  std::vector<std::string> active;
  for (const auto &[alias, outcome] : outcomes)
    if (outcome == "activated") active.push_back(alias);
  event("mcdata_functional_alias_status",
        {{"user_id", user.id}, {"active", active}, {"take_over", request.take_over}, {"outcomes", outcomes}});
  pending_.push_back([this, changed, publisher = user.id, pid = request.publish_id] {
    for (const auto &id : changed) notify_alias_status(id, id == publisher ? pid : std::string{});
  });
  response.status_code = 200; // step 8
  response.headers = {{"Expires", expires}, {"SIP-ETag", random_id()}};

  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 22.2.2.2.4: a subscription to the served MCData ID's functional alias status (<request-type>
// "functional-alias-status-determination"): only the user's own (step 4), 200 (step 5) and the NOTIFY of the status;
// Expires 0 fetches it once or ends the subscription in its dialog.
SipResponse DataServer::alias_status_subscribe(const SipMessage &request, User &subscriber) {
  SipResponse response;
  const bool in_dialog = alias_subscriptions_.contains(request.dialog_id);
  if (!in_dialog) {
    const auto *info_part = part(request, mcdata::info_mime);
    if (!info_part || mcdata::parse_info(info_part->body).request_uri != subscriber.id)
      return reject(403, "", subscriber.id, "functional-alias-subscription");
  } else if (alias_subscriptions_.at(request.dialog_id) != subscriber.id) {
    return reject(403, "", subscriber.id, "functional-alias-subscription");
  }
  const bool ended = get_header(request.headers, "Expires") == "0";
  response.status_code = 200;
  response.headers = {{"Expires", ended ? "0" : "4294967295"}};
  alias_subscriptions_[request.dialog_id] = subscriber.id;
  event(ended ? "mcdata_functional_alias_unsubscribed" : "mcdata_functional_alias_subscribed",
        {{"user_id", subscriber.id}});
  pending_.push_back([this, dialog = request.dialog_id, ended] { notify_alias_dialog(dialog, {}, ended); });
  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 22.2.2.2.5: the NOTIFY of a user's functional alias status to each of its subscriptions; the
// handled p-id-fa when a status change of the user caused it.
void DataServer::notify_alias_status(const std::string &id, const std::string &publish_id) {
  std::vector<std::string> dialogs;
  for (const auto &[dialog, subscriber] : alias_subscriptions_)
    if (subscriber == id) dialogs.push_back(dialog);
  for (const auto &dialog : dialogs) notify_alias_dialog(dialog, publish_id, false);
}

//------------------------------------------------------------------------------
// TS 24.282 clause 22.2.2.2.5 with the syntax of clause 22.3.1.2: the per-user status on one subscription: the
// activated aliases and those the user may take over; XML-protected like the affiliation status (TS 24.282 clause
// 4.11). A final NOTIFY ends the subscription.
void DataServer::notify_alias_dialog(const std::string &dialog, const std::string &publish_id, bool ended) {
  const auto found = alias_subscriptions_.find(dialog);
  if (found == alias_subscriptions_.end()) return;
  const auto id = found->second;
  const auto *user = by_id(id);
  FunctionalAliasStatus status;
  status.mcdata = true;
  status.entity = id;
  status.tuple_id = user && !user->client.empty() ? user->client : id;
  status.publish_id = publish_id;
  for (const auto &[alias, users] : functional_aliases_.activations())
    if (std::find(users.begin(), users.end(), id) != users.end())
      status.entries.push_back({alias, {}, "activated", {}});
  if (const auto possible = alias_takeover_possible_.find(id); possible != alias_takeover_possible_.end())
    for (const auto &alias : possible->second)
      if (!functional_aliases_.active(alias, id)) status.entries.push_back({alias, {}, "take-over-possible", {}});
  const auto body = functional_alias_status_xml(status);
  if (user) {
    try {
      require_csk_in_use(user->sip, {{"application/pidf+xml", body}});
    } catch (const CskExpired &error) {
      // TS 33.180 annex E.6.10: the subscriber's CSK may no longer be used: this NOTIFY is not sent.
      return csk_expired_not_sent(id, "functional alias notification", error);
    }
  }
  sip_.notify(dialog, "presence", ended ? "terminated;reason=timeout" : "active", "application/pidf+xml",
              user ? encrypt_xml(xml_key(user->sip), {{"application/pidf+xml", body}}).front().body : body);
  event("mcdata_functional_alias_notified",
        {{"user_id", id}, {"entries", status.entries.size()}, {"p_id_fa", publish_id}, {"terminated", ended}});
  if (ended) alias_subscriptions_.erase(dialog);
}

//------------------------------------------------------------------------------
// TS 24.282 clause 22.2.2.3.6: the functional aliases of a user who logs off or whose authorisation expires are
// deactivated, and its status subscriptions end with it.
void DataServer::deactivate_aliases(const std::string &id) {
  functional_aliases_.deactivate(id);
  alias_takeover_possible_.erase(id);
  std::erase_if(alias_subscriptions_, [&](const auto &entry) { return entry.second == id; });
}

} // namespace mcx
