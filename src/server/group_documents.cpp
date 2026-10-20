//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Group document subscriptions: the GMS subscription proxy function and the xcap-diff NOTIFYs (members of McServer).
//
// Specifications: TS 24.481 V19.3.0 (Rel-19), RFC 5875, RFC 6665.

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// Helper: the XCAP root URI of the group documents.
std::string McServer::xcap_root() const {
  return cfg_.at(svc_.name).value("xcap_root", cfg_.at("common").at("gms").get<std::string>() + "/xcap-root");
}

//------------------------------------------------------------------------------
// TS 24.481 clause 7.2.10.2: the groups a resource list names by the path of a group document addressed by a
// group ID; empty when it names other documents.
std::vector<std::string> McServer::subscribed_groups(const std::string &list) {
  std::vector<std::string> groups;
  std::vector<std::string> entries;
  try {
    entries = parse_xcap_resource_list(list);
  } catch (const std::exception &) {
    return {};
  }
  for (const auto &entry : entries) {
    const auto at = entry.find(groups_auid);
    if (at == std::string::npos) return {};
    auto group = entry.substr(at + std::string(groups_auid).size());
    if (const auto sel = group.find("/~~/"); sel != std::string::npos) group = group.substr(0, sel);
    // A malformed percent-encoding names no group: the list is refused like any other unknown document.
    const auto decoded = percent_decode(group);
    if (!decoded || decoded->empty()) return {};
    groups.push_back(*decoded);
  }
  return groups;
}

//------------------------------------------------------------------------------
// Helper: whether the GMS has the group.
bool McServer::group_exists(const std::string &group) {
  try {
    (void)group_profile(group);
    return true;
  } catch (const std::exception &) {
    return false;
  }
}

//------------------------------------------------------------------------------
// TS 24.481 clause 7.2.12.2: whether the identity may subscribe to the group document (a member of the group).
bool McServer::subscription_allowed(const std::string &group, const std::string &identity) {
  try {
    return member(group_profile(group), identity);
  } catch (const std::exception &) {
    return false;
  }
}

//------------------------------------------------------------------------------
// TS 24.481 clause 6.3.13.3.2.2 (from a GMC).
// server: an MCS server of this system (clauses 6.3.13.2.2 and 6.3.13.3.2.3), which may follow any group.
SipResponse McServer::doc_subscribe(const SipMessage &message, const std::string &identity,
                                    const std::vector<std::string> &groups, bool server) {
  SipResponse response;
  const auto expires = refreshed_expires(message);
  if (!expires || *expires > max_subscription_s || doc_subscriptions_.size() >= max_subscriptions || groups.empty() ||
      groups.size() > 16) {
    response.status_code = 400;
    return response;
  }
  DocSubscription sub;
  sub.subscriber = identity;
  sub.server = server;
  sub.expires = std::time(nullptr) + static_cast<std::int64_t>(*expires);
  for (const auto &group : groups) {
    // TS 24.481 clause 7.2.12.2: a member may subscribe to its group's document.
    if (!(server ? group_exists(group) : subscription_allowed(group, identity))) {
      docsub_count("refused");
      event("group_document_subscription_refused", {{"subscriber", identity}, {"group", group}});
      response.status_code = 403;
      return response;
    }
    sub.etags[group] = "";
  }
  doc_subscriptions_[message.dialog_id] = sub;
  docsub_count("subscriptions");
  event("group_document_subscription", {{"subscriber", identity}, {"groups", groups}});
  response.status_code = 200;
  response.headers = {{"Expires", std::to_string(*expires)}};
  schedule([this, id = message.dialog_id] { notify_documents(id); });
  return response;
}

//------------------------------------------------------------------------------
// TS 24.481 clause 6.2.5.1: whether the identity is in the authorized MCS server list.
bool McServer::is_mcs_server(const std::string &identity) const {
  const auto servers = cfg_.at(svc_.name).value("mcs_servers", std::vector<std::string>{});
  return !identity.empty() && std::find(servers.begin(), servers.end(), identity) != servers.end();
}

//------------------------------------------------------------------------------
// RFC 5875: the xcap-diff document of the changed group documents.
std::string McServer::xcap_diff(const std::string &root,
                                const std::vector<std::tuple<std::string, std::string, std::string>> &docs) {
  std::string out =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?><xcap-diff xmlns=\"urn:ietf:params:xml:ns:xcap-diff\" xcap-root=\"" +
      xml_escape(root) + "/\">";
  for (const auto &[group, previous, next] : docs) {
    out += "<document sel=\"" + xml_escape(std::string(groups_auid) + url_encode(group)) + "\"";
    if (!previous.empty()) out += " previous-etag=\"" + xml_escape(previous) + "\"";
    if (!next.empty()) out += " new-etag=\"" + xml_escape(next) + "\"";
    out += "/>";
  }
  return out + "</xcap-diff>";
}

//------------------------------------------------------------------------------
// TS 24.481 clause 6.3.13.3.2.2 and RFC 5875: a NOTIFY with the full state first, then each change.
void McServer::notify_documents(const std::string &dialog) {
  auto found = doc_subscriptions_.find(dialog);
  if (found == doc_subscriptions_.end() || found->second.pending) return;
  auto &sub = found->second;
  sub.next_poll = monotonic_ms() + cfg_.at(svc_.name).value("document_poll_ms", 2000u);
  const bool terminated = sub.expires <= std::time(nullptr);
  std::vector<std::tuple<std::string, std::string, std::string>> changes;
  if (!terminated)
    for (auto &[group, last] : sub.etags) {
      std::string current;
      bool exists = true;
      if (service_down("gms")) continue;
      const auto &common = cfg_.at("common");
      HttpResponse reply;
      try {
        reply = http_.request("GET", common.at("gms").get<std::string>() + "/internal/group?id=" + url_encode(group),
                              {}, {}, common.at("client_id"), common.at("secret"));
      } catch (const std::exception &) {
        // Status 0 stays: the GMS counts as failed below.
      }
      if (reply.status == 0 || reply.status >= 500) {
        service_failed("gms");
        continue;
      }
      if (reply.status == 404)
        exists = false;
      else if (reply.status != 200)
        continue;
      else
        current = reply.json().value("document_etag", std::string{});
      if (!exists) {
        if (!last.empty()) changes.emplace_back(group, last, ""); // the document was removed
        last.clear();
        continue;
      }
      if (current != last || sub.initial) {
        changes.emplace_back(group, sub.initial ? std::string{} : last, current);
        last = current;
      }
    }
  if (!terminated && changes.empty() && !sub.initial) return;
  sub.initial = false;
  sub.pending = true;
  sip_.notify(dialog, "xcap-diff",
              terminated ? "terminated;reason=timeout"
                         : "active;expires=" + std::to_string(sub.expires - std::time(nullptr)),
              "application/xcap-diff+xml", xcap_diff(xcap_root(), changes), {},
              [this, dialog, terminated](const SipResponse &response) {
                if (response.status_code < 200) return;
                schedule([this, dialog, terminated, status = response.status_code] {
                  auto it = doc_subscriptions_.find(dialog);
                  if (it == doc_subscriptions_.end()) return;
                  if (terminated || status >= 300)
                    end_doc_subscription(dialog);
                  else
                    it->second.pending = false;
                });
              });
  docsub_count("notifies");
  event("group_document_notify",
        {{"subscriber", sub.subscriber}, {"changes", changes.size()}, {"terminated", terminated}});
}

//------------------------------------------------------------------------------
// Helper: end a group document subscription.
void McServer::end_doc_subscription(const std::string &dialog) { doc_subscriptions_.erase(dialog); }

//------------------------------------------------------------------------------
// Helper: the periodic NOTIFYs of the group and configuration document subscriptions that are due.
void McServer::docsub_tick(std::uint64_t now) {
  std::vector<std::string> due;
  for (const auto &[dialog, sub] : doc_subscriptions_)
    if (!sub.pending && (now >= sub.next_poll || sub.expires <= std::time(nullptr))) due.push_back(dialog);
  for (const auto &dialog : due) notify_documents(dialog);
  due.clear();
  for (const auto &[dialog, sub] : config_subscriptions_)
    if (!sub.pending && (now >= sub.next_poll || sub.expires <= std::time(nullptr))) due.push_back(dialog);
  for (const auto &dialog : due) notify_configuration(dialog);
}

//------------------------------------------------------------------------------
// Helper: the status of the group document subscriptions: counters and subscriptions.
Json McServer::docsub_status() const {
  Json subs = Json::array();
  for (const auto &[dialog, sub] : doc_subscriptions_)
    subs.push_back({{"subscriber", sub.subscriber}, {"groups", sub.etags}});
  return {{"counters", docsub_counters_.json()}, {"subscriptions", subs}};
}

} // namespace mcx
