// Configuration management document subscriptions of users (CMS subscription function) and the document
// subscription status (members of McServer).
//
// Specifications: TS 24.484 V19.6.0 (Rel-19), RFC 5875.

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.484 clause 6.3.13.3.2.2 step e: the MCPTT IDs of the user profile documents a resource list names;
// empty when an entry is not a user profile document.
std::vector<std::string> McServer::subscribed_profiles(const std::string &list) {
  std::vector<std::string> ids;
  std::vector<std::string> entries;
  try {
    entries = parse_xcap_resource_list(list);
  } catch (const std::exception &) {
    return {};
  }
  for (const auto &entry : entries) {
    const auto at = entry.find(profile_auid);
    const auto end = entry.rfind("/index");
    if (at == std::string::npos || end == std::string::npos || end <= at) return {};
    const auto id = percent_decode(
        entry.substr(at + std::string(profile_auid).size(), end - at - std::string(profile_auid).size()));
    if (!id || id->empty()) return {};
    ids.push_back(*id);
  }
  return ids;
}

//------------------------------------------------------------------------------
// TS 24.484 clause 6.3.13.3.2.2 step d: a user may follow its own configuration documents only.
SipResponse McServer::config_subscribe(const SipMessage &message, const std::string &identity,
                                       const std::vector<std::string> &ids) {
  SipResponse response;
  const auto expires = refreshed_expires(message);
  if (!expires || *expires > max_subscription_s || config_subscriptions_.size() >= max_subscriptions ||
      ids.size() > 4) {
    response.status_code = 400;
    return response;
  }
  ConfigSubscription sub;
  sub.subscriber = identity;
  sub.expires = std::time(nullptr) + static_cast<std::int64_t>(*expires);
  for (const auto &id : ids) {
    if (id != identity) {
      configsub_counters_.add("refused");
      event("configuration_subscription_refused", {{"subscriber", identity}, {"profile", id}});
      response.status_code = 403;
      return response;
    }
    sub.etags[id] = "";
  }
  config_subscriptions_[message.dialog_id] = sub;
  configsub_counters_.add("subscriptions");
  event("configuration_subscription", {{"subscriber", identity}, {"profiles", ids}});
  response.status_code = 200;
  response.headers = {{"Expires", std::to_string(*expires)}};
  schedule([this, id = message.dialog_id] { notify_configuration(id); });
  return response;
}

//------------------------------------------------------------------------------
// TS 24.484 clause 6.3.13.3.2.2 step e and RFC 5875: the full state first, then each change of a document's
// entity tag.
void McServer::notify_configuration(const std::string &dialog) {
  auto found = config_subscriptions_.find(dialog);
  if (found == config_subscriptions_.end() || found->second.pending) return;
  auto &sub = found->second;
  sub.next_poll = monotonic_ms() + cfg_.at(svc_.name).value("configuration_poll_ms", 5000u);
  const bool terminated = sub.expires <= std::time(nullptr);
  std::vector<std::tuple<std::string, std::string, std::string>> changes;
  if (!terminated && !service_down("cms"))
    for (auto &[id, last] : sub.etags) {
      const auto &common = cfg_.at("common");
      HttpResponse reply;
      try {
        reply = http_.request("GET",
                              common.at("cms").get<std::string>() + "/internal/user-profile?mcptt_id=" + url_encode(id),
                              {}, {}, common.at("client_id"), common.at("secret"));
      } catch (const std::exception &) {
        // Status 0 stays: the CMS counts as failed below.
      }
      if (reply.status == 0 || reply.status >= 500) {
        service_failed("cms");
        break;
      }
      if (reply.status != 200) continue;
      const auto current = reply.json().value("document_etag", std::string{});
      if (current != last || sub.initial) {
        changes.emplace_back(id, sub.initial ? std::string{} : last, current);
        last = current;
      }
    }
  if (!terminated && changes.empty() && !sub.initial) return;
  sub.initial = false;
  sub.pending = true;
  std::string body =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?><xcap-diff xmlns=\"urn:ietf:params:xml:ns:xcap-diff\" xcap-root=\"" +
      xml_escape(cfg_.at("common").at("cms").get<std::string>() + "/xcap-root") + "/\">";
  for (const auto &[id, previous, next] : changes) {
    body += "<document sel=\"" + xml_escape(std::string(profile_auid) + url_encode(id) + "/index") + "\"";
    if (!previous.empty()) body += " previous-etag=\"" + xml_escape(previous) + "\"";
    if (!next.empty()) body += " new-etag=\"" + xml_escape(next) + "\"";
    body += "/>";
  }
  body += "</xcap-diff>";
  sip_.notify(dialog, "xcap-diff",
              terminated ? "terminated;reason=timeout"
                         : "active;expires=" + std::to_string(sub.expires - std::time(nullptr)),
              "application/xcap-diff+xml", body, {}, [this, dialog, terminated](const SipResponse &response) {
                if (response.status_code < 200) return;
                schedule([this, dialog, terminated, status = response.status_code] {
                  auto it = config_subscriptions_.find(dialog);
                  if (it == config_subscriptions_.end()) return;
                  if (terminated || status >= 300)
                    config_subscriptions_.erase(it);
                  else
                    it->second.pending = false;
                });
              });
  configsub_counters_.add("notifies");
  event("configuration_notify",
        {{"subscriber", sub.subscriber}, {"changes", changes.size()}, {"terminated", terminated}});
}

} // namespace mcx
