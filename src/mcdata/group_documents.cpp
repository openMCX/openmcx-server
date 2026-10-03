// Group documents: their retrieval from the GMS (TS 24.282 clause 6.3.3) and the subscription to their changes as
// an MCS server (TS 24.481 clause 6.3.13.2.2) (member functions of DataServer, declared in data_server.hpp).
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 24.481 V19.3.0 (Rel-19), IETF RFC 5875.

#include "data_server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.282 clause 6.3.3: the group document from the GMS; nullopt when the group does not exist. With
// mcdata.group_subscription_uri, the documents read are kept and subscribed to
// (TS 24.481 clause 6.3.13.2.2), and a notified change drops the kept copy.
std::optional<Json> DataServer::group_document(const std::string &group) {
  const bool subscribing = !cfg_.at("mcdata").value("group_subscription_uri", std::string{}).empty();
  const auto subscription = group_subscriptions_.find(group);
  const bool subscribed = subscription != group_subscriptions_.end() && subscription->second.active;
  if (subscribed)
    if (const auto kept = group_cache_.find(group); kept != group_cache_.end()) {
      ++group_docs_["hits"];
      return kept->second;
    }
  const auto &common = cfg_.at("common");
  const auto reply =
      http_.request("GET", common.at("gms").get<std::string>() + "/internal/group?id=" + url_encode(group), {}, {},
                    common.at("client_id"), common.at("secret"));
  if (reply.status == 404) return std::nullopt;
  if (reply.status != 200) throw std::runtime_error("group document unavailable");
  auto document = reply.json();
  if (subscribing) {
    ++group_docs_["reads"];
    if (subscribed)
      group_cache_[group] = document;
    else if (subscription == group_subscriptions_.end()) {
      group_subscriptions_[group];
      pending_.push_back([this, group] { subscribe_group_document(group); });
    }
  }
  return document;
}

//------------------------------------------------------------------------------
// TS 24.481 clause 6.3.13.2.2: the MCS server subscribes to the changes of one group document (SIP SUBSCRIBE
// for xcap-diff with the MCPTT ICSI and a resource list naming the document).
void DataServer::subscribe_group_document(const std::string &group) {
  const auto uri = cfg_.at("mcdata").value("group_subscription_uri", std::string{});
  if (uri.empty()) return;
  auto &sub = group_subscriptions_[group];
  sub.active = false;
  sub.refresh = monotonic_ms() + 3000000;
  ++group_docs_["subscriptions"];
  sub.dialog = sip_.subscribe(
      uri, "xcap-diff", 3600,
      {{"P-Asserted-Service", "urn:urn-7:3gpp-service.ims.icsi.mcptt"}, {"Accept", "application/xcap-diff+xml"}},
      [this, group](const SipResponse &response) {
        if (response.status_code < 200) return;
        pending_.push_back([this, group, status = response.status_code] {
          auto found = group_subscriptions_.find(group);
          if (found == group_subscriptions_.end()) return;
          found->second.active = status < 300;
          if (status >= 300) {
            group_cache_.erase(group);
            event("mcdata_group_subscription_failed", {{"group", group}, {"status", status}});
          }
        });
      },
      "application/resource-lists+xml",
      xcap_resource_list({"org.openmobilealliance.groups/global/byGroupID/" + url_encode(group)}));
  event("mcdata_group_subscription", {{"group", group}});
}

//------------------------------------------------------------------------------
// TS 24.481 clause 6.3.13.2.2 with RFC 5875: the notified documents changed (or were removed); their kept
// copies go.
std::optional<SipResponse> DataServer::group_documents_notified(const SipMessage &notify) {
  const auto found = std::find_if(group_subscriptions_.begin(), group_subscriptions_.end(),
                                  [&](const auto &entry) { return entry.second.dialog == notify.dialog_id; });
  if (found == group_subscriptions_.end()) return std::nullopt;
  SipResponse response;
  response.status_code = 200;
  const auto body = notify.parts.empty() ? notify.body : notify.parts.front().body;
  ++group_docs_["notifies"];
  for (std::size_t at = body.find("<document"); at != std::string::npos; at = body.find("<document", at + 1)) {
    const auto end = body.find("/>", at);
    const auto element = body.substr(at, end == std::string::npos ? std::string::npos : end - at);
    const auto sel = element.find("sel=\"");
    if (sel == std::string::npos) continue;
    const auto value = element.substr(sel + 5, element.find('"', sel + 5) - sel - 5);
    // A selector with a malformed percent-encoding names no group of ours (RFC 3986 section 2.1).
    const auto decoded = percent_decode(value.substr(value.rfind('/') + 1));
    if (!decoded) continue;
    const auto &group = *decoded;
    if (group_cache_.erase(group)) ++group_docs_["changes"];
    event("mcdata_group_document_changed",
          Json{{"group", group}, {"removed", element.find("new-etag") == std::string::npos}});
  }
  if (get_header(notify.headers, "Subscription-State").starts_with("terminated")) {
    found->second.active = false;
    group_cache_.erase(found->first);
  }
  return response;
}

} // namespace mcx
