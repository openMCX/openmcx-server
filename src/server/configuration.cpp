//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Configuration management document subscriptions of users (CMS subscription function): one subscription to several
// documents (the UE configuration, user profile and service configuration documents), and the document subscription
// status (members of McServer).
//
// Specifications: TS 24.484 V19.6.0 (Rel-19), RFC 5875, TS 37.579-1 V18.1.0 (Rel-18) table 5.3.2.6.1-1.

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.484 clause 6.3.13.3.2.2 step e: the configuration management documents a resource list names (at most
// max_config_documents); empty when an entry names no configuration management document (config_document_reference).
std::vector<ConfigDocument> McServer::subscribed_configuration(const std::string &list) {
  std::vector<std::string> entries;
  try {
    entries = parse_xcap_resource_list(list);
  } catch (const std::exception &) {
    return {};
  }
  std::vector<ConfigDocument> documents;
  for (const auto &entry : entries) {
    auto document = config_document_reference(entry);
    if (!document || documents.size() >= max_config_documents) return {};
    documents.push_back(std::move(*document));
  }
  return documents;
}

//------------------------------------------------------------------------------
// TS 24.484 clause 6.3.13.3.2.2 step d: of the listed documents, those the authenticated identity may follow: the
// documents of its own directory in the users tree and the documents of the global tree (the service configuration
// documents every MC service user reads, clause 8.4.2.9); a document of another user is left out. The entity tags
// already notified in the current subscription are kept.
std::map<std::tuple<std::string, std::string, std::string>, std::string>
McServer::followed_configuration(const std::string &identity, const std::vector<ConfigDocument> &documents,
                                 const ConfigSubscription *current) {
  std::map<std::tuple<std::string, std::string, std::string>, std::string> etags;
  for (const auto &document : documents) {
    if (!document.xui.empty() && document.xui != identity) {
      configsub_counters_.add("refused");
      event("configuration_subscription_refused",
            {{"subscriber", identity}, {"auid", document.auid}, {"xui", document.xui}});
      continue;
    }
    const auto key = std::make_tuple(document.auid, document.xui, document.document);
    std::string etag;
    if (current)
      if (const auto kept = current->etags.find(key); kept != current->etags.end()) etag = kept->second;
    etags[key] = etag;
  }
  return etags;
}

//------------------------------------------------------------------------------
// TS 24.484 clause 6.3.13.3.2.2 steps d and e: one subscription to several configuration management documents; 403
// when the identity may follow none of them.
SipResponse McServer::config_subscribe(const SipMessage &message, const std::string &identity,
                                       const std::vector<ConfigDocument> &documents) {
  SipResponse response;
  const auto expires = refreshed_expires(message);
  if (!expires || *expires > max_subscription_s || config_subscriptions_.size() >= max_subscriptions) {
    response.status_code = 400;
    return response;
  }
  ConfigSubscription sub;
  sub.subscriber = identity;
  sub.expires = std::time(nullptr) + static_cast<std::int64_t>(*expires);
  sub.etags = followed_configuration(identity, documents, nullptr);
  if (sub.etags.empty()) {
    response.status_code = 403;
    return response;
  }
  Json followed = Json::array();
  for (const auto &[key, etag] : sub.etags) followed.push_back(std::get<0>(key) + "/" + std::get<2>(key));
  config_subscriptions_[message.dialog_id] = sub;
  configsub_counters_.add("subscriptions");
  event("configuration_subscription", {{"subscriber", identity}, {"documents", followed}});
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
    for (auto &[key, last] : sub.etags) {
      const auto &[auid, xui, name] = key;
      const auto &common = cfg_.at("common");
      HttpResponse reply;
      try {
        reply = http_.request("GET",
                              common.at("cms").get<std::string>() + "/internal/configuration-document?auid=" +
                                  url_encode(auid) + "&xui=" + url_encode(xui) + "&document=" + url_encode(name),
                              {}, {}, common.at("client_id"), common.at("secret"));
      } catch (const std::exception &) {
        // Status 0 stays: the CMS counts as failed below.
      }
      if (reply.status == 0 || reply.status >= 500) {
        service_failed("cms");
        break;
      }
      // A document the CMS does not have is not reported.
      if (reply.status != 200) continue;
      const auto current = reply.json().value("document_etag", std::string{});
      if (current != last || sub.initial) {
        // RFC 5875 section 4.1: the document's path relative to the XCAP root; a user profile under the name of
        // the profile in use.
        const auto document = reply.json().value("document", name);
        const auto sel = auid + (xui.empty() ? "/global/" : "/users/" + url_encode(xui) + "/") + url_encode(document);
        changes.emplace_back(sel, sub.initial ? std::string{} : last, current);
        last = current;
      }
    }
  if (!terminated && changes.empty() && !sub.initial) return;
  sub.initial = false;
  sub.pending = true;
  std::string body =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?><xcap-diff xmlns=\"urn:ietf:params:xml:ns:xcap-diff\" xcap-root=\"" +
      xml_escape(cfg_.at("common").at("cms").get<std::string>() + "/xcap-root") + "/\">";
  for (const auto &[sel, previous, next] : changes) {
    body += "<document sel=\"" + xml_escape(sel) + "\"";
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
