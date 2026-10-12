//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Incoming SIP requests: the signalling and XML protection is removed and the request dispatched to its procedure.
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 23.282 V19.10.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19).

#include "data_server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.282 clauses 6.6.3.3 and 6.5.2.4 (TS 33.180 clause 9.5): a SIP request as received: the MCData signalling of a
// client is opened with its CSK, the protected XML is decrypted, and the XML of the answer is protected the same way.
SipResponse DataServer::incoming(const SipMessage &request) {
  // Only the SIP core is a trusted source (dispatch refuses any other).
  if (request.source_address != core_address_) return dispatch(request);
  const auto found = users_.find(asserted_identity(request));
  const auto *key = found != users_.end() ? signalling_key(found->first) : nullptr;
  const auto xml = found != users_.end() ? xml_key(found->first) : std::nullopt;
  if (!key && !xml) return dispatch(request);
  auto opened = request;
  try {
    auto parts = request.parts.empty() && !request.body.empty() ? parse_body_parts(request.content_type, request.body)
                                                                : request.parts;
    if (key) parts = open_from(*key, std::move(parts));
    try {
      parts = decrypt_xml(xml, std::move(parts));
    } catch (const std::exception &error) {
      // TS 24.282 clause 6.5.2.4.2 steps 1 and 3.
      ++xml_refused_;
      event("mcdata_xml_refused",
            {{"user_id", found->second.id}, {"method", request.method}, {"reason", error.what()}});
      SipResponse response;
      response.status_code = 403;
      response.headers = {{"Warning", warning_value("140 unable to decrypt XML content")}};
      return response;
    }
    opened.parts = std::move(parts);
    if (request.parts.empty() && opened.parts.size() == 1) opened.body = opened.parts.front().body;
  } catch (const std::exception &error) {
    ++signalling_refused_;
    event("mcdata_signalling_refused",
          {{"user_id", found->second.id}, {"method", request.method}, {"reason", error.what()}});
    SipResponse response;
    response.status_code = 403;
    return response;
  }
  auto response = dispatch(opened);

  // The XML of the answer is protected like any other sent to this client.
  if (xml && !response.parts.empty())
    response.parts = encrypt_xml(xml, std::move(response.parts));
  else if (xml && response.content_type == mcdata::info_mime && !response.body.empty())
    response.body = encrypt_xml(xml, {{std::string(mcdata::info_mime), response.body}}).front().body;
  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 6.3.1: a request, once opened, goes to the procedure its method, event package and target
// select.
SipResponse DataServer::dispatch(const SipMessage &request) {
  SipResponse response;
  response.status_code = 200;
  try {
    if (request.source_address != core_address_) {
      response.status_code = 403;
      return response;
    }
    if (request.method == "OPTIONS") return response;
    if (request.method == "NOTIFY" && get_header(request.headers, "Event") == "xcap-diff")
      if (auto notified = group_documents_notified(request)) return *notified;
    const auto event_name = std::string(get_header(request.headers, "Event"));
    if (request.method == "PUBLISH" && event_name == "poc-settings") return authorise(request);
    if (request.method == "INVITE") return media_invite(request); // TS 24.282 clauses 9.2.3 and 9.2.4: the media plane
    if (request.method == "BYE") {
      // Read before the disconnect is reported (TS 24.282 clause 13.2.2.2.4.3 step 3A).
      if (const auto reason = get_header(request.headers, "Reason"); !reason.empty())
        bye_reasons_[request.dialog_id] = std::string(reason);
      return response;
    }
    if (request.method == "INFO" && get_header(request.headers, "Info-Package") == mcdata::com_release_package)
      return com_release_info(request);
    if (request.method == "MESSAGE") {
      if (auto handled = location_.from_client(request)) return *handled;
      return message(request);
    }
    // A SUBSCRIBE or PUBLISH comes from a service authorised user, its asserted identity that of the request.
    const auto asserted = asserted_identity(request);
    const auto sender = [&]() -> User * {
      const auto found = users_.find(asserted);
      if (asserted != request.from_uri || found == users_.end() || found->second.expires <= std::time(nullptr))
        return nullptr;
      return &found->second;
    };
    if (request.method == "SUBSCRIBE") {
      auto *user = sender();
      if (!user)
        return reject(404, "141 user unknown to the participating function", asserted, "affiliation-subscription");
      if (event_name != "presence") {
        response.status_code = 489;
        return response;
      }
      // TS 24.282 clause 22.2.2.2.4: a subscription to the user's functional alias status (<request-type>
      // "functional-alias-status-determination"), initial or in its dialog.
      if (alias_subscriptions_.contains(request.dialog_id)) return alias_status_subscribe(request, *user);
      if (const auto *info_part = part(request, mcdata::info_mime); info_part && request.request_uri == service_uri_)
        if (mcdata::parse_info(info_part->body).request_type == "functional-alias-status-determination")
          return alias_status_subscribe(request, *user);
      // An initial SUBSCRIBE targets the PSI; an in-dialog one the server's contact.
      if (request.request_uri != service_uri_ && request.dialog_id != user->subscription)
        return reject(404, "", asserted, "affiliation-subscription");
      return affiliation_subscribe(request, *user);
    }
    if (request.method == "PUBLISH" && event_name == "presence") {
      auto *user = sender();
      if (!user) return reject(403, "", asserted, "affiliation");
      // A functional alias status change (TS 24.282 clause 22.2.2.2.3) or an affiliation (clause 8.3.2.3).
      for (const auto &body : request.parts)
        if (body.content_type == "application/pidf+xml" && is_functional_alias_pidf(body.body))
          return functional_alias_publish(request, *user, body);
      return affiliate(request, *user);
    }
    response.status_code = 405;
    return response;
  } catch (const std::exception &error) {
    event("mcdata_request_rejected", {{"method", request.method}, {"reason", error.what()}});
    response.status_code = 400;
    return response;
  }
}

} // namespace mcx
