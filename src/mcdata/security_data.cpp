//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Interworking Security Data (TS 29.582 clause 17.4; TS 23.283 clause 10.12.1.1, the Non-3GPP security message): an
// opaque LMR security payload between an MCData client and an interworking function (a peer, such as a TETRA IWF
// carrying the key management messages of TS 100 392-19-1 clause 13.4.3), through this server as the collocated
// originating participating (clause 17.4.2.1), controlling (clauses 17.4.3.2, 17.4.3.1) and terminating participating
// (clause 17.4.2.2) functions.
//
// Clauses 17.4.3.1 step 4 and 17.4.3.2 step 2 name the mcdata-signalling and mcdata-payload bodies, which an
// Interworking Security Data request does not have (clauses 17.2, 17.3.1 step 7): they are read as the
// interworking-data body (maintainer decision, as the TETRA IWF reads them).
//
// Specifications: TS 29.582 V19.0.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), TS 23.283 V19.5.0 (Rel-19).

#include "data_server.hpp"

namespace mcx {

namespace {

//------------------------------------------------------------------------------
// TS 29.582 clauses 17.4.3.1 steps 2, 3 and 8 and 17.4.2.2 step 5: the MCData feature tag and ICSI.
std::vector<SipHeader> security_data_headers() {
  return {{"Accept-Contact", "*;+g.3gpp.mcdata;require;explicit"},
          {"Accept-Contact", "*;+g.3gpp.icsi-ref=\"" + url_encode(mcdata::icsi) + "\";require;explicit"},
          {"P-Asserted-Service", mcdata::icsi}};
}

} // namespace

//------------------------------------------------------------------------------
// TS 29.582 clause 17.4.2.1 (a client's request, the binding checked by message(): steps 2 and 3) with the
// collocated controlling function, clause 17.4.3.2, and its delivery, clause 17.4.3.1: 202 (Accepted) once sent.
SipResponse DataServer::security_data(const SipMessage &request, const User &sender) {
  const char *what = "interworking-security-data";
  // Clause 17.4.1.1: the MCData ICSI in Accept-Contact.
  if (!accepts(request, mcdata::icsi)) return reject(403, "", sender.id, what);
  // Clause 17.3.1 sends no mcdata-info: this function adds it (clause 17.4.2.1 step 12), so the controlling function
  // finds it (clause 17.4.3.2 step 2 a); the interworking-data body is required (step 2, as read above) and decoded
  // (step 3).
  const auto *info_part = part(request, mcdata::info_mime);
  const auto *data_part = part(request, mcdata::interworking_data_mime);
  if (!data_part) return reject(403, "199 expected MIME bodies not in the request", sender.id, what);
  mcdata::Info info = info_part ? mcdata::parse_info(info_part->body) : mcdata::Info{};
  mcdata::InterworkingSecurityData body;
  try {
    body = mcdata::decode_interworking_security_data(data_part->body);
  } catch (const std::exception &) {
    return reject(400, "", sender.id, what);
  }
  // NOTE 2 of clause 17.4.2.1: the payload size is the Payload contents less the content type octet.
  const auto size = body.payload.size();
  Json policy;
  try {
    policy = profile(sender.id).value("mcdata", Json::object());
  } catch (const std::exception &) {
    policy = Json::object();
  }
  // Clause 17.4.2.1 steps 6 and 7 (TS 24.282 clause 11.1 steps 1, 1A and 7) and step 8.
  if (!policy.is_object() || !policy.value("transmit_data", false))
    return reject(403, "200 user not authorised to transmit data", sender.id, what);
  if (const auto max = limit(policy, "max_data_1to1"); max && size > max)
    return reject(403,
                  "202 user not authorised for one-to-one MCData communications due to exceeding the maximum amount "
                  "of data that can be sent in a single request",
                  sender.id, what);
  // Clause 17.4.3.2 step 5: exactly one <entry>, the targeted user.
  std::string target;
  if (const auto *resources = part(request, resource_lists_mime)) try {
      target = parse_private_call_target(resources->body);
    } catch (const std::exception &) {
      target.clear();
    }
  if (target.empty())
    return reject(403, "250 unable to determine targeted user for one-to-one message", sender.id, what);
  if (policy.contains("targets") && !policy.at("targets").empty() && !listed(policy.at("targets"), target))
    return reject(403, "229 one-to-one MCData communication not authorised to the targeted user", sender.id, what);
  if (const auto max = limit(cfg_.at("mcdata"), "max_payload_size_sds_cplane_bytes"); max && size > max)
    return reject(403, "203 message too large to send over signalling control plane", sender.id, what);
  // Clause 17.4.3.2 step 4 (TS 24.282 clause 11.1 step 3).
  if (const auto max = limit(cfg_.at("mcdata"), "max_data_size_sds_bytes"); max && size > max)
    return reject(403, "249 user not authorised for one-to-one message due to message size", sender.id, what);
  auto *callee = by_id(target);
  if (!callee) return reject(404, "", sender.id, what);
  // Clause 17.4.2.1 step 12 and clause 17.4.3.1 step 5: the calling user and the target in the mcdata-info.
  info.calling_user = sender.id;
  info.request_uri = target;
  info.client_id.clear();
  info.access_token.clear();
  if (callee->peer.empty()) {
    // Clause 17.4.2.2 for a user served here.
    if (auto refused = security_data_to_user(*callee, info, data_part->body)) return *refused;
  } else {
    // Clause 17.4.3.1 steps 6 and 7: to the terminating participating function, the peer, with the calling user's
    // public user identity asserted.
    const auto [type, payload] = message_body(
        {{mcdata::info_mime, mcdata::info_xml(info)}, {mcdata::interworking_data_mime, data_part->body}},
        "mcdata-" + random_id());
    auto headers = security_data_headers();
    headers.push_back({"P-Asserted-Identity", "<" + sender.sip + ">"});
    sip_.request("MESSAGE", peers_.at(callee->peer).service_uri, type, payload,
                 peer_route(peers_, callee->peer, std::move(headers)),
                 [id = sender.id, target](const SipResponse &response) {
                   if (response.status_code < 200) return;
                   event("mcdata_security_data_result",
                         {{"user_id", id},
                          {"target", target},
                          {"status", response.status_code},
                          {"warning", std::string(get_header(response.headers, "Warning"))}});
                 });
  }
  count("security_data");
  event("mcdata_security_data_relayed", {{"user_id", sender.id},
                                         {"target", target},
                                         {"server", callee->peer},
                                         {"payload_bytes", size},
                                         {"network", body.network ? static_cast<int>(*body.network) : 0}});
  SipResponse response;
  response.status_code = 202; // clause 17.4.3.2 steps 7 and 8
  response.reason = "Accepted";
  return response;
}

//------------------------------------------------------------------------------
// TS 29.582 clause 17.4.2.2 steps 3a to 6: the incoming list of the terminating user, then the SIP MESSAGE to its
// client (TS 24.282 clause 6.3.2.1: from this server, its PSI asserted) with the MCData ICSI; its answer is logged
// (the controlling function collocated here has answered already). A refusal, or nothing once sent.
std::optional<SipResponse> DataServer::security_data_to_user(const User &target, const mcdata::Info &info,
                                                             const std::string &data) {
  const char *what = "interworking-security-data";
  Json callee_policy;
  try {
    callee_policy = profile(target.id).value("mcdata", Json::object());
  } catch (const std::exception &) {
    return reject(404, "", target.id, what);
  }
  if (callee_policy.is_object() && callee_policy.contains("incoming_from") &&
      !callee_policy.at("incoming_from").empty() && !callee_policy.value("incoming_any", false) &&
      !listed(callee_policy.at("incoming_from"), info.calling_user))
    return reject(403, "230 one-to-one MCData communication not authorised from this originating user", target.id,
                  what);
  std::vector<BodyPart> parts{{mcdata::info_mime, mcdata::info_xml(info)}, {mcdata::interworking_data_mime, data}};
  try {
    parts = seal_for(target.sip, std::move(parts));
  } catch (const CskExpired &error) {
    csk_expired_not_sent(target.id, "message", error); // TS 33.180 annex E.6.10: never in the clear
    return reject(480, "", target.id, what);
  }
  const auto [type, body] = message_body(parts, "mcdata-" + random_id());
  sip_.request("MESSAGE", target.sip, type, body, security_data_headers(), [id = target.id](const SipResponse &response) {
    if (response.status_code < 200) return;
    event("mcdata_security_data_delivered", {{"user_id", id}, {"status", response.status_code}});
  });
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 29.582 clause 17.4.2.2 for a peer's request (the peer, an IWF, originating towards the terminating participating
// function, clause 17.1.1 step 6): the user named in <mcdata-request-uri> (steps 2, 3: 404), its incoming list (step
// 3a), the MESSAGE to its client (steps 4 to 6, from this server as TS 24.282 clause 6.3.2.1 has it); the client's
// final answer passed back to the peer.
SipResponse DataServer::peer_security_data(const SipMessage &request, const std::string &peer) {
  const char *what = "interworking-security-data";
  if (get_header(request.headers, "P-Asserted-Service") != mcdata::icsi) return reject(403, "", {}, what);
  const auto *info_part = part(request, mcdata::info_mime);
  const auto *data_part = part(request, mcdata::interworking_data_mime);
  if (!info_part || !data_part) return reject(403, "199 expected MIME bodies not in the request", {}, what);
  const auto info = mcdata::parse_info(info_part->body);
  auto *target = by_id(info.request_uri);
  if (!target || !target->peer.empty()) return reject(404, "", info.request_uri, what);
  try {
    static_cast<void>(mcdata::decode_interworking_security_data(data_part->body));
  } catch (const std::exception &) {
    return reject(400, "", target->id, what);
  }
  Json callee_policy;
  try {
    callee_policy = profile(target->id).value("mcdata", Json::object());
  } catch (const std::exception &) {
    return reject(404, "", target->id, what);
  }
  if (callee_policy.is_object() && callee_policy.contains("incoming_from") &&
      !callee_policy.at("incoming_from").empty() && !callee_policy.value("incoming_any", false) &&
      !listed(callee_policy.at("incoming_from"), info.calling_user))
    return reject(403, "230 one-to-one MCData communication not authorised from this originating user", target->id,
                  what);
  std::vector<BodyPart> parts{{mcdata::info_mime, mcdata::info_xml(info)},
                              {mcdata::interworking_data_mime, data_part->body}};
  try {
    parts = seal_for(target->sip, std::move(parts));
  } catch (const CskExpired &error) {
    csk_expired_not_sent(target->id, "message", error);
    return reject(480, "", target->id, what);
  }
  const auto [type, body] = message_body(parts, "mcdata-" + random_id());
  const auto transaction = request.transaction_id;
  sip_.request("MESSAGE", target->sip, type, body, security_data_headers(),
               [this, transaction, id = target->id, peer](const SipResponse &answer) {
                 if (answer.status_code < 200) return;
                 // Clause 17.4.2.2: the 200, or the 4xx to 6xx with its Warning header fields, to the peer.
                 SipResponse reply;
                 reply.status_code = answer.status_code;
                 reply.reason = answer.reason;
                 if (const auto warning = get_header(answer.headers, "Warning"); !warning.empty())
                   reply.headers = {{"Warning", std::string(warning)}};
                 pending_.push_back([this, transaction, reply] { sip_.respond(transaction, reply); });
                 event("mcdata_peer_security_data_answer",
                       {{"user_id", id}, {"server", peer}, {"status", answer.status_code}});
               });
  event("mcdata_peer_security_data", {{"user_id", target->id}, {"server", peer}, {"from", info.calling_user}});
  SipResponse response;
  response.deferred = true;
  return response;
}

} // namespace mcx
