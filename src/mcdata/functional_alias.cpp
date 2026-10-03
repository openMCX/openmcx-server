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
// TS 24.282 clauses 22.2.2.2.3 and 22.2.2.3.3: functional alias status change (clause 22.2.2.2.3 at the serving
// server with the checks of clause 22.2.2.3.3 at the owning server, performed together here). A
// nonzero Expires sets the user's active aliases to the listed ones; Expires 0
// deactivates them all. The owning-server checks answer the PUBLISH directly.
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
  auto change = functional_aliases_.change();
  for (auto &[alias, users] : change.next) std::erase(users, user.id);
  // TS 24.282 clause 22.2.2.3.3 steps 5 and 6: take-over needs <allow-takeover> and the user's
  // <allow-takeover-functional-alias-other-user>, read from the user's profile once the limit is reached.
  const AliasAdmissionRules rules{Service::mcdata, request.take_over, false, true, [&] {
                                    Json policy;
                                    try {
                                      policy = profile(user.id).value("mcdata", Json::object());
                                    } catch (const std::exception &) {
                                      policy = Json::object();
                                    }
                                    return policy.value("functional_alias_takeover", false);
                                  }};
  if (expires != "0")
    for (const auto &alias : request.aliases) {
      const auto definition = alias_definition(alias);
      // TS 24.282 clause 22.2.2.3.3 step 4 (unknown alias) and steps 4a to 6 (admission).
      if (!definition || AliasRegistry::admit(change, alias, user.id, *definition, rules) != AliasAdmission::Admitted)
        return reject(403, "", user.id, "functional-alias");
    }
  const auto taken = functional_aliases_.commit(std::move(change));
  for (const auto &[alias, previous] : taken)
    event("mcdata_functional_alias_taken_over", {{"alias", alias}, {"from", previous}, {"by", user.id}});
  event("mcdata_functional_alias_status", {{"user_id", user.id},
                                           {"active", expires == "0" ? std::vector<std::string>{} : request.aliases},
                                           {"take_over", request.take_over}});
  response.status_code = 200;
  response.headers = {{"Expires", expires}, {"SIP-ETag", random_id()}};
  return response;
}

} // namespace mcx
