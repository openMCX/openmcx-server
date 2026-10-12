//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The served users (src/server/parts/served_users.hpp): the lookup by MC service ID with each service's rule, the
// affiliation documents in each service's namespace and the list membership.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19).
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "parts/served_users.hpp"

#include <cassert>
#include <iostream>
using namespace mcx;

namespace {
//------------------------------------------------------------------------------
// TS 24.379 clause 7.3.3 step 5a, TS 24.282 clause 7.3.3 step 5a: the user bound to an MC service ID; MCData finds
// it only while its service authorisation lasts, the core whether it lasts or not.
void Clause_7_3_3_ByIdentity() {
  std::map<std::string, ServedUser> users;
  users["sip:a@x"].id = "alice";
  users["sip:a@x"].expires = std::time(nullptr) - 1;
  users["sip:b@x"].id = "bob";
  users["sip:b@x"].expires = std::time(nullptr) + 60;
  assert(served_by_id(users, "alice", false) == &users["sip:a@x"]);
  assert(served_by_id(users, "alice", true) == nullptr);
  assert(served_by_id(users, "bob", true) == &users["sip:b@x"]);
  assert(served_by_id(users, "carol", false) == nullptr);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.3.1, TS 24.281 clause 8.3.1, TS 24.282 clause 8.4.1: the affiliation document is in the
// service's namespace; the status lists every affiliated group (TS 24.379 clause 9.2.2.2.5, TS 24.282 clause
// 8.3.2.5).
void Clause_9_3_1_AffiliationDocuments() {
  const auto mcptt = service_affiliation(mcptt_service, "alice", "c1", "p1");
  const auto video = service_affiliation(mcvideo_service, "alice", "c1", "p1");
  const auto data = service_affiliation(mcdata_service, "alice", "c1", "p1");
  assert(!mcptt.mcvideo && !mcptt.mcdata && video.mcvideo && !video.mcdata && data.mcdata && !data.mcvideo);
  assert(data.user_id == "alice" && data.client_id == "c1" && data.publication_id == "p1");
  ServedUser user;
  user.id = "alice";
  user.client = "c1";
  user.groups = {"g1", "g2"};
  const auto status = affiliation_status(mcdata_service, user, "p2");
  assert(status.groups == std::vector<std::string>({"g1", "g2"}));
  assert(status.statuses == std::vector<std::string>({"affiliated", "affiliated"}) && status.publication_id == "p2");
  assert(parse_affiliation(affiliation_xml(status, true)).mcdata);
}

//------------------------------------------------------------------------------
// Helper: a JSON list names an ID only as a string entry; anything else names nobody.
void Listed() {
  assert(listed(Json::array({"alice", 3}), "alice") && !listed(Json::array({3}), "3"));
  assert(!listed(Json::object(), "alice") && !listed(Json(), "alice"));
}
} // namespace

//------------------------------------------------------------------------------
int main() {
  Clause_7_3_3_ByIdentity();
  Clause_9_3_1_AffiliationDocuments();
  Listed();
  std::cout << "served_users: all checks passed\n";
}
