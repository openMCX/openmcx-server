//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The MCData server's decisions of src/mcdata/media_rules.hpp: a service authorisation that uploads a new CSK is not
// opened with the old one, the MSRP status of a standalone SDS over the media plane against its size limits, and the
// release that waits for the invited client's answer to a one-to-one FD.
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 24.582 V19.0.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19).
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "media_rules.hpp"

#include <cassert>
#include <iostream>
using namespace mcx;

//------------------------------------------------------------------------------
// TS 24.282 clause 7.3.3 steps 2 and 3 with TS 33.180 clause 9.2.1.3: a PUBLISH for poc-settings, or the client's
// REGISTER, that uploads a CSK is opened with that CSK; other requests (a one-to-one SDS carries its PCK in an
// application/mikey body, clause 9.2.2.2.1 step 2c) and an authorisation without upload are opened with the binding's.
static void Clause_7_3_3_CskUploadOpenedWithItsOwnCsk() {
  const std::vector<std::string_view> upload{"application/vnd.3gpp.mcdata-info+xml", "application/poc-settings+xml",
                                             "application/mikey"};
  const std::vector<std::string_view> renewal{"application/vnd.3gpp.mcdata-info+xml", "application/poc-settings+xml"};
  assert(uploads_csk("PUBLISH", "poc-settings", upload));
  assert(uploads_csk("REGISTER", "", upload));
  assert(!uploads_csk("PUBLISH", "poc-settings", renewal));
  assert(!uploads_csk("MESSAGE", "", upload));
  assert(!uploads_csk("PUBLISH", "presence", upload));
  assert(!uploads_csk("INVITE", "", upload));
}

//------------------------------------------------------------------------------
// TS 24.582 clause 6.3.1.3 steps 2a and 2b: the smaller of the group's two limits applies; an unset one (0) does not.
static void Clause_6_3_1_3_GroupLimitsBoth() {
  assert(tightest_limit(0, 0) == 0);
  assert(tightest_limit(500, 0) == 500);
  assert(tightest_limit(0, 400) == 400);
  assert(tightest_limit(500, 400) == 400);
  assert(tightest_limit(300, 400) == 300);
}

//------------------------------------------------------------------------------
// TS 24.582 clause 6.3.1.3 steps 3 and 4: a SEND above the limit is answered 403, one within it (or without a limit)
// 200.
static void Clause_6_3_1_3_SendAnsweredByItsSize() {
  assert(standalone_sds_send_status(401, 400) == msrp_forbidden);
  assert(standalone_sds_send_status(400, 400) == msrp_ok);
  assert(standalone_sds_send_status(10, 400) == msrp_ok);
  assert(standalone_sds_send_status(100000, 0) == msrp_ok);
}

//------------------------------------------------------------------------------
// TS 24.282 clause 10.2.5.4.4: the invited leg of a one-to-one FD ending while the originator's INVITE waits for its
// final response does not release the communication; the originator leaving, or a leg ending once it is answered,
// does.
static void Clause_10_2_5_4_4_DeclineAnswersTheOriginator() {
  assert(release_waits_for_answer(false, true));
  assert(!release_waits_for_answer(true, true));
  assert(!release_waits_for_answer(false, false));
  assert(!release_waits_for_answer(true, false));
}

//------------------------------------------------------------------------------
// Runs every test; an assert ends the program on the first failure.
int main() {
  Clause_7_3_3_CskUploadOpenedWithItsOwnCsk();
  Clause_6_3_1_3_GroupLimitsBoth();
  Clause_6_3_1_3_SendAnsweredByItsSize();
  Clause_10_2_5_4_4_DeclineAnswersTheOriginator();
  std::cout << "media rules: all tests passed\n";
  return 0;
}
