// The lifetime of the MCData server's record of a file distribution over the media plane
// (src/mcdata/transfer_record.hpp): it is finished when every recipient has reported a final disposition, or when
// the time for the notifications has passed, and not before.
//
// Specifications: TS 24.282 V19.7.0 (Rel-19).
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "transfer_record.hpp"

#include <cassert>
#include <iostream>
using namespace mcx;

//------------------------------------------------------------------------------
// TS 24.282 clause 12.2.3: a final disposition (completed or rejected) from every recipient finishes the record.
static void Clause_12_2_3_EveryRecipientReported() {
  const std::set<std::string> recipients{"bob", "carol"};
  assert(!media_transfer_finished(recipients, {}, {}, 1000, 10));
  assert(!media_transfer_finished(recipients, {"bob"}, {}, 1000, 10));
  assert(media_transfer_finished(recipients, {"bob", "carol"}, {}, 1000, 10));
  assert(media_transfer_finished(recipients, {"bob"}, {"carol"}, 1000, 10));
  assert(media_transfer_finished(recipients, {}, {"bob", "carol"}, 1000, 10));
  // A report from someone who is not a recipient does not count.
  assert(!media_transfer_finished(recipients, {"bob", "dave"}, {}, 1000, 10));
}

//------------------------------------------------------------------------------
// TS 24.282 clause 12.2: the record is kept only for the time allowed for the notifications; after it, the record
// is finished even if recipients never reported (for example one that refused the media-plane INVITE).
static void Clause_12_2_NotificationTimePassed() {
  const std::set<std::string> recipients{"bob", "carol"};
  assert(!media_transfer_finished(recipients, {"bob"}, {}, 1000, 999));
  assert(media_transfer_finished(recipients, {"bob"}, {}, 1000, 1000));
  assert(media_transfer_finished(recipients, {}, {}, 1000, 5000));
}

//------------------------------------------------------------------------------
// A record without recipients is not finished by reports (none can arrive); only its time ends it.
static void NoRecipients() {
  assert(!media_transfer_finished({}, {}, {}, 1000, 10));
  assert(media_transfer_finished({}, {}, {}, 1000, 1000));
}

int main() {
  Clause_12_2_3_EveryRecipientReported();
  Clause_12_2_NotificationTimePassed();
  NoRecipients();
  std::cout << "transfer record tests passed\n";
}
