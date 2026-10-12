#pragma once
// The lifetime of the MCData server's record of a file distribution over the media plane (TS 24.282 clause 10.2.5),
// header only so that it is unit tested without the server.
//
// Specifications: TS 24.282 V19.7.0 (Rel-19).
#include <algorithm>
#include <cstdint>
#include <set>
#include <string>

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.282 clause 12.2: a transfer over the media plane stores no file, so its record only correlates the
// disposition notifications of its recipients. It is finished once every recipient has reported a final
// disposition (completed or rejected, clause 12.2.3), or once the time allowed for the notifications (expires, a
// monotonic time in ms) has passed. A notification that arrives later is refused as not correlated (403, warning 216).
inline bool media_transfer_finished(const std::set<std::string> &recipients, const std::set<std::string> &downloaded,
                                    const std::set<std::string> &rejected, std::uint64_t expires, std::uint64_t now) {
  if (expires && expires <= now) return true;
  return !recipients.empty() && std::ranges::all_of(recipients, [&](const std::string &recipient) {
    return downloaded.contains(recipient) || rejected.contains(recipient);
  });
}

} // namespace mcx
