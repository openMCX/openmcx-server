//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The MBMS usage information body of TS 24.379 annex F.2 (include/mcx/mbms_usage.hpp): the listening status report.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19).

#include "mcx/mbms_usage.hpp"

#include "protocol_internal.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.3 item 1 a), table F.2.3-1: the values of <mbms-listening-status>.
inline constexpr std::string_view listening_value = "listening", not_listening_value = "not-listening";

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.3 item 1 d): a TMGI is hexBinary of 3 or 6 octets (TS 24.008 clause 10.5.6.13 octets 3 to 8);
// lower case, as compared with the configured one.
static std::string tmgi_value(std::string value) {
  constexpr std::size_t service_id_digits = 6, with_plmn_digits = 12;
  if ((value.size() != service_id_digits && value.size() != with_plmn_digits) ||
      value.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
    invalid("TMGI must be 3 or 6 octets of hexBinary");
  return lower(std::move(value));
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.3 item 1: a status needs a TMGI, and without <general-purpose> a session.
static void check_listening_status(const MbmsListeningStatus &status) {
  if (status.tmgis.empty()) invalid("listening status without a TMGI");
  if (!status.general_purpose && status.session_id.empty())
    invalid("listening status without session or general purpose");
}

//------------------------------------------------------------------------------
// TS 24.379 clause 14.3.3.2 steps 1 e) to 1 g): the listening status report.
std::string mbms_listening_status_xml(const MbmsListeningStatus &status) {
  check_listening_status(status);
  std::string out = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><mcptt-mbms-usage-info xmlns=\"" +
                    std::string(mbms_usage_ns) + "\"><mbms-listening-status><mbms-listening-status>" +
                    std::string(status.listening ? listening_value : not_listening_value) + "</mbms-listening-status>";
  if (!status.session_id.empty()) {
    conference_uri(status.session_id, true);
    out += "<session-id>" + xml_escape(status.session_id) + "</session-id>";
  }
  if (status.general_purpose)
    out += std::string("<general-purpose>") + (*status.general_purpose ? "true" : "false") + "</general-purpose>";
  for (const auto &tmgi : status.tmgis) out += "<TMGI>" + tmgi_value(tmgi) + "</TMGI>";
  out += "</mbms-listening-status><version>1</version></mcptt-mbms-usage-info>";
  bounded(out);
  return out;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.3 item 1: reads an <mbms-listening-status> element.
static MbmsListeningStatus listening_status(xmlNode *node) {
  MbmsListeningStatus out;
  const auto value = text(unique_child(node, "mbms-listening-status", mbms_usage_ns));
  if (value != listening_value && value != not_listening_value) invalid("unknown MBMS listening status");
  out.listening = value == listening_value;
  if (auto *session = unique_child(node, "session-id", mbms_usage_ns, false)) {
    out.session_id = text(session);
    conference_uri(out.session_id, true);
  }
  if (auto *general = unique_child(node, "general-purpose", mbms_usage_ns, false)) {
    const auto flag = text(general);
    // XML Schema part 2 section 3.2.2.1: the lexical forms of xs:boolean.
    if (flag != "true" && flag != "false" && flag != "1" && flag != "0") invalid("general-purpose is not a boolean");
    out.general_purpose = flag == "true" || flag == "1";
  }
  for (auto *child = node->children; child; child = child->next)
    if (is(child, "TMGI", mbms_usage_ns)) out.tmgis.push_back(tmgi_value(text(child)));
  check_listening_status(out);
  return out;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.2 and annex F.2.3: reads an MBMS usage information document.
MbmsUsageInfo parse_mbms_usage_info(std::string_view xml) {
  auto doc = document(xml);
  auto *root = xmlDocGetRootElement(doc.get());
  if (!is(root, "mcptt-mbms-usage-info", mbms_usage_ns)) invalid("wrong MBMS usage information root");
  // TS 24.379 annex F.2.2: <version> is mandatory.
  (void)unique_child(root, "version", mbms_usage_ns);
  MbmsUsageInfo out;
  if (auto *status = unique_child(root, "mbms-listening-status", mbms_usage_ns, false))
    out.listening_status = listening_status(status);
  out.suspension_status = unique_child(root, "mbms-suspension-status", mbms_usage_ns, false) != nullptr;
  out.announcement = unique_child(root, "announcement", mbms_usage_ns, false) != nullptr;
  return out;
}

} // namespace mcx
