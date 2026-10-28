//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The MBMS usage information bodies of TS 24.379 annex F.2 and TS 24.281 annex F.2 (include/mcx/mbms_usage.hpp):
// the bearer announcement, the listening and suspension status reports and the MuSiK download.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.008 V19.4.0 (Rel-19).

#include "mcx/mbms_usage.hpp"

#include "protocol_internal.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.3 item 1 a), table F.2.3-1, and item 2 a), table F.2.3-2: the status values.
inline constexpr std::string_view listening_value = "listening", not_listening_value = "not-listening";
inline constexpr std::string_view suspending_value = "suspending", not_suspending_value = "not-suspending";

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.4, F.2.2 and F.2.3 item 3 g); TS 24.281 annex F.2.4, F.2.2 and F.2.3.
const MbmsUsageType &mbms_usage_type(MbmsService service) {
  static constexpr MbmsUsageType mcptt{mbms_usage_mime, mbms_usage_ns, "mcptt-mbms-usage-info", "mcptt-mbms-rohc"};
  static constexpr MbmsUsageType mcvideo{"application/vnd.3gpp.mcvideo-mbms-usage-info+xml",
                                         "urn:3gpp:ns:mcvideoMbmsUsage:1.0", "mcvideo-mbms-usage-info",
                                         "mcvid-mbms-rohc"};
  return service == MbmsService::Mcvideo ? mcvideo : mcptt;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.3 item 1 d): a TMGI is hexBinary of 3 or 6 octets (TS 24.008 clause 10.5.6.13 octets 3 to 8);
// lower case, as compared with the configured one.
std::string tmgi_hex(std::string value) {
  constexpr std::size_t service_id_digits = 6, with_plmn_digits = 12;
  if ((value.size() != service_id_digits && value.size() != with_plmn_digits) ||
      value.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
    invalid("TMGI must be 3 or 6 octets of hexBinary");
  return lower(std::move(value));
}

//------------------------------------------------------------------------------
// Helper: XML Schema part 2 section 3.2.15: a non-empty hexBinary value (an MBMS service area ID), in lower case.
static std::string hex_binary(std::string value) {
  if (value.empty() || value.size() % 2 != 0 || value.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
    invalid("not hexBinary");
  return lower(std::move(value));
}

//------------------------------------------------------------------------------
// Helper: XML Schema part 2 section 3.2.2.1: the lexical forms of xs:boolean.
static bool boolean(xmlNode *node, const char *what) {
  const auto flag = text(node);
  if (flag != "true" && flag != "false" && flag != "1" && flag != "0") invalid(what);
  return flag == "true" || flag == "1";
}

static const char *boolean_text(bool flag) { return flag ? "true" : "false"; }

//------------------------------------------------------------------------------
// Helper: an xs:integer (or xs:unsignedLong) element within [low, high].
static std::uint64_t integer(xmlNode *node, std::uint64_t low, std::uint64_t high, const char *what) {
  const auto value = text(node);
  if (value.empty() || value.size() > 20 || value.find_first_not_of("0123456789") != std::string::npos) invalid(what);
  std::uint64_t number = 0;
  try {
    number = std::stoull(value);
  } catch (const std::exception &) {
    invalid(what);
  }
  if (number < low || number > high) invalid(what);
  return number;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.3 item 1: a status needs a TMGI, and without <general-purpose> a session; the reception
// quality ranges from 0 to 5 (item 1 e).
static void check_listening_status(const MbmsListeningStatus &status) {
  if (status.tmgis.empty()) invalid("listening status without a TMGI");
  if (!status.general_purpose && status.session_id.empty())
    invalid("listening status without session or general purpose");
  if (status.reception_quality && (*status.reception_quality < 0 || *status.reception_quality > 5))
    invalid("MBMS reception quality out of range");
}

//------------------------------------------------------------------------------
// Helper: TS 24.379 annex F.2.3 item 1: writes an <mbms-listening-status> element.
static std::string listening_status_xml(const MbmsListeningStatus &status) {
  check_listening_status(status);
  std::string out = "<mbms-listening-status><mbms-listening-status>" +
                    std::string(status.listening ? listening_value : not_listening_value) + "</mbms-listening-status>";
  if (!status.session_id.empty()) {
    conference_uri(status.session_id, true);
    out += "<session-id>" + xml_escape(status.session_id) + "</session-id>";
  }
  if (status.general_purpose)
    out += std::string("<general-purpose>") + boolean_text(*status.general_purpose) + "</general-purpose>";
  for (const auto &tmgi : status.tmgis) out += "<TMGI>" + tmgi_hex(tmgi) + "</TMGI>";
  if (status.reception_quality)
    out += "<anyExt><mbms-reception-quality>" + std::to_string(*status.reception_quality) +
           "</mbms-reception-quality></anyExt>";
  return out + "</mbms-listening-status>";
}

//------------------------------------------------------------------------------
// Helper: TS 24.379 annex F.2.3 item 2: writes an <mbms-suspension-status> element.
static std::string suspension_status_xml(const MbmsSuspensionStatus &status) {
  if (status.suspended_tmgi.empty()) invalid("suspension status without a suspended TMGI");
  std::string out = "<mbms-suspension-status><mbms-suspension-status>" +
                    std::string(status.suspending ? suspending_value : not_suspending_value) +
                    "</mbms-suspension-status><number-of-reported-bearers>" +
                    std::to_string(1 + status.other_tmgis.size()) + "</number-of-reported-bearers><suspended-TMGI>" +
                    tmgi_hex(status.suspended_tmgi) + "</suspended-TMGI>";
  for (const auto &tmgi : status.other_tmgis) out += "<other-TMGI>" + tmgi_hex(tmgi) + "</other-TMGI>";
  return out + "</mbms-suspension-status>";
}

//------------------------------------------------------------------------------
// Helper: TS 24.379 annex F.2.3 item 3: writes an <announcement> element, in the schema's order.
static std::string announcement_xml(const MbmsAnnouncement &announcement, const MbmsUsageType &type) {
  std::string out = "<announcement><TMGI>" + tmgi_hex(announcement.tmgi) + "</TMGI>";
  if (announcement.qci) {
    if (*announcement.qci < 0) invalid("negative QCI");
    out += "<QCI>" + std::to_string(*announcement.qci) + "</QCI>";
  }
  if (announcement.frequency) out += "<frequency>" + std::to_string(*announcement.frequency) + "</frequency>";
  if (!announcement.service_areas.empty()) {
    out += "<mbms-service-areas>";
    for (const auto &area : announcement.service_areas)
      out += "<mbms-service-area-id>" + hex_binary(area) + "</mbms-service-area-id>";
    out += "</mbms-service-areas>";
  }
  if (announcement.gpms) {
    if (*announcement.gpms == 0) invalid("GPMS is a positive integer");
    out += "<GPMS>" + std::to_string(*announcement.gpms) + "</GPMS>";
  }
  if (announcement.report_suspension)
    out += std::string("<report-suspension>") + boolean_text(*announcement.report_suspension) + "</report-suspension>";
  if (announcement.rohc) out += std::string("<anyExt><") + type.rohc + "/></anyExt>";
  return out + "</announcement>";
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.2 (TS 24.281 annex F.2.2): the document, in the schema's order: listening status, suspension
// status, announcements, <version>, and the MuSiK download in <anyExt> (annex F.2.3 item 5).
std::string mbms_usage_xml(const MbmsUsageInfo &info, MbmsService service) {
  const auto &type = mbms_usage_type(service);
  std::string out =
      std::string("<?xml version=\"1.0\" encoding=\"UTF-8\"?><") + type.root + " xmlns=\"" + type.ns + "\">";
  if (info.listening_status) out += listening_status_xml(*info.listening_status);
  if (info.suspension_status) out += suspension_status_xml(*info.suspension_status);
  for (const auto &announcement : info.announcements) out += announcement_xml(announcement, type);
  out += "<version>1</version>";
  if (info.musik_download) {
    const auto &download = *info.musik_download;
    if (download.explicit_groups && download.groups.empty()) invalid("explicit MuSiK download without a group");
    const char *element = download.explicit_groups ? "mbms-explicitMuSiK-download" : "mbms-defaultMuSiK-download";
    out += std::string("<anyExt><") + element + ">";
    for (const auto &group : download.groups) {
      if (group.empty()) invalid("empty MuSiK download group");
      out += "<group>" + xml_escape(group) + "</group>";
    }
    out += std::string("</") + element + "></anyExt>";
  }
  out += std::string("</") + type.root + ">";
  bounded(out);
  return out;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 14.3.3.2 steps 1 e) to 1 g): the listening status report.
std::string mbms_listening_status_xml(const MbmsListeningStatus &status, MbmsService service) {
  return mbms_usage_xml({status, std::nullopt, {}, std::nullopt}, service);
}

//------------------------------------------------------------------------------
// Helper: the <anyExt> child of a node, or none.
static xmlNode *any_ext(xmlNode *node, const char *ns) { return unique_child(node, "anyExt", ns, false); }

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.3 item 1: reads an <mbms-listening-status> element.
static MbmsListeningStatus listening_status(xmlNode *node, const char *ns) {
  MbmsListeningStatus out;
  const auto value = text(unique_child(node, "mbms-listening-status", ns));
  if (value != listening_value && value != not_listening_value) invalid("unknown MBMS listening status");
  out.listening = value == listening_value;
  if (auto *session = unique_child(node, "session-id", ns, false)) {
    out.session_id = text(session);
    conference_uri(out.session_id, true);
  }
  if (auto *general = unique_child(node, "general-purpose", ns, false))
    out.general_purpose = boolean(general, "general-purpose is not a boolean");
  for (auto *child = node->children; child; child = child->next)
    if (is(child, "TMGI", ns)) out.tmgis.push_back(tmgi_hex(text(child)));
  if (auto *ext = any_ext(node, ns))
    if (auto *quality = unique_child(ext, "mbms-reception-quality", ns, false))
      out.reception_quality = static_cast<int>(integer(quality, 0, 5, "MBMS reception quality out of range"));
  check_listening_status(out);
  return out;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.3 item 2: reads an <mbms-suspension-status> element. The schema makes each child optional;
// the procedures of clause 14.2.3 need the status and the suspended TMGI. <number-of-reported-bearers> is checked
// to be an integer and otherwise ignored.
static MbmsSuspensionStatus suspension_status(xmlNode *node, const char *ns) {
  MbmsSuspensionStatus out;
  const auto value = text(unique_child(node, "mbms-suspension-status", ns));
  if (value != suspending_value && value != not_suspending_value) invalid("unknown MBMS suspension status");
  out.suspending = value == suspending_value;
  if (auto *count = unique_child(node, "number-of-reported-bearers", ns, false))
    (void)integer(count, 0, 65535, "number-of-reported-bearers is not an integer");
  out.suspended_tmgi = tmgi_hex(text(unique_child(node, "suspended-TMGI", ns)));
  for (auto *child = node->children; child; child = child->next)
    if (is(child, "other-TMGI", ns)) out.other_tmgis.push_back(tmgi_hex(text(child)));
  return out;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.3 item 3: reads an <announcement> element.
static MbmsAnnouncement announcement(xmlNode *node, const MbmsUsageType &type) {
  MbmsAnnouncement out;
  out.tmgi = tmgi_hex(text(unique_child(node, "TMGI", type.ns)));
  if (auto *qci = unique_child(node, "QCI", type.ns, false))
    out.qci = static_cast<int>(integer(qci, 0, 255, "QCI out of range"));
  if (auto *frequency = unique_child(node, "frequency", type.ns, false))
    out.frequency = integer(frequency, 0, UINT64_MAX, "frequency is not an unsignedLong");
  if (auto *areas = unique_child(node, "mbms-service-areas", type.ns, false)) {
    for (auto *child = areas->children; child; child = child->next)
      if (is(child, "mbms-service-area-id", type.ns)) out.service_areas.push_back(hex_binary(text(child)));
    if (out.service_areas.empty()) invalid("mbms-service-areas without an MBMS service area ID");
  }
  if (auto *gpms = unique_child(node, "GPMS", type.ns, false))
    out.gpms = static_cast<unsigned>(integer(gpms, 1, 65535, "GPMS out of range"));
  if (auto *report = unique_child(node, "report-suspension", type.ns, false))
    out.report_suspension = boolean(report, "report-suspension is not a boolean");
  if (auto *ext = any_ext(node, type.ns)) out.rohc = unique_child(ext, type.rohc, type.ns, false) != nullptr;
  return out;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.3 item 5: reads a MuSiK download element.
static MusikDownload musik_download(xmlNode *node, bool explicit_groups, const char *ns) {
  MusikDownload out{explicit_groups, {}};
  for (auto *child = node->children; child; child = child->next)
    if (is(child, "group", ns)) {
      out.groups.push_back(text(child));
      if (out.groups.back().empty()) invalid("empty MuSiK download group");
    }
  if (explicit_groups && out.groups.empty()) invalid("explicit MuSiK download without a group");
  return out;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.2 and annex F.2.3 (TS 24.281 annex F.2): reads an MBMS usage information document.
MbmsUsageInfo parse_mbms_usage_info(std::string_view xml, MbmsService service) {
  const auto &type = mbms_usage_type(service);
  auto doc = document(xml);
  auto *root = xmlDocGetRootElement(doc.get());
  if (!is(root, type.root, type.ns)) invalid("wrong MBMS usage information root");
  // TS 24.379 annex F.2.2: <version> is mandatory.
  (void)unique_child(root, "version", type.ns);
  MbmsUsageInfo out;
  if (auto *status = unique_child(root, "mbms-listening-status", type.ns, false))
    out.listening_status = listening_status(status, type.ns);
  if (auto *status = unique_child(root, "mbms-suspension-status", type.ns, false))
    out.suspension_status = suspension_status(status, type.ns);
  for (auto *child = root->children; child; child = child->next)
    if (is(child, "announcement", type.ns)) out.announcements.push_back(announcement(child, type));
  if (auto *ext = any_ext(root, type.ns)) {
    auto *by_default = unique_child(ext, "mbms-defaultMuSiK-download", type.ns, false);
    auto *by_group = unique_child(ext, "mbms-explicitMuSiK-download", type.ns, false);
    if (by_default && by_group) invalid("both a default and an explicit MuSiK download");
    if (by_default || by_group)
      out.musik_download = musik_download(by_group ? by_group : by_default, by_group != nullptr, type.ns);
  }
  return out;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.2A.4 and F.2A.2; TS 24.281 annex F.2A.
const MbmsUsageType &mbs_usage_type(MbmsService service) {
  static constexpr MbmsUsageType mcptt{"application/vnd.3gpp.mcptt-mbs-usage-info+xml", "urn:3gpp:ns:mcpttMbsUsage:1.0",
                                       "mcptt-mbs-usage-info", "mcptt-mbs-rohc"};
  static constexpr MbmsUsageType mcvideo{"application/vnd.3gpp.mcvideo-mbs-usage-info+xml",
                                         "urn:3gpp:ns:mcvideoMbsUsage:1.0", "mcvideo-mbs-usage-info",
                                         "mcvideo-mbs-rohc"};
  return service == MbmsService::Mcvideo ? mcvideo : mcptt;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.2A.3 items 1 and 3, item 2 a), item 4 a) ii): the string values.
inline constexpr std::string_view deleting_value = "deleting", not_deleting_value = "not-deleting";
inline constexpr std::string_view join_value = "ue-session-join", leave_value = "ue-session-leave";

//------------------------------------------------------------------------------
// Helper: an MBS session ID (TS 23.247 clause 6.5.1), hexBinary in lower case.
static std::string mbs_session_hex(std::string value) { return hex_binary(std::move(value)); }

//------------------------------------------------------------------------------
// TS 24.379 annex F.2A.2: the document, in the schema's order: listening status, de-announcement status, UE session join
// notification, announcements, <version>, and the MuSiK download in <anyExt>. The schema makes
// <multicast-mbs-session-related-info> mandatory in <mbs-session-info>; it is written empty.
std::string mbs_usage_xml(const MbsUsageInfo &info, MbmsService service) {
  const auto &type = mbs_usage_type(service);
  std::string out = std::string("<?xml version=\"1.0\" encoding=\"UTF-8\"?><") + type.root + " xmlns=\"" + type.ns +
                    "\">";
  if (info.listening_status) {
    const auto &status = *info.listening_status;
    if (status.mbs_session_ids.empty()) invalid("MBS listening status without an MBS session ID");
    if (!status.general_purpose && status.session_id.empty())
      invalid("MBS listening status without session or general purpose");
    out += "<mbs-listening-status><mbs-listening-status>" +
           std::string(status.listening ? listening_value : not_listening_value) +
           "</mbs-listening-status><unicast-listening-status>" +
           std::string(status.unicast_listening ? listening_value : not_listening_value) +
           "</unicast-listening-status>";
    if (!status.session_id.empty()) {
      conference_uri(status.session_id, true);
      out += "<session-id>" + xml_escape(status.session_id) + "</session-id>";
    }
    if (status.general_purpose)
      out += std::string("<general-purpose>") + boolean_text(*status.general_purpose) + "</general-purpose>";
    for (const auto &id : status.mbs_session_ids) out += "<mbs-session-id>" + mbs_session_hex(id) + "</mbs-session-id>";
    out += "</mbs-listening-status>";
  }
  if (info.de_announcement_status) {
    const auto &status = *info.de_announcement_status;
    out += "<mbs-session-de-announcement-status><mbs-session-de-announcement-status>" +
           std::string(status.deleting ? deleting_value : not_deleting_value) +
           "</mbs-session-de-announcement-status><number-of-reported-sessions>" +
           std::to_string(1 + status.other_session_ids.size()) + "</number-of-reported-sessions><deleted-mbs-session-id>" +
           mbs_session_hex(status.deleted_session_id) + "</deleted-mbs-session-id>";
    for (const auto &id : status.other_session_ids)
      out += "<other-mbs-session-id>" + mbs_session_hex(id) + "</other-mbs-session-id>";
    out += "</mbs-session-de-announcement-status>";
  }
  if (info.join_notification) {
    const auto &join = *info.join_notification;
    out += "<ue-session-join-notification><mbs-multicast-joining-status>" +
           std::string(join.join ? join_value : leave_value) + "</mbs-multicast-joining-status><mbs-session-id>" +
           mbs_session_hex(join.mbs_session_id) + "</mbs-session-id>";
    if (!join.session_id.empty()) {
      conference_uri(join.session_id, true);
      out += "<session-id>" + xml_escape(join.session_id) + "</session-id>";
    }
    out += "</ue-session-join-notification>";
  }
  for (const auto &announcement : info.announcements) {
    if (announcement.mode != "multicast" && announcement.mode != "broadcast") invalid("unknown MBS session mode");
    out += "<announcement><mbs-session-info><mbs-session-id>" + mbs_session_hex(announcement.session_id) +
           "</mbs-session-id><mbs-session-mode>" + announcement.mode + "</mbs-session-mode>";
    if (announcement.frequency) out += "<frequency>" + std::to_string(*announcement.frequency) + "</frequency>";
    if (announcement.gpms) {
      if (*announcement.gpms == 0) invalid("GPMS is a positive integer");
      out += "<GPMS>" + std::to_string(*announcement.gpms) + "</GPMS>";
    }
    if (!announcement.service_areas.empty()) {
      out += "<mbs-service-areas>";
      for (const auto &area : announcement.service_areas)
        out += "<mbs-service-area-id>" + hex_binary(area) + "</mbs-service-area-id>";
      out += "</mbs-service-areas>";
    }
    if (announcement.report_join)
      out += std::string("<report-ue-session-join-notification>") + boolean_text(*announcement.report_join) +
             "</report-ue-session-join-notification>";
    out += "<multicast-mbs-session-related-info/>";
    for (const auto &fsa : announcement.fsa_ids) out += "<mbs-fsa-id>" + hex_binary(fsa) + "</mbs-fsa-id>";
    if (announcement.de_announcement_ack)
      out += std::string("<mbs-session-de-announcement-acknowledgement>") +
             boolean_text(*announcement.de_announcement_ack) + "</mbs-session-de-announcement-acknowledgement>";
    out += "</mbs-session-info></announcement>";
  }
  out += "<version>1</version>";
  if (info.musik_download) {
    const auto &download = *info.musik_download;
    if (download.explicit_groups && download.groups.empty()) invalid("explicit MuSiK download without a group");
    const char *element = download.explicit_groups ? "mbs-explicitMuSiK-download" : "mbs-defaultMuSiK-download";
    out += std::string("<anyExt><") + element + ">";
    for (const auto &group : download.groups) out += "<group>" + xml_escape(group) + "</group>";
    out += std::string("</") + element + "></anyExt>";
  }
  out += std::string("</") + type.root + ">";
  bounded(out);
  return out;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.2A.2 and F.2A.3 (TS 24.281 annex F.2A): reads an MBS usage information document. An announcement
// without <mbs-session-info> (an eMBMS bearer only) is not taken.
MbsUsageInfo parse_mbs_usage_info(std::string_view xml, MbmsService service) {
  const auto &type = mbs_usage_type(service);
  const char *ns = type.ns;
  auto doc = document(xml);
  auto *root = xmlDocGetRootElement(doc.get());
  if (!is(root, type.root, ns)) invalid("wrong MBS usage information root");
  (void)unique_child(root, "version", ns);
  MbsUsageInfo out;
  if (auto *node = unique_child(root, "mbs-listening-status", ns, false)) {
    MbsListeningStatus status;
    const auto value = text(unique_child(node, "mbs-listening-status", ns));
    const auto unicast = text(unique_child(node, "unicast-listening-status", ns));
    for (const auto &item : {value, unicast})
      if (item != listening_value && item != not_listening_value) invalid("unknown MBS listening status");
    status.listening = value == listening_value;
    status.unicast_listening = unicast == listening_value;
    if (auto *session = unique_child(node, "session-id", ns, false)) {
      status.session_id = text(session);
      conference_uri(status.session_id, true);
    }
    if (auto *general = unique_child(node, "general-purpose", ns, false))
      status.general_purpose = boolean(general, "general-purpose is not a boolean");
    for (auto *child = node->children; child; child = child->next)
      if (is(child, "mbs-session-id", ns)) status.mbs_session_ids.push_back(mbs_session_hex(text(child)));
    if (status.mbs_session_ids.empty()) invalid("MBS listening status without an MBS session ID");
    if (!status.general_purpose && status.session_id.empty())
      invalid("MBS listening status without session or general purpose");
    out.listening_status = status;
  }
  if (auto *node = unique_child(root, "mbs-session-de-announcement-status", ns, false)) {
    MbsDeAnnouncementStatus status;
    const auto value = text(unique_child(node, "mbs-session-de-announcement-status", ns));
    if (value != deleting_value && value != not_deleting_value) invalid("unknown MBS de-announcement status");
    status.deleting = value == deleting_value;
    status.deleted_session_id = mbs_session_hex(text(unique_child(node, "deleted-mbs-session-id", ns)));
    for (auto *child = node->children; child; child = child->next)
      if (is(child, "other-mbs-session-id", ns)) status.other_session_ids.push_back(mbs_session_hex(text(child)));
    out.de_announcement_status = status;
  }
  if (auto *node = unique_child(root, "ue-session-join-notification", ns, false)) {
    UeSessionJoin join;
    const auto value = text(unique_child(node, "mbs-multicast-joining-status", ns));
    if (value != join_value && value != leave_value) invalid("unknown MBS joining status");
    join.join = value == join_value;
    join.mbs_session_id = mbs_session_hex(text(unique_child(node, "mbs-session-id", ns)));
    if (auto *session = unique_child(node, "session-id", ns, false)) {
      join.session_id = text(session);
      conference_uri(join.session_id, true);
    }
    out.join_notification = join;
  }
  for (auto *child = root->children; child; child = child->next) {
    if (!is(child, "announcement", ns)) continue;
    auto *info = unique_child(child, "mbs-session-info", ns, false);
    if (!info) continue;
    MbsAnnouncement announcement;
    announcement.session_id = mbs_session_hex(text(unique_child(info, "mbs-session-id", ns)));
    announcement.mode = text(unique_child(info, "mbs-session-mode", ns));
    if (announcement.mode != "multicast" && announcement.mode != "broadcast") invalid("unknown MBS session mode");
    if (auto *frequency = unique_child(info, "frequency", ns, false))
      announcement.frequency = integer(frequency, 0, UINT64_MAX, "frequency is not an unsignedLong");
    if (auto *gpms = unique_child(info, "GPMS", ns, false))
      announcement.gpms = static_cast<unsigned>(integer(gpms, 1, 65535, "GPMS out of range"));
    if (auto *areas = unique_child(info, "mbs-service-areas", ns, false)) {
      for (auto *area = areas->children; area; area = area->next)
        if (is(area, "mbs-service-area-id", ns)) announcement.service_areas.push_back(hex_binary(text(area)));
      if (announcement.service_areas.empty()) invalid("mbs-service-areas without an MBS service area ID");
    }
    if (auto *report = unique_child(info, "report-ue-session-join-notification", ns, false))
      announcement.report_join = boolean(report, "report-ue-session-join-notification is not a boolean");
    for (auto *fsa = info->children; fsa; fsa = fsa->next)
      if (is(fsa, "mbs-fsa-id", ns)) announcement.fsa_ids.push_back(hex_binary(text(fsa)));
    if (auto *ack = unique_child(info, "mbs-session-de-announcement-acknowledgement", ns, false))
      announcement.de_announcement_ack = boolean(ack, "mbs-session-de-announcement-acknowledgement is not a boolean");
    out.announcements.push_back(std::move(announcement));
  }
  if (auto *ext = any_ext(root, ns)) {
    auto *by_default = unique_child(ext, "mbs-defaultMuSiK-download", ns, false);
    auto *by_group = unique_child(ext, "mbs-explicitMuSiK-download", ns, false);
    if (by_default && by_group) invalid("both a default and an explicit MuSiK download");
    if (by_default || by_group)
      out.musik_download = musik_download(by_group ? by_group : by_default, by_group != nullptr, ns);
  }
  return out;
}

} // namespace mcx
