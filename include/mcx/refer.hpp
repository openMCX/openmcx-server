//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The SIP REFER of a call over a pre-established session, signalling plane: the header fields and bodies that the
// MCPTT client builds (TS 24.379 clauses 6.2.4.2, 6.2.5.2, 10.1.1.2.2.1, 10.1.2.2.2.1, 11.1.1.2.2.1, 11.1.6.2.2.1)
// and that the participating MCPTT function reads (clauses 10.1.1.3.1.2, 10.1.2.3.2, 11.1.1.3.1.2): the Refer-To
// header field with a Content-ID URL (RFC 2392) or the MCPTT session identity with method "BYE"; the
// application/resource-lists+xml body (RFC 5366) whose single <entry> "uri" holds, in the headers portion of the SIP
// URI (RFC 3261 section 19.1.1), the Accept-Contact header fields and the hname "body" with the MCPTT-Info, SDP and
// location bodies; the Refer-Sub and Supported header fields of RFC 4488; the Target-Dialog header field of RFC 4538;
// and the Replaces header field of RFC 3891 (TS 24.379 clauses 6.3.2.2.5.3 and 6.3.2.2.6.3).
//
// Protection (TS 24.379 clause 6.6.2.1): the "uri" attribute is encrypted whole with the resource-lists body by the
// signalling protection filters; the XML bodies inside the hname "body" are protected by the caller before
// refer_entry_uri escapes them and after parse_refer_entry_uri reads them.
//
// Where the specifications differ (see docs/3GPP_CORRECTION_CANDIDATES.md, S06): TS 24.379 asks for the
// "multiple-refer" option tag in the Require header field of the private call, ambient listening and ad hoc group
// call REFERs (clauses 11.1.1.2.2.1 step 4, 11.1.6.2.2.1 step 4, 17.2.2.2 step 4) but not in the prearranged and
// chat group call REFERs (clauses 10.1.1.2.2.1, 10.1.2.2.2.1); TS 37.579-1 table 5.5.2.12-1 expects it in every
// REFER, and RFC 5368 section 4 asks for it whenever the Refer-To points to a URI list. Every REFER with a
// Content-ID URL carries it here; the participating function accepts a REFER with or without it.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 37.579-1 V18.1.0 (Rel-18), RFC 3261, RFC 3515, RFC 4488,
// RFC 4538, RFC 2392, RFC 5366, RFC 5368, RFC 3891, RFC 2046.

#pragma once

#include "mcx/protocol.hpp"
#include "mcx/sip.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mcx {

//------------------------------------------------------------------------------
// RFC 3261 section 19.1.1 and section 25.1: escapes an hname or hvalue of the headers portion of a SIP URI: every
// character but unreserved and hnv-unreserved ones ("[" "]" "/" "?" ":" "+" "$") becomes %HH.
std::string escape_uri_header(std::string_view value);
//------------------------------------------------------------------------------
// RFC 3261 section 19.1.2: undoes escape_uri_header; throws on a malformed escape.
std::string unescape_uri_header(std::string_view value);

//------------------------------------------------------------------------------
// TS 24.379 clauses 10.1.2.2.2.1 step 3 and 11.1.1.2.2.1 step 8, TS 37.579-1 table 5.5.2.12-2: the single <entry>
// of the REFER's resource list: the target (a group identity, an MCPTT ID or a functional alias), the header fields
// of its headers portion (two Accept-Contact; Answer-Mode or Priv-Answer-Mode for a private call) and the parts of
// its hname "body" (MCPTT-Info, an SDP offer, location-info), each with its Content-ID.
struct ReferEntry {
  std::string target;
  std::vector<SipHeader> headers;
  std::vector<BodyPart> body;
};

//------------------------------------------------------------------------------
// TS 24.379 clauses 10.1.2.2.2.1 step 3 a and b, 11.1.1.2.2.1 step 8: the two Accept-Contact header fields of the
// entry, for the service's media feature tag and ICSI with "require" and "explicit" (RFC 3841).
std::vector<SipHeader> refer_accept_contacts(const ServiceProfile &service = mcptt_service);

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.2.2.2.1 step 3, TS 37.579-1 table 5.5.2.12-2: the "uri" attribute value: the target, then
// "?" and its header fields escaped, the Content-Type "multipart/mixed" with `boundary` and the hname "body" holding
// the parts as a multipart/mixed body (RFC 2046 section 5.1.1). Throws when the target already has a headers portion.
std::string refer_entry_uri(const ReferEntry &entry, std::string_view boundary);
//------------------------------------------------------------------------------
// TS 24.379 clauses 10.1.1.3.1.2 step 9 and 11.1.1.3.1.2: reads the "uri" attribute: the target without its headers
// portion, the header fields other than Content-Type and body, and the parts of the hname "body" (a body of another
// type than multipart is one part of that type). Throws on a malformed URI or body.
ReferEntry parse_refer_entry_uri(std::string_view uri);

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.2.2.2.1 step 3 with RFC 5366: the resource list with one <list> holding the single <entry>.
std::string refer_resource_list(std::string_view entry_uri);
//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.1.3.1.2 step 9: the "uri" attribute of the single <entry> of the REFER's resource list;
// throws when the list has no entry or more than one (a first-to-answer call has several: refer_resource_list_entries).
std::string parse_refer_resource_list(std::string_view xml);
//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.2.2.1 step 8 (first-to-answer: one <entry> per called user, TS 37.579-1 table
// 5.5.3.3.1-1): the "uri" attributes of every <entry>, in order; at most 64.
std::string refer_resource_list_of(const std::vector<std::string> &entry_uris);
std::vector<std::string> refer_resource_list_entries(std::string_view xml);

//------------------------------------------------------------------------------
// RFC 3515 section 2.1: what a Refer-To header field names: a Content-ID URL (RFC 2392) pointing to a body of the
// REFER, or a URI with its "method" parameter (TS 24.379 clause 6.2.4.2 step 7: "BYE"), without the parameter.
struct ReferTo {
  std::string content_id; // set for a "cid:" URL, without the "cid:" and decoded
  std::string uri;        // otherwise
  std::string method;     // the "method" URI parameter, upper case as received; empty when absent
};

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.2.2.2.1 step 2 with RFC 2392 section 2: the Refer-To value "<cid:...>" for a Content-ID.
std::string cid_refer_to(std::string_view content_id);
//------------------------------------------------------------------------------
// TS 24.379 clauses 6.2.4.2 steps 6 and 7, 6.2.5.2 steps 6 and 7: the Refer-To value "<session;method=BYE>".
std::string bye_refer_to(std::string_view session_identity);
//------------------------------------------------------------------------------
// RFC 3515 section 2.1 with RFC 2392 section 2: reads a Refer-To value (name-addr or addr-spec, with refer-params).
ReferTo parse_refer_to(std::string_view value);

//------------------------------------------------------------------------------
// RFC 4538 section 7: "callid;local-tag=...;remote-tag=..." (TS 24.379 clause 10.1.2.2.2.1 step 10).
std::string target_dialog_value(const DialogIdentifiers &dialog);
//------------------------------------------------------------------------------
// RFC 4538 section 7: reads a Target-Dialog value; throws when a tag is missing.
DialogIdentifiers parse_target_dialog(std::string_view value);

//------------------------------------------------------------------------------
// RFC 3891 section 6.1: a Replaces value, "callid;to-tag=...;from-tag=..." (TS 24.379 clause 6.3.2.2.5.3 step 1 a),
// and its "early-only" flag.
struct ReplacesValue {
  std::string call_id, to_tag, from_tag;
  bool early_only = false;

  bool operator==(const ReplacesValue &) const = default;
};

std::string replaces_value(const ReplacesValue &replaces);
//------------------------------------------------------------------------------
// RFC 3891 section 6.1: reads a Replaces value; throws when a tag is missing.
ReplacesValue parse_replaces(std::string_view value);

//------------------------------------------------------------------------------
// RFC 3891 section 3: the Replaces of an INVITE naming one of the sender's own dialogs with the recipient: the
// recipient compares the to-tag with its local tag and the from-tag with its remote tag, so the to-tag is the
// recipient's (the sender's remote tag) and the from-tag the sender's own. TS 24.379 clauses 6.3.2.2.5.3 step 1 a and
// 6.3.2.2.6.3 step 1 a i ("the call-id, to-tag and from-tag of the targeted pre-established session") are read this
// way, not as the To and From tags of the INVITE that created the session (docs/3GPP_CORRECTION_CANDIDATES.md, S07).
ReplacesValue replaces_for(const DialogIdentifiers &own_dialog, bool early_only = false);
//------------------------------------------------------------------------------
// RFC 3891 section 3: whether a received Replaces names the recipient's dialog (Call-ID, to-tag = local tag,
// from-tag = remote tag).
[[nodiscard]] bool replaces_names(const ReplacesValue &replaces, const DialogIdentifiers &own_dialog) noexcept;

//------------------------------------------------------------------------------
// RFC 4488 section 4 with TS 24.379 clause 10.1.1.3.1.2 step 6: the REFER asks for no implicit subscription (a
// Refer-Sub header field "false" and "norefersub" among the Supported option tags).
[[nodiscard]] bool refer_without_subscription(const std::vector<SipHeader> &headers) noexcept;

//------------------------------------------------------------------------------
// The header fields of a REFER over a pre-established session, beyond those every request has: Refer-To,
// Refer-Sub "false", Supported "norefersub" (RFC 4488), Require "multiple-refer" for a Content-ID URL (see the file
// header), Target-Dialog identifying the pre-established session (RFC 4538) and the service's P-Preferred-Service
// (RFC 6050). TS 24.379 clauses 6.2.4.2 steps 4 to 8, 10.1.2.2.2.1 steps 2, 8 to 10, 11.1.1.2.2.1 steps 2 to 7.
std::vector<SipHeader> pre_established_refer_headers(std::string_view refer_to, const DialogIdentifiers &session,
                                                     const ServiceProfile &service = mcptt_service);

//------------------------------------------------------------------------------
// TS 24.379 clauses 10.1.1.2.2.1 and 10.1.2.2.2.1 steps 2 and 3: the body of a REFER that starts a call: the resource
// list part with its Content-ID `content_id` (the Refer-To's cid URL), the entry built by refer_entry_uri.
BodyPart refer_resource_list_part(const ReferEntry &entry, std::string_view content_id, std::string_view boundary);
// TS 24.379 clause 11.1.1.2.2.1 step 9: a first-to-answer call's list, one entry per targeted user.
BodyPart refer_resource_list_part(const std::vector<ReferEntry> &entries, std::string_view content_id,
                                  std::string_view boundary);

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.1.3.1.2 conditions 1 to 3, clause 11.1.1.3.1.2, clause 11.1.3.2.1.2: what a received REFER for
// a pre-established session asks for: a call (the entries of the resource list the Refer-To's Content-ID names, its
// first one read by parse_refer_entry_uri) or the end of a call (Refer-To with method "BYE": the session identity).
struct PreEstablishedReferRequest {
  bool leave = false;           // method "BYE": leave or release the call
  std::string session_identity; // for leave
  std::vector<std::string> entry_uris;
  ReferEntry entry; // the first entry, parsed
};

//------------------------------------------------------------------------------
// Reads a received REFER's Refer-To and parts (as the incoming protection filter gave them). Throws when the
// Refer-To is missing or unreadable, its Content-ID names no application/resource-lists+xml part, the list names
// no entry, or a method other than "BYE" is asked (the caller answers 400 or 403 as its clause says).
PreEstablishedReferRequest parse_pre_established_refer(const std::vector<SipHeader> &headers,
                                                       const std::vector<BodyPart> &parts);

} // namespace mcx
