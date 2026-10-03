// The XML and SDP documents of the MC services (include/mcx/protocol.hpp): the internal helpers the
// files of src/protocol/ share (XML parsing over libxml2, limits, namespaces, element names).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19),
// TS 24.481 V19.3.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19), RFC 3863, RFC 4575, RFC 4745, RFC 4826.

#pragma once

#include "mcx/protocol.hpp"

#include <libxml/parser.h>
#include <libxml/tree.h>

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <charconv>
#include <functional>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>

namespace mcx {
namespace protocol_detail {

// Helper: the largest protocol body accepted, in bytes.
inline constexpr std::size_t max_body = 65536;

// TS 24.379 annex F.1.2: the namespace of <mcpttinfo>.
inline constexpr const char *info_ns = "urn:3gpp:ns:mcpttInfo:1.0";

// RFC 3863: the PIDF namespace.
inline constexpr const char *pidf_ns = "urn:ietf:params:xml:ns:pidf";

// TS 24.379 clause 9.3.1.2, TS 24.282 clause 8.4.1, TS 24.281 clause 8.3.1: the affiliation namespaces.
inline constexpr const char *affiliation_ns = "urn:3gpp:ns:mcpttPresInfo:1.0";

inline constexpr const char *mcdata_affiliation_ns = "urn:3gpp:ns:mcdataPresInfo:1.0";

inline constexpr const char *mcvideo_affiliation_ns = "urn:3gpp:ns:mcvideoPresInfo:1.0";

//------------------------------------------------------------------------------
// TS 24.379 clause 9.3.1.2, TS 24.282 clause 8.4.1, TS 24.281 clause 8.3.1: the affiliation namespace of the
// service; an affiliation belongs to one MC service.
const char *affiliation_namespace(bool mcdata, bool mcvideo);

// TS 24.379 annex F.7.2: the namespace of the regroup document.
inline constexpr const char *regroup_ns = "urn:3gpp:ns:preconfiguredRegroup:1.0";

// RFC 4575: the conference-info namespace, and the MCPTT extension of TS 24.379 clause 10.1.3.6.1.2.
inline constexpr const char *conference_ns = "urn:ietf:params:xml:ns:conference-info";

inline constexpr const char *conference_mcptt_ns = "urn:3gpp:ns:mcpttConfInfo:1.0";

// RFC 4826: the resource-lists namespace.
inline constexpr const char *resource_lists_ns = "urn:ietf:params:xml:ns:resource-lists";

//------------------------------------------------------------------------------
// Helper: an owned libxml2 document.
using Doc = std::unique_ptr<xmlDoc, decltype(&xmlFreeDoc)>;

//------------------------------------------------------------------------------
// Helper: throws the protocol error with its message.
[[noreturn]] void invalid(const char *message);

//------------------------------------------------------------------------------
// Helper: refuses an empty, oversized or binary (NUL-carrying) protocol body.
void bounded(std::string_view body);

//------------------------------------------------------------------------------
// TS 24.282 annex E.1 and annex E.2: refuses an empty or oversized body. A multipart envelope may carry binary
// parts (MCData TLV bodies); each XML part is still checked by bounded() when it is parsed.
void bounded_envelope(std::string_view body);

//------------------------------------------------------------------------------
// Helper: removes the leading and trailing white space.
std::string trim(std::string_view value);

//------------------------------------------------------------------------------
// Helper: the ASCII lower-case form.
std::string lower(std::string value);

//------------------------------------------------------------------------------
// Helper: parses a bounded XML document without network access, DTD or entities.
Doc document(std::string_view xml);

//------------------------------------------------------------------------------
// Helper: whether the node is the element of the given name in the given namespace.
bool is(xmlNode *node, const char *name, const char *ns);

//------------------------------------------------------------------------------
// Helper: the text content of a node.
std::string text(xmlNode *node);

//------------------------------------------------------------------------------
// Helper: the value of an attribute (empty when absent).
std::string attr(xmlNode *node, const char *key);

//------------------------------------------------------------------------------
// Helper: the single child element of the given name and namespace; a duplicate, or a missing required one, is
// refused.
xmlNode *unique_child(xmlNode *root, const char *name, const char *ns, bool required = true);

//------------------------------------------------------------------------------
// The ad hoc participant criteria element: TS 24.379 annex F.1 <call-participants-criterias>, TS 24.281 annex F.1
// <call-participants-criteria>. The MCData <mcdatainfo> (TS 24.282 annex D.1) is not read or written with
// InfoNames (src/protocol/mcdata.cpp): refused.
inline const char *participant_criteria_element(const ServiceProfile &service) {
  switch (service.service) {
  case Service::mcptt: return "call-participants-criterias";
  case Service::mcvideo: return "call-participants-criteria";
  case Service::mcdata: break;
  }
  throw std::invalid_argument("the mcdata-info document is TS 24.282 annex D.1, not an MCPTT or MCVideo info");
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.1 and TS 24.281 annex F.1: the element names of an MC service information document:
// <mcpttinfo> or <mcvideoinfo>, which differ only in prefix.
struct InfoNames {
  std::string ns, prefix, root, params, uri, str, boolean, ambient, criteria;

  explicit InfoNames(const ServiceProfile &service)
      : ns(service.info_ns), prefix(service.info_prefix), root(prefix + "info"), params(prefix + "-Params"),
        uri(prefix + "URI"), str(prefix + "String"), boolean(prefix + "Boolean"),
        ambient(std::string(service.ambient) + "-type"), // <ambient-listening-type>, <ambient-viewing-type>
        criteria(participant_criteria_element(service)) {}

  [[nodiscard]] std::string element(std::string_view suffix) const { return prefix + "-" + std::string(suffix); }
};

//------------------------------------------------------------------------------
// TS 24.379 annex F.1.2 and annex F.1.3 (TS 24.281 annex F.1.2): reads a contentType element: its single URI or
// String value, unprotected ("Normal").
std::string content(xmlNode *node, const InfoNames &names);

//------------------------------------------------------------------------------
// TS 24.379 annex F.1.2: writes a contentType element with type "Normal" and its value wrapper; nothing when
// the value is empty.
std::string wrapped(std::string_view key, std::string_view type, const std::string &value);

//------------------------------------------------------------------------------
// Helper: a decimal number of at most max.
std::uint32_t number(std::string_view value, std::uint32_t max);

//------------------------------------------------------------------------------
// Helper: the non-empty trimmed fields of a text separated by sep.
std::vector<std::string> tokens(std::string_view value, char sep);

//------------------------------------------------------------------------------
// Helper: refuses a media address that is not a routable IPv4 address.
void address(std::string_view value);

//------------------------------------------------------------------------------
// RFC 4575 with RFC 3986 section 3.1: checks a conference URI.
void conference_uri(std::string_view uri, bool session = false);

//------------------------------------------------------------------------------
// RFC 4575: checks an endpoint <status> value.
void conference_status(const std::string &status);

//------------------------------------------------------------------------------
// Helper: the text of an element that must have no child elements.
std::string scalar(xmlNode *node);

//------------------------------------------------------------------------------
// TS 24.379 annex F.1 and TS 24.281 annex F.1: the values of <release-reason>. The schema's releaseReasonType
// enumeration (TS 24.379 annex F.1.2, clause F.1.3) spells "MIKEY-SAKE"; it is a schema value and kept as is, unlike
// the Warning text 136 of table 4.4.2-2, which spells "MIKEY-SAKKE".
static const std::set<std::string, std::less<>> release_reasons{
    "private-call-expiry",
    "administrator-action",
    "not selected for call",
    "call-request-for-listened-to-client",
    "call-request-initiated-by-listened-to-client",
    "call-request-for-viewed-to-client",
    "call-request-initiated-by-viewed-to-client", // TS 24.281 annex F.1
    "authentication of the MIKEY-SAKE I_MESSAGE failed"};

// TS 24.379 clause 9A.3.1.2, TS 24.282 clause 22.3.1, TS 24.281 clause 20.3.1: the functional alias namespaces.
inline constexpr const char *mcptt_functional_alias_ns = "urn:3gpp:ns:mcpttPresInfoFA:1.0";

inline constexpr const char *mcdata_functional_alias_ns = "urn:3gpp:ns:mcdataPresInfoFA:1.0";

inline constexpr const char *mcvideo_functional_alias_ns = "urn:3gpp:ns:mcvideoPresInfoFA:1.0";

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.3.1.2: the status values of a functional alias.
static const std::set<std::string> functional_alias_statuses{"activating", "activated", "deactivating",
                                                             "take-over-possible"};

// The MCPTT user profile document of TS 24.484 clause 8.3 (namespace of clause 8.3.2.4),
// and the MCVideo user profile document of TS 24.484 clause 9.3 (clause 9.3.2.4), which has the
// same structure for what is read here.
inline constexpr const char *profile_ns = "urn:3gpp:mcptt:user-profile:1.0";

inline constexpr const char *mcvideo_profile_ns = "urn:3gpp:ns:mcvideo:user-profile:1.0";

inline constexpr const char *mcdata_profile_ns = "urn:3gpp:ns:mcdata:user-profile:1.0";

inline constexpr const char *profile_extension_ns = "urn:openmcx:ns:userProfile:1.0";

inline constexpr const char *common_policy_ns = "urn:ietf:params:xml:ns:common-policy";

// TS 24.481 clause 7.2.2: the <list-service> of a group document (<group> of the OMA
// list-service namespace), whose MCS elements are in the mcpttGroupInfo namespace.
inline constexpr const char *poc_ns = "urn:oma:xml:poc:list-service";

inline constexpr const char *mcpttgi_ns = "urn:3gpp:ns:mcpttGroupInfo:1.0";

} // namespace protocol_detail

using namespace protocol_detail;
} // namespace mcx
