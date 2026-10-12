//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Key management documents: the KMS response XML (KmsInit, KmsKeyProv, KmsCertCache), the KMS Redirect Response, and
// the MCS GKTP document with its xcap-diff subscription and notification bodies.
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.481 V19.3.0 (Rel-19), RFC 4826, RFC 5874, RFC 5875.
#pragma once
#include "mcx/keying.hpp"

namespace mcx::keying {
// The KMS documents of TS 33.180 annex D below are the TLS profile: the transport must authenticate the KMS (TLS).
// XML signatures and encrypted-key extensions are not accepted by these parsers.

//------------------------------------------------------------------------------
// TS 33.180 annexes D.3.1 and D.3.2: the KmsInit response with the Root KMS certificate.
std::string kms_init_xml(const PublicParameters &parameters, std::string_view user, std::string_view request,
                         std::uint64_t now);

//------------------------------------------------------------------------------
// TS 33.180 annex D.3.3: the KmsKeyProv response with the user's key set for the current key period.
std::string kms_keyprov_xml(const PublicParameters &parameters, const IdentityKeys &keys, std::string_view request,
                            std::uint64_t now);

//------------------------------------------------------------------------------
// TS 33.180 annex D.3.2 and clause 5.3.5: reads the Root KMS certificate of a KmsInit response.
PublicParameters parse_kms_init(std::string_view xml, std::string_view user, std::string_view kms,
                                std::string_view request, std::uint64_t now);

//------------------------------------------------------------------------------
// TS 33.180 annex D.3.3 and clause 5.3.6: reads the user's key set of a KmsKeyProv response and validates it against
// the KMS certificate.
IdentityKeys parse_kms_keyprov(std::string_view xml, const PublicParameters &parameters, std::string_view user,
                               std::string_view request, std::uint64_t now);

//------------------------------------------------------------------------------
// TS 33.180 annexes D.2.5 and D.3.2: the KmsCertCache response of a KMS without External KMSs: no certificates.
std::string kms_certcache_xml(const PublicParameters &home, std::string_view user, std::string_view request,
                              std::uint64_t now);

//------------------------------------------------------------------------------
// TS 33.180 clause 5.2.8 and annex D.4: the content type of a KMS Redirect Response, returned in a SIP 488.
inline constexpr const char *krr_mime = "application/vnd.3gpp.kmsredirectresponse+xml";

//------------------------------------------------------------------------------
// TS 33.180 clause 5.2.8.2.1: the content of a KMS Redirect Response. An empty KMS list stands for "ANY".
struct KmsRedirect {
  std::string creator, initiator, initiator_kms, receiver, receiver_kms;
  std::vector<std::string> initiator_list, receiver_list;
};

//------------------------------------------------------------------------------
// TS 33.180 clause 5.2.8.2.1 and annex D.4: a KMS Redirect Response. Unsigned: the signature of annex D.4.2 (ECDSA
// with an X.509 certificate) is optional.
std::string krr_xml(const KmsRedirect &redirect, std::uint64_t now);

//------------------------------------------------------------------------------
// TS 33.180 clause 5.2.8.2.1 and annex D.4: reads a KMS Redirect Response.
KmsRedirect parse_krr(std::string_view xml);

//------------------------------------------------------------------------------
// TS 24.481 clauses 7.7.2 and 7.7.8: an MCS GKTP document with one <GKTP> of <GMK-GKTPs> (the MIKEY-SAKKE I_MESSAGE
// carrying the GMK) and its activation time.
std::string gktp_document_xml(std::string_view group, std::string_view id, std::span<const std::uint8_t> mikey,
                              std::uint64_t now);

//------------------------------------------------------------------------------
// TS 24.481 clauses 7.7.2 and 7.7.8: the GMK GKTP of the MCS GKTP document of a group; refuses one whose activation
// time is still to come.
Bytes parse_gktp_document(std::string_view xml, std::string_view group, std::uint64_t now);

//------------------------------------------------------------------------------
// TS 24.481 clauses 6.3.13.2.1, 7.7.3 and 7.7.10: the XCAP path of the <GKTPs> element of the MCS GKTP document of a
// group (relative to the XCAP root).
std::string gktp_selector(std::string_view group);

//------------------------------------------------------------------------------
// TS 24.481 clause 6.3.13.2.1: the application/resource-lists+xml body (RFC 4826) of a SUBSCRIBE to the <GKTPs>
// element of a group's GKTP document.
std::string gktp_resource_list(std::string_view group);

//------------------------------------------------------------------------------
// TS 24.481 clause 6.3.13.3.3 and RFC 5875: the xcap-diff body (RFC 5874) of a NOTIFY carrying the <GKTPs> element of
// a group's GKTP document.
std::string gktp_xcap_diff(std::string_view source, std::string_view group, std::string_view xcap_root);

//------------------------------------------------------------------------------
// TS 24.481 clause 6.3.13.2.1 and RFC 5875: rebuilds the GKTP document of a group from the xcap-diff body (RFC 5874)
// of a NOTIFY, checking the XCAP root and the selector.
std::string parse_gktp_xcap_diff(std::string_view source, std::string_view group, std::string_view xcap_root);

//------------------------------------------------------------------------------
// TS 24.481 clause 6.3.13.3.3: a subscription body must be exactly the resource list for the <GKTPs> element of the
// group.
void validate_gktp_resource_list(std::string_view source, std::string_view group);
} // namespace mcx::keying
