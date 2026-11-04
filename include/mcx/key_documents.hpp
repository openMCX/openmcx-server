//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Key management documents: the KMS response XML (KmsInit, KmsKeyProv, KmsCertCache), the KMS Redirect Response, and
// the MCS GKTP document with its xcap-diff subscription and notification bodies.
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.481 V19.3.0 (Rel-19), RFC 4826, RFC 5874, RFC 5875.
#pragma once
#include "mcx/keying.hpp"
#include "mcx/transport_keys.hpp"

#include <functional>

namespace mcx::keying {
// The KMS documents of TS 33.180 annex D below. Without transport keys (keys null or empty) they are the TLS profile:
// the transport must authenticate the KMS (TLS), and XML signatures and encrypted keys are refused. With the user's
// pre-provisioned TrK and InK (TS 33.180 clause 5.3.2, annex D.1): KMS messages signed under the InK, else the TrK
// (annexes D.2.2 and D.3.1), and key sets whose keys are wrapped under the TrK (clause 9.3.4.2, annex D.3.3.2). A signed
// response is verified with the key its KeyName names, which must be that integrity key; no Signature-ID or TrK-ID
// element is written or read (annex D.3.5.3 gives no text form, a spec defect). The readings of the ETSI test suite for
// TS 37.579 used where TS 33.180 is silent (key-wrap padding, the schema's Id as reference target): transport_keys.hpp,
// kms_xml_signature.hpp.

//------------------------------------------------------------------------------
// TS 33.180 annexes D.3.1 and D.3.2: the KmsInit response with the Root KMS certificate.
std::string kms_init_xml(const PublicParameters &parameters, std::string_view user, std::string_view request,
                         std::uint64_t now, const transport::TransportKeys *keys = nullptr);

//------------------------------------------------------------------------------
// TS 33.180 annex D.3.3: the KmsKeyProv response with the user's key set for the current key period.
std::string kms_keyprov_xml(const PublicParameters &parameters, const IdentityKeys &keys, std::string_view request,
                            std::uint64_t now, const transport::TransportKeys *transport_keys = nullptr);

//------------------------------------------------------------------------------
// TS 33.180 annex D.3.2 and clause 5.3.5: reads the Root KMS certificate of a KmsInit response.
PublicParameters parse_kms_init(std::string_view xml, std::string_view user, std::string_view kms,
                                std::string_view request, std::uint64_t now,
                                const transport::TransportKeys *keys = nullptr);

//------------------------------------------------------------------------------
// TS 33.180 annex F.2.1.1 (the UID form is not stated, spec defect): which UID forms a key set may be validated for.
// text_only: the base64 text (OpenMCX's form; the MC servers, the GMS and the KMS). raw_then_text: the 32 octets first
// (the ETSI test suite's reading for TS 37.579), then the text; asked for by the Linux client only.
enum class UidDetection : std::uint8_t { text_only, raw_then_text };

//------------------------------------------------------------------------------
// TS 33.180 annex D.3.3 and clause 5.3.6: reads the user's key set of a KmsKeyProv response and validates it against
// the KMS certificate, for the UID forms detection allows; the form it validates for is returned in uid_form.
IdentityKeys parse_kms_keyprov(std::string_view xml, const PublicParameters &parameters, std::string_view user,
                               std::string_view request, std::uint64_t now,
                               const transport::TransportKeys *keys = nullptr,
                               UidDetection detection = UidDetection::text_only);

//------------------------------------------------------------------------------
// TS 33.180 annex D.2.2 (table D.2.2-1): the SignedKmsRequest a KM client posts with a KMS request when it holds an
// InK or TrK: UserUri, KmsUri (the KMS URI, the security domain identifier of clause 3.1), Time and ClientReqUrl (the
// request URI), signed under the integrity key.
std::string kms_request_xml(std::string_view user, std::string_view kms, std::string_view request, std::uint64_t now,
                            const transport::TransportKeys &keys);

//------------------------------------------------------------------------------
// TS 33.180 annex D.2.2: the KMS's checks of a SignedKmsRequest: the signature, under the integrity key of the keys
// that keys_of gives for the request's UserUri ("based on the UserUri and the InK or TrK"); the XML; the KmsUri is
// this KMS's; the Time is within window seconds of now (the clause's "recent time window (e.g. 5 seconds)" is left to
// the KMS); the ClientReqUrl is the request URI. Returns the UserUri; throws on any failure.
std::string verify_kms_request(std::string_view xml, const std::function<transport::TransportKeys(const std::string &)> &keys_of,
                               std::string_view kms, std::string_view request, std::uint64_t now, std::uint64_t window);

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
// TS 24.481 clauses 7.7.2 and 7.7.8: the GMK GKTP of the MCS GKTP document of a group. One whose activation time is
// still to come is returned too: the GMK's own Activation Time (TS 33.180 annex E.6.4) says from when it is used.
Bytes parse_gktp_document(std::string_view xml, std::string_view group);

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
