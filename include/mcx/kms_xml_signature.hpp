//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Verification and creation of the XML signature of a signed KMS message (SignedKmsRequest, SignedKmsResponse) under
// an integrity key the caller has already derived (TS 33.180 clause 9.3.3, annex F.1.4). Cryptographic only: it does
// not select the key (the caller does, by the KeyName), read or write the TrK-ID or Signature-ID elements, or unwrap
// key material; the KMS documents (include/mcx/key_documents.hpp) use it.
//
// Supported, from the texts (anything else is refused, not skipped):
// - SignatureMethod HMAC-SHA256 with a 256-bit output (TS 33.180 annex D.1), HMACOutputLength absent or 256.
// - DigestMethod SHA-256 (TS 33.180 clause 9.3.5; decision X2: HMAC-SHA256 and SHA-256 only).
// - CanonicalizationMethod and canonicalization Transform: Canonical XML 1.0 and 1.1 (REQUIRED, XMLDSig Second Edition
//   clause 6.1), with comments (RECOMMENDED), and Exclusive XML Canonicalization 1.0 (clause 6.5).
// - Reference URI: the null URI (the whole document) and a shortname XPointer "#id" (clause 4.3.3.2: "MUST support
//   the null URI and shortname XPointer"), "#id" resolved through xml:id or the unqualified Id attribute of the KMS
//   schema. The schema types Id xsd:string, not xsd:ID (TS 33.180 annex D.3.5.1, reported); treating it as an ID is
//   the reading of the ETSI test suite for TS 37.579 (maintainer decision 2026-11-01). A duplicate ID is refused.
// - Transforms: the enveloped signature transform (REQUIRED, clause 6.6.4), then at most one canonicalization.
// The signature must cover the whole KmsRequest or KmsResponse (TS 33.180 annexes D.1, D.2.2 and D.3.1): one of its
// References must identify that element or an ancestor of it, and every Reference must validate.
//
// Specifications: TS 33.180 V19.5.0 (Rel-19) clauses 9.3.3 and 9.3.5, annexes D.1, D.2.2, D.3.1 and D.3.5.1; W3C XML
// Signature Syntax and Processing (Second Edition, 2008) clauses 3.2, 4.3.3 and 6; W3C Canonical XML 1.0 and 1.1;
// W3C Exclusive XML Canonicalization 1.0; W3C xml:id.
#pragma once
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace mcx::kmsxml {
//------------------------------------------------------------------------------
// XMLDSig Second Edition clause 3.2 (core validation): verifies the ds:Signature of a SignedKmsRequest or
// SignedKmsResponse under the derived integrity key (16 or 32 octets) and returns the canonical form of the
// authenticated KmsRequest or KmsResponse by the canonicalization of the Reference that covers it (comments omitted;
// Canonical XML 1.0 when that Reference names none). Throws when the
// document is malformed, carries a DTD, uses an unsupported algorithm, reference or transform, or does not verify.
std::string verify_payload(std::string_view signed_xml, std::span<const std::uint8_t> derived_integrity_key);

//------------------------------------------------------------------------------
// The text of the ds:KeyName in the KeyInfo of a signed KMS message's Signature, not verified: it names the key that
// signed it (TS 33.180 clause 9.3.5 and annex D.3.1, "base64 encoded" XPK-ID); empty when there is none.
std::string key_name(std::string_view signed_xml);

//------------------------------------------------------------------------------
// TS 33.180 annexes D.1, D.2.2 and D.3.1: signs a KmsRequest or KmsResponse element (payload_xml, without an XML
// declaration, its Id attribute naming it) under the derived integrity key (16 or 32 octets) and returns the
// SignedKmsRequest or SignedKmsResponse: one Reference to "#<Id>" without transforms (digested as Canonical XML 1.0,
// XMLDSig Second Edition clause 4.3.3.2), SHA-256, Canonical XML 1.0 for SignedInfo, HMAC-SHA256 and the KeyName
// given (the base64 XPK-ID). No Signature-ID or TrK-ID element is added: annex D.3.5.3 types them xsd:string and no
// clause gives their text form (a spec defect, reported). The result is verified with verify_payload before it is
// returned.
std::string sign_payload(std::string_view payload_xml, std::span<const std::uint8_t> derived_integrity_key,
                         std::string_view key_name);
} // namespace mcx::kmsxml
