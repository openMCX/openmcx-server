//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The TLS profile of TS 33.210 clause 6.2 (include/mcx/tls_profile.hpp) on reSIProcate's TLS: a resip::Security that
// applies it to every SSL_CTX the stack creates, its own (the client side) and each TLS transport's domain context
// (the server side).
//
// Private to src/sip/.
//
// Specifications: TS 33.210 V19.3.0 clause 6.2, TS 33.180 V19.4.0 (Rel-19) clause 6.1.
#pragma once

#include "resip/stack/ssl/Security.hxx"

#include <openssl/ssl.h>

namespace mcx::resip_engine {

//------------------------------------------------------------------------------
// TS 33.210 clause 6.2: on one SSL_CTX: TLS 1.2 to TLS 1.3, the TLS 1.2 ECDHE AEAD suites, the profile's groups.
void apply_tls_profile(SSL_CTX *ctx);

// reSIProcate's Security with the TLS profile on every SSL_CTX.
class ProfileSecurity : public resip::Security {
public:
  ProfileSecurity();

  SSL_CTX *createDomainCtx(const SSL_METHOD *method, const resip::Data &domain, const resip::Data &certificate,
                           const resip::Data &key, const resip::Data &passphrase) override;
};

} // namespace mcx::resip_engine
