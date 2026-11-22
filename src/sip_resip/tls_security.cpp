//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The TLS profile of TS 33.210 clause 6.2 on reSIProcate's TLS (tls_security.hpp).
//
// Specifications: TS 33.210 V19.3.0 clause 6.2, TS 33.180 V19.4.0 (Rel-19) clause 6.1.

#include "tls_security.hpp"

#include "mcx/tls_profile.hpp"

#include <stdexcept>

namespace mcx::resip_engine {

//------------------------------------------------------------------------------
// TS 33.210 clause 6.2.1 (TLS 1.2 and 1.3), 6.2.3 (the TLS 1.2 suites) and 6.2.1 to 6.2.3 (the groups) on one SSL_CTX.
void apply_tls_profile(SSL_CTX *ctx) {
  if (ctx == nullptr) return;
  if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1 ||
      SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1 ||
      SSL_CTX_set_cipher_list(ctx, tls_profile::tls12_ciphers) != 1 ||
      SSL_CTX_set1_groups_list(ctx, tls_profile::groups) != 1)
    throw std::runtime_error("cannot apply the TLS profile of TS 33.210 clause 6.2");
}

//------------------------------------------------------------------------------
// The profile on the stack's own contexts, from which outgoing TLS connections are made.
ProfileSecurity::ProfileSecurity() : Security(resip::BaseSecurity::CipherList(tls_profile::tls12_ciphers)) {
  apply_tls_profile(getTlsCtx());
  apply_tls_profile(getSslCtx());
}

//------------------------------------------------------------------------------
// The profile on a TLS transport's domain context, made for its certificate (the server side).
SSL_CTX *ProfileSecurity::createDomainCtx(const SSL_METHOD *method, const resip::Data &domain,
                                          const resip::Data &certificate, const resip::Data &key,
                                          const resip::Data &passphrase) {
  SSL_CTX *ctx = Security::createDomainCtx(method, domain, certificate, key, passphrase);
  apply_tls_profile(ctx);
  return ctx;
}

} // namespace mcx::resip_engine
