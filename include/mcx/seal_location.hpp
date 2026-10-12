// The location-info documents of the SEAL location management protocol over HTTP (TS 24.545 clause 7,
// application/vnd.3gpp.seal-location-info+xml), as the location management client (SLM-C) of a user and an MC service
// server (the VAL server) exchange them with the location management server (SLM-S).
//
// Specifications: TS 24.545 (clauses 6.2 and 7), TS 23.032, RFC 3339.
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mcx::seal {

//------------------------------------------------------------------------------
// TS 24.545 clause 7: the content type of a location-info document.
inline constexpr const char *location_mime = "application/vnd.3gpp.seal-location-info+xml";

//------------------------------------------------------------------------------
// TS 23.032 clause 6.1: a position, as <threebytes> codes, and when it was taken.
struct Fix {
  std::uint32_t latitude = 0, longitude = 0;
  std::string timestamp; // RFC 3339
  bool history = false;  // reported in a history location result report
};

//------------------------------------------------------------------------------
// TS 24.545 clause 6.2.2.3.1: the configuration a client reads, and where it reports.
struct Configuration {
  unsigned periodic = 0;         // <periodic-report>, seconds
  unsigned minimum_interval = 0; // <minimum-interval-length>, seconds
  std::string report_uri, history_uri;
};

//------------------------------------------------------------------------------
// TS 24.545 clause 6.2.2.3.1: reads the location reporting configuration a client receives and, in the OpenMCX
// <anyExt> extension, where it reports.
Configuration parse_configuration(std::string_view xml);

//------------------------------------------------------------------------------
// TS 24.545 clause 6.2.2.2.2: a client's report.
std::string report_xml(const std::string &user, const std::string &trigger, const Fix &fix);

//------------------------------------------------------------------------------
// TS 24.545 clause 6.2.20.2: the positions a client stored while it could not report.
std::string history_xml(const std::string &subscription, const std::vector<Fix> &fixes);

//------------------------------------------------------------------------------
// TS 24.545 clause 6.2.6.1.2: an MC service server's subscription.
std::string subscription_xml(const std::string &server, const std::vector<std::string> &users, unsigned interval,
                             unsigned expiry);

//------------------------------------------------------------------------------
// TS 24.545 clause 6.2.6.1.2: the deletion of a subscription (expiry time 0).
std::string unsubscription_xml(const std::string &server, const std::string &subscription);

//------------------------------------------------------------------------------
// TS 24.545 clause 6.2.8.1: an on-demand request; with history, the stored positions too.
std::string request_xml(const std::string &server, const std::vector<std::string> &users, bool history = false);

//------------------------------------------------------------------------------
// TS 24.545 clause 7: a position of a user in a notification or an answer.
struct UserFix {
  std::string user;
  Fix fix;
};

//------------------------------------------------------------------------------
// TS 24.545 clause 7: any answer or notification of the SLM-S.
struct Answer {
  std::string subscription;       // <subscription-identifier>
  std::optional<int> expiry;      // <expiry-time>; 0 when a subscription ended
  std::vector<std::string> users; // <identities-list>
  std::string trigger;            // a notification's trigger-id
  bool notification = false;
  std::vector<UserFix> reports; // <loc-info-report>s
};

//------------------------------------------------------------------------------
// TS 24.545 clause 7: reads an answer or notification of the SLM-S.
Answer parse_answer(std::string_view xml);

} // namespace mcx::seal
