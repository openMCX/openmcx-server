// The MCData server of openMCX: the controlling and participating MCData functions (TS 24.282) for
// short data service, file distribution, IP connectivity, message store and emergency alerts, their
// media plane (TS 24.582) and their security (TS 33.180).
//
// MCData server (TS 23.282 clause 6.4.3.1.2): combined participating and controlling
// MCData functions with the SDS distribution function (TS 24.282).
// Milestone 1 scope: service authorisation (TS 24.282 clause 7.3.3), affiliation (clause 8.3),
// standalone SDS over the signalling control plane (clause 9.2.2) and SDS
// disposition notifications (clause 12.2).
//
// The class is declared here; its member functions are defined in the files of this directory,
// one per topic.
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 24.582 V19.0.0 (Rel-19), TS 23.282 V19.10.0 (Rel-19),
// TS 23.280 V19.10.1 (Rel-19), TS 24.481 V19.3.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19),
// TS 24.379 V19.7.0 (Rel-19), RFC 4975.
#pragma once

#include "mcx/http.hpp"
#include "mcx/ipconn.hpp"
#include "mcx/key_client.hpp"
#include "mcx/location.hpp"
#include "mcx/mcdata.hpp"
#include "mcx/msrp.hpp"
#include "mcx/runtime.hpp"
#include "mcx/xml_security.hpp"

// Shared with the MCPTT and MCVideo servers: Expires and percent-encoding parsing, and the service parts.
#include "../server/request_values.hpp"
#include "parts/alias_registry.hpp"
#include "parts/common_services.hpp"
#include "parts/counters.hpp"
#include "parts/location_service.hpp"
#include "parts/message_parts.hpp"
#include "parts/program.hpp"
#include "parts/served_users.hpp"
#include "parts/task_queue.hpp"

#include <algorithm>
#include <csignal>
#include <ctime>
#include <deque>
#include <iostream>
#include <optional>
#include <set>
#include <sstream>

namespace mcx {
class DataServer {
  // The binding of MCData ID, MCData client ID and public user identity (TS 24.282 clause 7.3.3 step 5a), with the
  // affiliated MCData groups (TS 24.282 clause 8.3), the affiliation status subscription (clause 8.3.2.4) and the CSK
  // of signalling protection (TS 24.282 clause 7.2.2 step 3, TS 33.180 clause 9.5): the shared served user
  // (parts/served_users.hpp).
  using User = ServedUser;

  //------------------------------------------------------------------------------
  // A relayed SDS message awaiting disposition notifications (TS 24.282 clause 9.2.2.4.2 step 4).
  // How long a dispatched SDS waits for its disposition notifications (a local choice; TS 24.282 sets none).
  static constexpr std::uint64_t disposition_wait_ms = 600000;

  struct Dispatched {
    std::string originator, group;
    std::set<std::string> recipients;
    std::uint64_t deadline = 0;
    mcdata::DispositionRequest disposition = mcdata::DispositionRequest::None;
    // Aggregation of group disposition notifications (TS 24.282 clause 12.2.3 step 15c, TDC1).
    std::vector<BodyPart> collected;
    std::set<std::string> finished; // recipients whose last expected notification arrived
    std::uint64_t tdc1 = 0;         // TDC1 running when nonzero
    bool aggregate_sent = false;
  };

  Json cfg_, status_;
  HttpClient http_;
  // ---- Signalling and XML protection (protection.cpp): TS 33.180 clause 9.5, TS 24.282 clause 6.6.3 ----
  // MCData signalling protection: with a client that uploaded a CSK, every
  // application/vnd.3gpp.mcdata-signalling body is an MCData Protected Payload message
  // under that CSK, hop by hop. This function opens what
  // arrives and seals what it sends for each client. The DATA PAYLOAD is left alone:
  // it is protected end to end, if at all.
  std::unique_ptr<KeyClient> keys_;
  unsigned signalling_opened_ = 0, signalling_sealed_ = 0, signalling_refused_ = 0;

  bool protect_signalling() const { return keys_ && cfg_.at("mcdata").value("protect_signalling", false); }

  keying::KeyParameterWireProfile payload_profile() const;

  const keying::KeyMessage *signalling_key(const std::string &sip) const;

  // TS 24.282 clause 6.5.2 with TS 33.180 clause 9.3: the sensitive XML content of TS 24.282 clause 4.6 is
  // encrypted with the client's CSK as the XPK, keyed to the client's MCData ID.
  unsigned xml_encrypted_ = 0, xml_decrypted_ = 0, xml_refused_ = 0;

  bool protects_xml() const { return keys_ && cfg_.at("mcdata").value("confidentiality_protection", false); }

  static xmlsec::Key xml_key_of(const keying::KeyMessage &csk, const std::string &id);

  std::optional<xmlsec::Key> xml_key(const std::string &sip) const;

  static const xmlsec::Profile &xml_profile();

  static bool xml_part(std::string_view type);

  std::vector<BodyPart> encrypt_xml(const std::optional<xmlsec::Key> &key, std::vector<BodyPart> parts);

  std::vector<BodyPart> decrypt_xml(const std::optional<xmlsec::Key> &key, std::vector<BodyPart> parts);

  std::vector<std::pair<std::string, std::string>> seal_msrp(const std::string &owner,
                                                             std::vector<std::pair<std::string, std::string>> bodies);

  std::vector<BodyPart> seal_for_id(const std::string &id, std::vector<BodyPart> parts);

  std::vector<BodyPart> seal_for(const std::string &sip, std::vector<BodyPart> parts);

  std::vector<BodyPart> open_from(const keying::KeyMessage &key, std::vector<BodyPart> parts);

  Control control_;
  SipEngine sip_;
  std::string core_address_, service_uri_;
  std::map<std::string, User> users_; // by public user identity
  std::map<std::string, Dispatched> dispatched_; // by Message ID text

  //------------------------------------------------------------------------------
  // Ad hoc groups created for ad hoc group SDS (TS 24.282 clause 9.2.2.4.2 step 6A), by the
  // server-generated ad hoc group identity: the initiator and the participants.
  struct AdhocGroup {
    std::set<std::string> members;
    std::uint64_t deadline = 0;
  };

  std::map<std::string, AdhocGroup> adhoc_groups_;
  // Functional alias activations (TS 24.282 clause 22.2.2.3.2), as both the server serving the
  // user and the server owning the alias: alias -> MCData IDs in activation order.
  AliasRegistry functional_aliases_;

  //------------------------------------------------------------------------------
  // Outstanding MCData emergency alerts (TS 24.282 clause 16.2.3.1 step 4b iii A): group -> originator ->
  // the alert as notified (mcdata-info fields and the copied location body).
  struct EmergencyAlert {
    std::string organization, functional_alias, location;
  };

  std::map<std::string, std::map<std::string, EmergencyAlert>> emergency_alerts_;

  //------------------------------------------------------------------------------
  // SDS messages delivered to each recipient, kept by the participating function
  // serving the recipient so that an UNDELIVERED notification can store the message
  // for re-delivery (TS 24.282 clause 12.2.2.1 steps 5 and 6). Key: recipient MCData ID and Message ID.
  struct Held {
    mcdata::Info info;
    std::vector<BodyPart> binary;
    std::uint64_t retain_until = 0, redeliver_at = 0; // redeliver_at: TDP1 running when nonzero
    unsigned attempts = 0;
  };

  std::map<std::pair<std::string, std::string>, Held> held_;
  std::deque<std::pair<std::string, std::string>> held_order_;

  //------------------------------------------------------------------------------
  // File distribution over HTTP (TS 24.282 clause 10.2.4): one entry per FD request, by Message ID.
  // TDC2 (file availability timer, TS 24.282 clause 12.4.1.1) runs per entry; the recipients that
  // have not reported a completed download are notified when it expires.
  struct FileTransfer {
    std::string originator, group, file_url, conversation;
    std::set<std::string> recipients, downloaded, rejected;
    std::uint64_t expires = 0;
    std::optional<std::uint8_t> application_id;
    // Aggregation of the group's FD notifications (TS 24.282 clause 12.2.3 step 15c, TDC1).
    std::vector<BodyPart> collected;
    std::set<std::string> finished; // recipients that reported a final disposition
    std::uint64_t tdc1 = 0;
    bool aggregate_sent = false;
    // Release with prior indication (TS 24.282 clause 13.2.4.5): TDC3 runs after the intent is sent.
    std::uint64_t tdc3 = 0;
    bool intent_sent = false, extended = false;
    // TS 24.282 clause 13.2.6.3: the authorised user that announced the release, if it was not the server.
    std::string release_initiator;
    // A transfer over the media plane (TS 24.282 clause 10.2.5): there is no stored file, so no file
    // availability timer; the entry only correlates the disposition notifications.
    bool media_plane = false;
  };

  std::map<std::string, FileTransfer> transfers_;

  //------------------------------------------------------------------------------
  // MCData media plane (TS 24.282 clause 9.2.3 with TS 24.582). The server is the MSRP endpoint on
  // both legs and always listens, so each client connects to it. One session per
  // SIP dialog; the originating session keeps the leg toward the recipient.
  struct MediaSession {
    std::unique_ptr<msrp::Endpoint> endpoint;
    std::string dialog, originator, target, group, message_id;
    std::string owner; // the MCData ID of the client on this leg
    std::string sdp;   // this leg's own media, repeated in a re-INVITE or its answer
    bool originating = false;            // the leg from the sender
    std::vector<std::string> recipients; // the affiliated members of a group request
    std::uint64_t max_bytes = 0;         // the group's SDS size limit, checked on arrival
    // An SDS session (TS 24.282 clause 9.2.4) stays open: every leg of one session shares this key,
    // and each MSRP SEND is relayed to the other legs (TS 24.582 clause 6.3.2.3).
    std::string key;
    bool session = false;
    // File distribution over the media plane (TS 24.282 clause 10.2.5): the legs of one transfer
    // share a key like a session's, but they end when the file has been relayed.
    bool file = false;
    std::uint64_t declared_bytes = 0; // the size selector of the SDP offer
    bool emergency = false;           // the in-progress emergency condition of the communication
    bool imminent = false;            // the in-progress imminent peril condition of a group session
    // An ad hoc group communication (TS 24.282 clause 24): the group is a server-generated
    // ad hoc group, and the recipients reached through a functional alias are
    // told the alias they were called by (TS 24.282 clause 24.4.2.2 step 15b iv).
    bool adhoc = false;
    std::map<std::string, std::string> aliases;
    // TS 24.282 clause 13: the originating leg of a session or transfer measures the
    // communication against the transmission time and data limits.
    std::uint64_t started = 0, relayed_bytes = 0;
    std::vector<std::pair<std::string, std::string>> pending; // bodies to send once bound
    std::string pending_file;                                 // a file to send once bound
    // A file sent on this leg that its recipient has not answered yet: closing
    // the connection before the answer can lose the file in flight.
    bool file_unanswered = false;
    std::uint64_t deadline = 0;
  };

  //------------------------------------------------------------------------------
  // IP connectivity (TS 24.282 clause 20 with TS 24.582 clause 13). The participating and
  // controlling functions are collocated and in the path of the tunnel (TS 24.582 clauses 13.2 and 13.3):
  // one UDP socket faces each client, and the GRE-in-UDP datagrams are relayed
  // between them unchanged.
  struct IpconSession {
    std::string originator, target, called_alias;
    std::string origin_dialog, target_dialog;
    std::unique_ptr<UdpSocket> origin_socket, target_socket;
    ipconn::TunnelMedia origin_peer, target_peer; // each client's end of the tunnel
    std::string origin_sdp, target_sdp;           // this server's end on each leg
    bool established = false;
    std::uint64_t established_at = 0; // for the transmission time limit (TS 24.282 clause 13.2.3.2)
    std::uint64_t deadline = 0;       // the setup timeout, then the idle timeout
    std::uint64_t to_target = 0, to_origin = 0, bytes = 0, dropped = 0;
  };

  std::map<std::string, std::shared_ptr<IpconSession>> ipcons_; // by the dialog of either leg

  //------------------------------------------------------------------------------
  // TS 24.282 clause 10.2.5.2.1: the file attributes of the SDP offer and the FD SIGNALLING PAYLOAD,
  // repeated to each recipient of the transfer.
  struct FileOffer {
    std::string selector, date, description, signalling;
  };

  std::map<std::string, std::shared_ptr<MediaSession>> media_;
  // The I_MESSAGE of a one-to-one media plane offer, by (originator, recipient),
  // until this function offers the communication to the recipient.
  std::map<std::pair<std::string, std::string>, std::string> media_key_mgmt_;

  //------------------------------------------------------------------------------
  // TS 24.282 clause 6.3.7.1: the in-progress emergency and imminent peril states of a group, which
  // the clients mirror as their MDEG and MDIG states (TS 24.282 clause 6.2.8.1).
  struct GroupPriority {
    bool emergency = false, imminent = false;
    std::string originator;
  };

  std::map<std::string, GroupPriority> group_priority_;
  TaskQueue pending_;
  std::uint64_t last_save_ = 0;
  Counters counters_{"sds_one_to_one",
                     "sds_group",
                     "sds_delivered",
                     "notifications",
                     "rejected",
                     "undelivered",
                     "sds_redelivered",
                     "redelivery_abandoned",
                     "aggregates",
                     "fd_requests",
                     "fd_delivered",
                     "fd_downloads",
                     "fd_expired",
                     "fd_terminated",
                     "fd_stopped",
                     "fd_extended",
                     "media_sds",
                     "media_adhoc",
                     "ipconn_sessions",
                     "ipconn_packets",
                     "releases_policy",
                     "releases_server",
                     "releases_authorised",
                     "release_intents",
                     "extensions_accepted",
                     "extensions_rejected",
                     "ipconn_bytes",
                     "ipconn_dropped",
                     "media_delivered",
                     "media_emergency",
                     "media_emergency_cancelled",
                     "media_files",
                     "media_file_bytes",
                     "media_files_delivered",
                     "media_state_notifications",
                     "media_alerts",
                     "media_group_emergency",
                     "media_group_emergency_cancelled",
                     "media_imminent_peril",
                     "media_imminent_peril_cancelled",
                     "media_priority_corrections"};

  Json redelivery() const { return cfg_.at("mcdata").value("redelivery", Json::object()); }

  Json file_distribution() const { return cfg_.at("mcdata").value("fd", Json::object()); }

  void count(const char *name) { counters_.add(name); }

  // ---- Group documents (group_documents.cpp): TS 24.282 clause 6.3.3 ----
  Json internal(const std::string &role, const std::string &path) {
    return common_document(http_, cfg_.at("common"), role, path);
  }

  std::optional<Json> group_document(const std::string &group);

  // ---- Group document subscription as an MCS server (group_documents.cpp): TS 24.481 clause 6.3.13.2.2 ----
  //------------------------------------------------------------------------------
  // One subscription per group read, each a SUBSCRIBE to the PSI of the GMS's
  // subscription proxy function; a refresh is a new subscription (TS 24.481 clause 6.3.13.2.2).
  struct GroupSubscription {
    std::string dialog;
    bool active = false;
    std::uint64_t refresh = 0;
  };

  std::map<std::string, GroupSubscription> group_subscriptions_;
  std::map<std::string, Json> group_cache_;
  std::map<std::string, unsigned> group_docs_{
      {"reads", 0}, {"hits", 0}, {"notifies", 0}, {"changes", 0}, {"subscriptions", 0}};

  void subscribe_group_document(const std::string &group);

  std::optional<SipResponse> group_documents_notified(const SipMessage &notify);

  // ---- Functional aliases (functional_alias.cpp): TS 24.282 clause 22.2.2 ----
  Json profile(const std::string &mcdata_id);

  std::optional<Json> alias_definition(const std::string &alias);

  bool alias_active(const std::string &alias, const std::string &id) const {
    return functional_aliases_.active(alias, id);
  }

  // TS 24.282 clause 22.2.2.2.8: the MCData IDs that have activated an alias, other than the sender.
  std::vector<std::string> alias_users(const std::string &alias, const std::string &sender) const {
    return functional_aliases_.users(alias, sender);
  }

  // TS 24.282 clause 22.2.2.3.6: the functional aliases of a user who logs off or whose authorisation expires are
  // deactivated.
  void deactivate_aliases(const std::string &id) { functional_aliases_.deactivate(id); }

  SipResponse functional_alias_publish(const SipMessage &received, User &user, const BodyPart &pidf);

  // ---- Users (data_server.hpp) ----
  // The service authorised user with the MCData ID (while its authorisation lasts), or nullptr.
  User *by_id(const std::string &id) { return served_by_id(users_, id, true); }

  static std::string service_of(const SipMessage &request);

  static std::vector<SipHeader> copied(const SipMessage &request, std::initializer_list<const char *> names);

  // ---- Delivery (delivery.cpp): TS 24.282 clauses 9.2.2.4.1.1 and 12.2.2.1 ----

  static unsigned limit(const Json &object, const char *key) { return object.is_object() ? object.value(key, 0u) : 0u; }

  static std::size_t payload_size(const mcdata::DataPayload &payload);

  static const BodyPart *part(const SipMessage &request, const char *type);

  static bool accepts(const SipMessage &request, std::string_view icsi);

  SipResponse reject(int status, const std::string &warning, const std::string &user, const char *what);

  void deliver(const User &target, mcdata::Info info, const std::vector<BodyPart> &binary, const std::string &what,
               const std::string &reason = {});

  void hold(const std::string &recipient, const mcdata::Info &info, const std::vector<BodyPart> &binary);

  void undelivered(const std::string &recipient, const std::string &message);

  void redeliver(const std::pair<std::string, std::string> &key, Held &held);

  // ---- Service authorisation and affiliation (authorisation.cpp): TS 24.282 clauses 7.3 and 8.3.2 ----
  SipResponse authorise(const SipMessage &request);

  // authorise: a SIP PUBLISH with Expires 0 logs the user off.
  SipResponse log_off(const std::string &asserted);

  // authorise: the CSK upload and the decryption of the MCData info body, or the refusal.
  std::optional<SipResponse> authorise_csk(const SipMessage &request, const std::string &asserted,
                                           std::string &info_body, std::optional<keying::KeyMessage> &csk,
                                           std::string &uploader);

  SipResponse affiliate(const SipMessage &request, User &user);

  void notify_affiliation(const User &user, const std::string &publication = {}, bool terminated = false);

  void schedule_notify(const User &served, const std::string &publication = {});

  SipResponse affiliation_subscribe(const SipMessage &request, User &subscriber);

  void implicit_affiliations(User &user);

  bool affiliated(const std::string &id, const std::string &group);

  const User *affiliated_member(const Json &member, const std::string &group, const std::string &except);

  // ---- Standalone SDS over the signalling control plane (sds.cpp): TS 24.282 clause 9.2.2 ----
  SipResponse sds(const SipMessage &sip_request, const User &sender, mcdata::Info info, const BodyPart &signalling,
                  const BodyPart &data);

  // sds: the signalling control plane size limit, or the refusal.
  std::optional<SipResponse> sds_cplane_limit(const Json &service, const User &sender, const std::string &request,
                                              std::size_t size);

  // sds: the target of a one-to-one SDS and its authorisation, a functional alias redirection, or the refusal.
  std::optional<SipResponse> sds_one_to_one(const SipMessage &sip_request, const User &sender, const mcdata::Info &info,
                                            const std::string &request, const Json &policy, std::size_t size,
                                            std::vector<const User *> &targets);

  // sds: the group checks and affiliated recipients of a group SDS, or the refusal.
  std::optional<SipResponse> sds_group(const User &sender, mcdata::Info &info,
                                       const std::string &request, std::size_t size,
                                       std::vector<const User *> &targets);

  std::optional<SipResponse> adhoc_recipients(const SipMessage &sip_request, const User &sender, mcdata::Info &info,
                                              const Json &policy, std::vector<const User *> &targets,
                                              std::map<std::string, std::string> &called);

  // adhoc_recipients: the members an ad hoc group participant criteria list designates, or the refusal.
  std::optional<SipResponse> adhoc_criteria_members(const User &sender, const mcdata::Info &info,
                                                    std::vector<std::string> &requested);

  // adhoc_recipients: the participants delivered to and those excluded by their profile.
  void adhoc_participation_filter(const std::vector<std::string> &participants, std::vector<const User *> &targets,
                                  std::vector<std::string> &excluded);

  SipResponse notification(const SipMessage &request, const User &notifier, mcdata::Info info,
                           const BodyPart &signalling);

  Json aggregation() const { return cfg_.at("mcdata").value("aggregation", Json::object()); }

  void send_aggregate(const std::string &message, Dispatched &sent);

  // ---- File distribution over HTTP (file_distribution.cpp): TS 24.282 clause 10.2.4 ----
  bool file_available(const std::string &url);

  void delete_file(const std::string &url);

  std::uint64_t file_availability(const mcdata::FdSignalling &fd);

  SipResponse media_storage_discovery(const User &user, const mcdata::Info &info);

  SipResponse fd(const SipMessage &received, const User &sender, mcdata::Info info, const BodyPart &signalling);

  // fd: the recipient of a one-to-one FD request and its authorisation, a functional alias redirection, or the
  // refusal.
  std::optional<SipResponse> fd_one_to_one(const SipMessage &received, const User &sender, const mcdata::Info &info,
                                           const Json &policy, std::uint64_t size, std::vector<const User *> &targets,
                                           std::string &called_alias);

  // fd: the group checks and affiliated recipients of a group FD request, or the refusal.
  std::optional<SipResponse> fd_group(const User &sender, mcdata::Info &info, std::uint64_t size,
                                      std::vector<const User *> &targets);

  SipResponse fd_notification(const User &sender, mcdata::Info info, const BodyPart &signalling);

  void send_file_aggregate(const std::string &message, FileTransfer &transfer);

  void file_expired(const std::string &message_id, FileTransfer &transfer,
                    mcdata::FdNetworkNotificationType reason = mcdata::FdNetworkNotificationType::Expired);

  SipResponse fd_termination(const User &sender, const BodyPart &signalling, const std::string &reason = {});

  // fd_termination: an authorised user's answer to the originator's request for extension.
  SipResponse fd_extension_response(const User &sender, const mcdata::FdHttpTermination &request,
                                    const std::string &message_id, FileTransfer &transfer);

  // fd_termination: the originator's request for extension, granted or forwarded to the authorised user.
  SipResponse fd_extension_request(const User &sender, const mcdata::FdHttpTermination &request,
                                   const std::string &message_id, FileTransfer &transfer);

  void send_termination(const std::string &id, const mcdata::FdHttpTermination &message,
                        const std::string &reason = {});

  bool stop_transmission(const std::string &message_id, const std::string &reason);

  void release_intent(const std::string &message_id, FileTransfer &transfer,
                      const std::string &reason = "file availability is about to expire");

  // ---- Emergency alerts (emergency_alert.cpp): TS 24.282 clause 16.2 ----
  void alert_message(const User &target, mcdata::Info info, const std::string &location);

  void late_in_progress_state(const User &user, const std::string &group);

  void late_alerts(const User &user, const std::string &group);

  SipResponse emergency_alert(const SipMessage &request, User &user, mcdata::Info info);

  // emergency_alert: the cancellation of an emergency alert: state, notices to the members and the receipt.
  void emergency_alert_cancelled(const User &user, const mcdata::Info &info, const std::string &group,
                                 const Json &settings);

  void schedule_receipt(const User &user, mcdata::Info receipt);

  // ---- Incoming SIP MESSAGE requests (message.cpp) ----
  SipResponse message(const SipMessage &sip_request);

  // message: an FD request, notification or termination over HTTP.
  SipResponse message_fd(const SipMessage &sip_request, const User &user, const mcdata::Info &info,
                         const BodyPart &signalling, mcdata::MessageType type);

  // ---- Media plane sessions (media_session.cpp): TS 24.282 clauses 9.2.3 and 10.2.5, TS 24.582 ----
  std::shared_ptr<MediaSession> media_session(const std::string &dialog);

  msrp::Endpoint::Callbacks media_callbacks(const std::shared_ptr<MediaSession> &session);

  std::string media_address() const;

  MsrpMedia media_offer(const std::shared_ptr<MediaSession> &session);

  SipResponse media_reinvite(const SipMessage &request, const std::shared_ptr<MediaSession> &leg);

  SipResponse media_group_reinvite(const std::shared_ptr<MediaSession> &leg, const mcdata::Info &info);

  SipResponse media_invite(const SipMessage &request);

  // The state of an initial media-plane INVITE (media_invite) as its steps determine it.
  struct MediaInvite {
    bool adhoc = false, adhoc_session = false, session = false, file_request = false, group_request = false;
    const char *what = "media-sds";
    std::string target, group;
    std::vector<std::string> recipients;
    std::uint64_t group_limit = 0;
    std::map<std::string, std::string> called_aliases;
    FileOffer file_offer;
    mcdata::FdSignalling file_signalling;
    std::uint64_t file_bytes = 0;
    bool corrected = false, alert = false, alert_refused = false;
    std::string alert_location;
  };

  // media_invite: the kind of communication requested, or its refusal.
  std::optional<SipResponse> media_invite_kind(const User &user, const mcdata::Info &info, const BodyPart &sdp,
                                               MediaInvite &invite);

  // media_invite: the participants of an ad hoc group communication, or the refusal.
  std::optional<SipResponse> media_invite_adhoc_targets(const SipMessage &request, const User &user, mcdata::Info &info,
                                                        const Json &policy, MediaInvite &invite);

  // media_invite: the group checks and the affiliated recipients of a group communication, or the refusal.
  std::optional<SipResponse> media_invite_group_targets(const User &user, const mcdata::Info &info,
                                                        MediaInvite &invite);

  // media_invite: the recipient of a one-to-one communication and its authorisation, or the refusal.
  std::optional<SipResponse> media_invite_private_target(const User &user, const Json &policy,
                                                         const BodyPart *resources, MediaInvite &invite);

  // media_invite: the client's SDP offer and its PCK, or a 488 refusal.
  std::optional<SipResponse> media_invite_sdp_offer(const User &user, const BodyPart &sdp, const MediaInvite &invite,
                                                    MsrpMedia &offer);

  // media_invite: the FD signalling payload and file size checks of an FD request, or the refusal.
  std::optional<SipResponse> media_invite_file(const SipMessage &request, const User &user, const Json &policy,
                                               const MsrpMedia &offer, MediaInvite &invite);

  // media_invite: an emergency or imminent peril request, its authorisation and group state, or the refusal.
  std::optional<SipResponse> media_invite_priority(const SipMessage &request, User &user, const mcdata::Info &info,
                                                   const Json &policy, MediaInvite &invite);

  // media_invite: the originating leg and this server's SDP answer, kept in media_.
  std::shared_ptr<MediaSession> media_invite_leg(const SipMessage &request, const User &user, const MediaInvite &invite,
                                                 const std::string &level, MsrpMedia &answer);

  // media_invite: the queued invitation of every recipient of a session or file transfer.
  void media_invite_recipients(const User &user, const MediaInvite &invite, const MediaSession &leg,
                               const std::string &level);

  // media_invite: the 200 (OK) response, a SIP INFO correction and the in-progress state notifications.
  void media_invite_answer(const SipMessage &request, const User &user, const mcdata::Info &info,
                           const MediaInvite &invite, const MediaSession &leg, const std::string &level,
                           SipResponse &response);

  // media_invite: the file transfer record that disposition notifications are correlated with.
  void media_invite_transfer(const User &user, const MediaInvite &invite);

  // ---- IP connectivity (ipconn.cpp): TS 24.282 clause 20, TS 24.582 clause 13 ----
  SipResponse ipcon_invite(const SipMessage &request, const User &user, const mcdata::Info &info, const BodyPart &sdp,
                           const BodyPart *resources);

  // ipcon_invite: the IP connectivity feature tag and ICSI are in Accept-Contact.
  static bool ipcon_accept_contact(const SipMessage &request);

  // ipcon_invite: a 300 (Multiple Choices) redirection for a functional alias target, or its refusal.
  std::optional<SipResponse> ipcon_alias_redirect(const User &user, const mcdata::Info &info,
                                                  const std::string &target);

  Json ipconn_config() const { return cfg_.at("mcdata").value("ipconn", Json::object()); }

  std::string tunnel_address() const;

  void ipcon_invite_target(const std::shared_ptr<IpconSession> &tunnel, const mcdata::Info &info,
                           const std::string &sip, const std::string &originator_sip);

  void ipcon_target_answered(const std::shared_ptr<IpconSession> &tunnel, const SipResponse &response);
  //------------------------------------------------------------------------------
  // TS 24.582 clauses 13.2 and 13.3: the relay. A datagram is accepted only from the
  // address and source port the client named in its SDP, is checked to be
  // GRE-in-UDP carrying IP, and goes to the other client unchanged.
  void ipcon_tick() try {
    const auto now = monotonic_ms();
    std::set<std::shared_ptr<IpconSession>> seen;
    std::vector<std::shared_ptr<IpconSession>> expired;
    for (auto &[dialog, tunnel] : ipcons_) {
      if (!seen.insert(tunnel).second) continue;
      if (tunnel->established) {
        ipcon_relay(*tunnel, *tunnel->origin_socket, tunnel->origin_peer, *tunnel->target_socket, tunnel->target_peer,
                    tunnel->to_target);
        ipcon_relay(*tunnel, *tunnel->target_socket, tunnel->target_peer, *tunnel->origin_socket, tunnel->origin_peer,
                    tunnel->to_origin);
      }
      if (tunnel->deadline <= now) expired.push_back(tunnel);
    }
    for (const auto &tunnel : expired) {
      event("mcdata_ipconn_released", {{"user_id", tunnel->originator},
                                       {"target", tunnel->target},
                                       {"reason", tunnel->established ? "idle" : "setup timeout"}});
      ipcons_.erase(tunnel->origin_dialog);
      ipcons_.erase(tunnel->target_dialog);
      if (!tunnel->established) {
        SipResponse timeout;
        timeout.status_code = 408;
        sip_.answer(tunnel->origin_dialog, timeout);
      } else {
        sip_.bye(tunnel->origin_dialog);
      }
      if (!tunnel->target_dialog.empty()) sip_.bye(tunnel->target_dialog);
    }
  } catch (const std::exception &error) {
    event("mcdata_ipconn_failed", {{"reason", error.what()}});
  }

  void ipcon_relay(IpconSession &tunnel, UdpSocket &from, const ipconn::TunnelMedia &sender, UdpSocket &to,
                   const ipconn::TunnelMedia &receiver, std::uint64_t &relayed);

  void ipcon_released(const std::string &dialog);

  // ---- Media plane delivery and priority conditions (media_delivery.cpp): TS 24.582 clauses 6.3 and 7.3 ----
  void media_file_received(const std::shared_ptr<MediaSession> &session, const msrp::Message &message);

  void media_received(const std::shared_ptr<MediaSession> &session, const msrp::Message &message);

  std::vector<SipHeader> media_priority_headers(const char *level = "emergency") const;

  const char *group_level(const std::string &group) const;

  static bool valid_priority_combination(const mcdata::Info &info);

  bool priority_authorised(const std::string &user, const std::string &group, bool emergency, bool enable);

  SipResponse reject_priority(const std::string &user, bool emergency);

  void send_priority_info(const std::string &dialog, const std::string &user, const std::string &group,
                          std::optional<bool> imminent = false, std::optional<bool> emergency = true,
                          std::optional<bool> alert = std::nullopt);

  void notify_in_progress_state(const std::string &group, const std::string &originator,
                                const std::vector<std::string> &participants, bool emergency, bool imminent,
                                const std::string &location = {});

  bool group_alert(const SipMessage &request, User &user, const std::string &group, std::string &location);

  void media_group_notify(const std::shared_ptr<MediaSession> &leg, bool emergency, bool imminent);

  std::string media_deliver(const std::string &originator, const std::string &target, const std::string &group,
                            const std::string &message_id,
                            const std::vector<std::pair<std::string, std::string>> &bodies, const std::string &key = {},
                            const std::string &level = "normal", const FileOffer *file = nullptr,
                            const std::string &alert_location = {}, bool alert = false,
                            const std::string &called_alias = {}, bool session = false,
                            SipResponseHandler answered = {});

  // ---- Release of communications over the media plane (release.cpp): TS 24.282 clause 13.2 ----
  //------------------------------------------------------------------------------
  // TS 24.282 clause 13 over the media plane: a release announced to the originator (clause 13.2.4)
  // by the server or by an authorised user (clause 13.2.6.2), waiting for TDC3 or for an
  // extension request.
  struct ReleaseProcess {
    std::string initiator; // the authorised user, or empty for the server
    std::string reason;
    std::uint64_t tdc3 = 0;
    bool extension_requested = false;
    std::string remaining; // the remaining amount of data the originator reported
  };

  std::map<std::string, ReleaseProcess> releases_; // by session key
  std::map<std::string, std::string> bye_reasons_; // the Reason of a received BYE, by dialog

  Json release_config() const { return cfg_.at("mcdata").value("release", Json::object()); }

  static std::string reason_header(const std::string &text);

  static std::string reason_text(const std::string &header);

  std::shared_ptr<MediaSession> originating_leg(const std::string &key);

  std::shared_ptr<MediaSession> leg_of(const std::string &key, const std::string &owner);

  void release_communication(const std::string &key, const std::string &reason, const char *counter);

  void release_tunnel(std::shared_ptr<IpconSession> tunnel, const std::string &reason, const char *counter);

  void send_com_release(const std::string &dialog, const std::vector<BodyPart> &parts, const std::string &reason = {},
                        std::function<void(const SipResponse &)> answered = {});

  bool release_intent_media(const std::string &key, const std::string &initiator, const std::string &reason,
                            bool query);

  void extension_response(const std::string &key, bool accepted);

  SipResponse com_release_info(const SipMessage &sip_request);

  // com_release_info: the release of an IP connectivity session by an authorised user, or the refusal.
  std::optional<SipResponse> com_release_tunnel(const SipMessage &sip_request,
                                                const std::shared_ptr<IpconSession> &tunnel, const BodyPart *signalling,
                                                const std::string &reason);

  // com_release_info: the originator's remaining amount of data, or the refusal.
  std::optional<SipResponse> com_release_remaining(const MediaSession &leg, const std::string &key,
                                                   const BodyPart &payload);

  // com_release_info: the originator's request for extension of an announced release, or the refusal.
  std::optional<SipResponse> com_release_extension_request(const MediaSession &leg, const std::string &key,
                                                           const BodyPart &signalling);

  void release_tick(std::uint64_t now);

  void media_released(const std::string &dialog);
  //------------------------------------------------------------------------------
  // The media plane tick: the release timers (TDC3), the bodies and files waiting for a leg's
  // connection, and the release of expired legs.
  void media_tick() try {
    const auto now = monotonic_ms();
    release_tick(now);
    for (auto it = media_.begin(); it != media_.end();) {
      auto &session = it->second;
      if (session->endpoint) session->endpoint->poll();
      if (!session->pending.empty() && session->endpoint && session->endpoint->connected()) {
        session->deadline = now + cfg_.at("mcdata").value("media", Json::object()).value("session_ms", 60000u);
        session->endpoint->send_parts(seal_msrp(session->owner, session->pending));
        session->pending.clear();
        count("media_delivered");
        event("mcdata_media_sds_delivered", {{"user_id", session->target}, {"message_id", session->message_id}});
      }
      if (!session->pending_file.empty() && session->endpoint && session->endpoint->connected()) {
        // TS 24.582 clause 7.2.3: the file follows the binding of the recipient's connection.
        session->deadline = now + cfg_.at("mcdata").value("media", Json::object()).value("session_ms", 60000u);
        session->endpoint->send(std::string(mcdata::file_mime), session->pending_file);
        session->file_unanswered = true;
        event("mcdata_media_file_delivered", {{"user_id", session->target}, {"bytes", session->pending_file.size()}});
        session->pending_file.clear();
      }
      if (session->deadline && session->deadline <= now) {
        const auto dialog = session->dialog;
        event("mcdata_media_session_released", {{"dialog", dialog}, {"message_id", session->message_id}});
        it = media_.erase(it);
        if (!dialog.empty()) sip_.bye(dialog);
        continue;
      }
      ++it;
    }
  } catch (const std::exception &error) {
    // The media plane must never take the server down.
    event("mcdata_media_failed", {{"reason", error.what()}});
  }

  // ---- The MCData message store (message_store.cpp): TS 24.282 clause 21 ----
  // TS 24.282 clause 21.2.5A: the participating function deposits the communications so chosen in the
  // user's storage area over MCData-8, as an object of the user's Inbox.
  //------------------------------------------------------------------------------
  // TS 24.282 clause 21.3.3: each user's choice of communications to store, within what the user
  // profile allows (<allow-store-comms-in-msgstore>, <allow-store-private-comms-in-msgstore>,
  // and <allow-store-group-comm-in-msgstore> per group: "store_comms",
  // "store_private_comms" and "store_group_comms" of the profile's "mcdata" object).
  struct StoragePrefs {
    bool all_private = false, all_group = false;
    std::set<std::string> private_on, private_off, group_on, group_off;
  };

  std::map<std::string, StoragePrefs> storage_;
  Counters msgstore_counters_{"controls", "refused", "deposited", "deposit_failures"};

  void msgstore_count(const char *key) { msgstore_counters_.add(key); }

  Json msgstore_settings() const { return cfg_.at("mcdata").value("msgstore", Json::object()); }

  Json storage_rights(const std::string &id);

  bool group_storage_allowed(const Json &rights, const std::string &group);

  bool stores(const std::string &user, const std::string &other, const std::string &group);

  SipResponse msgstore_refusal(int status, const std::string &warning, const std::string &user);

  SipResponse msgstore_control(const SipMessage &request, const User &user, const mcdata::Info &info);

  static std::string iso_now();

  //------------------------------------------------------------------------------
  // One communication of a user, deposited in its storage area (TS 24.282 clause 21.2.5A.1): the SDS
  // messages as its payload parts, or a file by the URL of the content server, which
  // the message store fetches (retrieveFile absent).
  struct Deposit {
    std::string user, direction, request_type, from, message_id, conversation_id, group, file_url, text;
    std::vector<std::string> to;
    std::vector<BodyPart> parts;
  };

  void deposit(Deposit entry);

  void store_communication(const User &originator, const std::vector<const User *> &targets, const mcdata::Info &info,
                           const std::vector<BodyPart> &binary, const std::string &message_id,
                           const std::string &conversation_id, const std::string &file_url);

  // ---- The shared service parts (src/server/parts): location (TS 24.282 clause 17.2, with clauses 6.3.7.1.6 and
  // 6.3.7.1.7) ----
  //------------------------------------------------------------------------------
  // The host of this server's service parts (service_parts.cpp, location.cpp): the users,
  // mcdata-info and protection the shared procedures need, called per request.
  class PartsGlue final : public LocationHost {
  public:
    explicit PartsGlue(DataServer &server) : server_(server) {}

    // ServiceHost (service_parts.cpp).
    std::vector<BodyPart> seal_for_client(const std::string &sip, std::vector<BodyPart> parts) override;
    [[nodiscard]] std::string service_uri() const override;
    Json common_document(const std::string &role, const std::string &path) override;
    Json introspect(const std::string &token) override;
    void send_message(const std::string &uri, const std::string &type, const std::string &body,
                      const std::vector<SipHeader> &headers, SipResponseHandler handler) override;
    void publish(const std::string &uri, const std::string &type, const std::string &body,
                 const std::vector<SipHeader> &headers, SipResponseHandler handler) override;
    void respond(const std::string &transaction, const SipResponse &response) override;
    void schedule(std::function<void()> task) override;
    // LocationHost (location.cpp).
    [[nodiscard]] Json location_settings() const override;
    Json location_profile(const std::string &id) override;
    std::optional<LocationUser> location_user_by_id(const std::string &id) override;
    std::optional<LocationUser> location_user_by_sip(const std::string &sip) override;
    void each_location_user(const std::function<void(const std::string &id, const std::string &peer)> &visit) override;
    bool location_group_member(const std::string &group, const std::string &id) override;
    std::vector<std::string> location_alias_users(const std::string &alias) override;
    LocationInfo location_info(const SipMessage &message, const BodyPart &info_part) override;
    std::vector<BodyPart> location_info_parts(const LocationInfo &info) override;
  private:
    DataServer &server_;
  };

  PartsGlue parts_glue_{*this};
  LocationService location_{parts_glue_, mcdata_service, mcdata_location_traits};

  // ---- SIP dispatch (sip_dispatch.cpp) ----
  SipResponse incoming(const SipMessage &request);

  SipResponse dispatch(const SipMessage &request);

  // ---- Run loop (data_server.cpp) ----
  void tick();

  // tick: TDC1, TDC2 and TDC3 of the file transfers, with the release intent before TDC2 expires.
  void file_transfer_timers(std::uint64_t now, unsigned indication);

  // tick: the status file, written at most every 200 ms.
  void save_status();

  // save_status: the media sessions, group priority states, file transfers and held messages.
  void status_communications();

  // save_status: the functional aliases, emergency alerts, IP connectivity sessions, releases and ad hoc groups.
  void status_procedures();

public:
  DataServer(Json cfg, bool disable_tls);

  void run();
};
} // namespace mcx
