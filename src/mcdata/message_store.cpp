//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The MCData message store: control of the storage of communications and the deposit of stored communications.
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 23.282 V19.10.0 (Rel-19).

#include "data_server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// Helper: the MCData part of a user's profile, which holds its storage rights (TS 24.282 clause 21.3.1 item 1);
// empty when the profile cannot be read.
Json DataServer::storage_rights(const std::string &id) {
  try {
    return profile(id).value("mcdata", Json::object());
  } catch (const std::exception &) {
    return Json::object();
  }
}

//------------------------------------------------------------------------------
// Helper: whether the user's rights allow the storage of the communications of a group (TS 24.282 clause 21.3.3.2
// steps 4c and 4e).
bool DataServer::group_storage_allowed(const Json &rights, const std::string &group) {
  return rights.value("store_comms", false) && listed(rights.value("store_group_comms", Json::array()), group);
}

//------------------------------------------------------------------------------
// TS 24.282 clause 21.3.1: whether a communication is to be stored for the user: its profile allows it, and the
// user enabled it for this group or this private partner.
bool DataServer::stores(const std::string &user, const std::string &other, const std::string &group) {
  const auto found = storage_.find(user);
  if (found == storage_.end()) return false;
  const auto &prefs = found->second;
  const auto rights = storage_rights(user);
  if (!rights.value("store_comms", false)) return false;
  if (!group.empty())
    return group_storage_allowed(rights, group) &&
           ((prefs.all_group && !prefs.group_off.contains(group)) || prefs.group_on.contains(group));
  return rights.value("store_private_comms", false) &&
         ((prefs.all_private && !prefs.private_off.contains(other)) || prefs.private_on.contains(other));
}

//------------------------------------------------------------------------------
// Helper: a refused request for control of the storage of communications, counted.
SipResponse DataServer::msgstore_refusal(int status, const std::string &warning, const std::string &user) {
  msgstore_count("refused");
  return reject(status, warning, user, "msgstore-ctrl");
}

//------------------------------------------------------------------------------
// TS 24.282 clause 21.3.3.2: a "SIP MESSAGE request for controlling the storage of the MCData
// communications into MCData message store".
SipResponse DataServer::msgstore_control(const SipMessage &request, const User &user, const mcdata::Info &info) {
  static const std::string unauthorised = "234 user not authorized to enable or disable the storage of MCData "
                                          "communications into the MCData message store";
  static const std::string no_target = "235 unable to determine target user or group for enabling or disabling the "
                                       "storage of MCData communications into the MCData message store";
  const auto rights = storage_rights(user.id);

  // Step 4a.
  if (!rights.value("store_comms", false)) return msgstore_refusal(403, unauthorised, user.id);
  // Step 4b.
  if (info.store_all_private && !rights.value("store_private_comms", false))
    return msgstore_refusal(403, unauthorised, user.id);

  // Step 4c: at least one group must allow the storage of its communications.
  if (info.store_all_group && rights.value("store_group_comms", Json::array()).empty())
    return msgstore_refusal(403, unauthorised, user.id);
  const auto *list_part = part(request, mcdata::msgstore_ctrl_mime);
  // Step 4d.
  if (!list_part && !info.store_all_private && !info.store_all_group) return msgstore_refusal(403, no_target, user.id);
  mcdata::MsgStoreControl control;
  if (list_part) {
    try {
      control = mcdata::parse_msgstore_control(list_part->body);
    } catch (const std::exception &) {
      return msgstore_refusal(403, no_target, user.id);
    }
  }

  // Step 4e: every group named must allow the storage of its communications.
  if (!info.store_all_group)
    for (const auto *groups : {&control.enable_groups, &control.disable_groups})
      for (const auto &group : *groups)
        if (!group_storage_allowed(rights, group)) return msgstore_refusal(403, unauthorised, user.id);

  // Step 4f names a resource-lists body, but the client procedure (TS 24.282 clause 21.3.2.2 step 6)
  // sends the users and groups in the annex D.7 body: either is accepted.
  if ((!info.store_specific_private.empty() || !info.store_specific_group.empty()) && !list_part &&
      !part(request, resource_lists_mime))
    return msgstore_refusal(403, no_target, user.id);
  auto &prefs = storage_[user.id];

  // Step 5.
  if (info.store_all_private) {
    prefs.all_private = *info.store_all_private;
    prefs.private_on.clear();
    prefs.private_off.clear();
  } else if (info.store_specific_private == "enable") {
    for (const auto &id : control.enable_private) {
      prefs.private_on.insert(id);
      prefs.private_off.erase(id);
    }
  } else if (info.store_specific_private == "disable") {
    for (const auto &id : control.disable_private) {
      prefs.private_on.erase(id);
      prefs.private_off.insert(id);
    }
  }
  if (info.store_all_group) {
    prefs.all_group = *info.store_all_group;
    prefs.group_on.clear();
    prefs.group_off.clear();
  } else if (info.store_specific_group == "enable") {
    for (const auto &group : control.enable_groups) {
      prefs.group_on.insert(group);
      prefs.group_off.erase(group);
    }
  } else if (info.store_specific_group == "disable") {
    for (const auto &group : control.disable_groups) {
      prefs.group_on.erase(group);
      prefs.group_off.insert(group);
    }
  }
  msgstore_count("controls");
  event("mcdata_msgstore_control", {{"user_id", user.id},
                                    {"all_private", prefs.all_private},
                                    {"all_group", prefs.all_group},
                                    {"private", prefs.private_on},
                                    {"groups", prefs.group_on},
                                    {"private_off", prefs.private_off},
                                    {"groups_off", prefs.group_off}});

  // Step 6: 200, asserting the participating function's identity.
  SipResponse response;
  response.status_code = 200;
  response.headers = {{"P-Asserted-Identity", "<" + service_uri_ + ">"}};
  return response;
}

//------------------------------------------------------------------------------
// Helper: the current UTC time in ISO 8601 form, for the Date attribute of a deposited object.
std::string DataServer::iso_now() {
  const auto now = std::time(nullptr);
  std::tm tm{};
  gmtime_r(&now, &tm);
  char text[32];
  std::strftime(text, sizeof text, "%Y-%m-%dT%H:%M:%SZ", &tm);
  return text;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 21.2.5A.1 (TS 23.282 clause 7.13.3.8): deposit an object of an MCData user in the MCData
// message store with an HTTP POST request of the NMS REST API: the attributes of the communication, and its bodies
// or the URL of its file.
void DataServer::deposit(Deposit entry) {
  const auto settings = msgstore_settings();
  if (!settings.contains("uri")) return;
  Json attributes = Json::array();
  const auto attribute = [&](const char *name, const std::vector<std::string> &values) {
    if (!values.empty() && !values.front().empty()) attributes.push_back({{"name", name}, {"value", values}});
  };
  attribute("Date", {iso_now()});
  attribute("Direction", {entry.direction});
  attribute("Request-Type", {entry.request_type});
  attribute("From", {entry.from});
  attribute("To", entry.to);
  attribute("Group-Id", {entry.group});
  attribute("Message-Id", {entry.message_id});
  attribute("Conversation-Id", {entry.conversation_id});
  attribute("Text", {entry.text});
  Json object = {{"attributes", {{"attribute", attributes}}},
                 {"flags", {{"flag", {"\\Recent"}}}},
                 {"correlationId", entry.message_id}};
  const auto url = settings.at("uri").get<std::string>() + "/nms/v1/" + url_encode(settings.value("store", "mcdata")) +
                   "/" + url_encode(entry.user) + "/objects";
  std::string content_type, body;
  if (!entry.file_url.empty()) {
    object["payloadPart"] = Json::array({{{"contentType", "application/octet-stream"}, {"href", entry.file_url}}});
    content_type = "application/json";
    body = Json{{"object", object}}.dump();
  } else {
    const auto boundary = "nms-" + random_id();
    body = "--" + boundary +
           "\r\nContent-Disposition: form-data; name=\"root-fields\"\r\nContent-Type: application/json\r\n\r\n" +
           Json{{"object", object}}.dump() + "\r\n";
    for (const auto &attachment : entry.parts)
      body += "--" + boundary +
              "\r\nContent-Disposition: form-data; name=\"attachments\"\r\nContent-Type: " + attachment.content_type +
              "\r\n\r\n" + attachment.body + "\r\n";
    body += "--" + boundary + "--\r\n";
    content_type = "multipart/form-data; boundary=" + boundary;
  }
  const auto &common = cfg_.at("common");
  try {
    const auto reply =
        http_.request("POST", url, body, {{"Content-Type", content_type}}, common.at("client_id"), common.at("secret"));
    if (reply.status != 201) throw std::runtime_error("message store answered " + std::to_string(reply.status));
    msgstore_count("deposited");
    event("mcdata_msgstore_deposit", {{"user_id", entry.user},
                                      {"direction", entry.direction},
                                      {"request_type", entry.request_type},
                                      {"message_id", entry.message_id},
                                      {"file", !entry.file_url.empty()}});
  } catch (const std::exception &error) {
    msgstore_count("deposit_failures");
    event("mcdata_msgstore_deposit_failed", {{"user_id", entry.user}, {"reason", error.what()}});
  }
}

//------------------------------------------------------------------------------
// TS 24.282 clause 21.3.1: after an SDS or FD request has been passed on, the communication is stored for each user
// who enabled it: the originator's copy, if it is served here, and each recipient's served here.
void DataServer::store_communication(const User &originator, const std::vector<const User *> &targets,
                                     const mcdata::Info &info, const std::vector<BodyPart> &binary,
                                     const std::string &message_id, const std::string &conversation_id,
                                     const std::string &file_url) {
  if (!msgstore_settings().contains("uri") || storage_.empty()) return;
  std::string text;
  for (const auto &body : binary)
    if (body.content_type == mcdata::payload_mime && !body.body.empty() &&
        (static_cast<std::uint8_t>(body.body[0]) & 0x40) == 0) {
      try {
        for (const auto &payload : mcdata::decode_data_payload(body.body).payloads)
          if (payload.type == mcdata::ContentType::Text) text += payload.data;
      } catch (const std::exception &) {
        // An undecodable payload adds no text to the stored copy.
      }
    }
  std::vector<std::string> to;
  for (const auto *target : targets) to.push_back(target->id);
  const auto group = info.calling_group;
  std::vector<BodyPart> parts;
  for (const auto &body : binary)
    if (body.content_type == mcdata::signalling_mime || body.content_type == mcdata::payload_mime)
      parts.push_back(body);
  std::vector<Deposit> deposits;
  if (stores(originator.id, to.size() == 1 && group.empty() ? to.front() : std::string{}, group))
    deposits.push_back({originator.id, "Out", info.request_type, originator.id, message_id, conversation_id, group,
                        file_url, text, to, parts});
  for (const auto *target : targets)
    if (stores(target->id, originator.id, group))
      deposits.push_back({target->id,
                          "In",
                          info.request_type,
                          originator.id,
                          message_id,
                          conversation_id,
                          group,
                          file_url,
                          text,
                          {target->id},
                          parts});
  for (auto &entry : deposits) pending_.push_back([this, entry] { deposit(entry); });
}

} // namespace mcx
