// Location information from the SEAL location management server: the server as location management client
// subscribes to, requests and receives location reports (member functions of McServer).
//
// Specifications: TS 24.545, TS 23.434.

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.545: the root URL of the location management server's HTTP resources.
std::string McServer::seal_root() const {
  const auto &common = cfg_.at("common");
  if (!common.contains("lms")) throw std::runtime_error("no location management server is configured");
  return common.at("lms").get<std::string>() + "/seal-lm/v1";
}

//------------------------------------------------------------------------------
// TS 24.545: POST a location management document to a resource of the location management server.
HttpResponse McServer::seal_post(const std::string &path, const std::string &body) {
  const auto &common = cfg_.at("common");
  return http_.request("POST", seal_root() + path, body,
                       {{"Content-Type", seal::location_mime}, {"Accept", seal::location_mime}}, common.at("client_id"),
                       common.at("secret"));
}

//------------------------------------------------------------------------------
// Helper: the non-empty items of a comma-separated list.
std::vector<std::string> McServer::comma_list(const std::string &text) {
  std::vector<std::string> out;
  for (std::size_t start = 0; start <= text.size();) {
    const auto end = std::min(text.find(',', start), text.size());
    if (end > start) out.push_back(text.substr(start, end - start));
    start = end + 1;
  }
  return out;
}

//------------------------------------------------------------------------------
// Helper: record the location reports of an answer or notification in the status, as the current position or
// in the history of each user; `how` names the way they came (request or notification).
void McServer::seal_record(const seal::Answer &answer, const char *how) {
  for (const auto &report : answer.reports) {
    Json entry = {{"latitude", location::decode_latitude(report.fix.latitude)},
                  {"longitude", location::decode_longitude(report.fix.longitude)},
                  {"encoded", {{"latitude", report.fix.latitude}, {"longitude", report.fix.longitude}}},
                  {"timestamp", report.fix.timestamp},
                  {"via", how}};
    if (report.fix.history) {
      auto &list = seal_status_["history"][report.user];
      if (!list.is_array()) list = Json::array();
      list.push_back(entry);
    } else {
      seal_status_["positions"][report.user] = entry;
    }
  }
}

//------------------------------------------------------------------------------
// TS 24.545: subscribe to the location of users at the location management server and start the thread that
// polls the notification channel.
// seal-subscribe <MCPTT ID>[,...] <interval> [<expiry>]
void McServer::seal_subscribe(const std::string &users, unsigned interval, unsigned expiry) {
  if (!seal_subscription_.empty()) seal_unsubscribe();
  const auto response =
      seal_post("/subscriptions", seal::subscription_xml(own_service_uri(), comma_list(users), interval, expiry));
  if (response.status != 200)
    throw std::runtime_error("SEAL location subscription: " + std::to_string(response.status));
  const auto answer = seal::parse_answer(response.body);
  seal_subscription_ = answer.subscription;
  seal_status_["subscription"] = seal_subscription_;
  seal_status_["expiry"] = answer.expiry.value_or(0);
  seal_status_["users"] = answer.users.empty() ? comma_list(users) : answer.users;
  seal_status_["ended"] = false;
  event("seal_subscribed",
        {{"subscription", seal_subscription_}, {"users", seal_status_["users"]}, {"expiry", seal_status_["expiry"]}});
  if (!seal_channel_) {
    seal_channel_ = std::make_shared<SealChannel>();
    const auto &common = cfg_.at("common");
    const auto url = seal_root() + "/notifications?val=" + url_encode(own_service_uri()) + "&wait=8";
    std::thread([channel = seal_channel_, url, ca = cfg_.at("tls").at("ca_file").get<std::string>(),
                 user = common.at("client_id").get<std::string>(), secret = common.at("secret").get<std::string>()] {
      HttpClient client(ca);
      while (channel->running) {
        try {
          const auto response = client.request("POST", url, {}, {}, user, secret);
          if (response.status == 200) {
            std::lock_guard lock(channel->mutex);
            for (const auto &notification : response.json().value("notifications", Json::array()))
              channel->received.push_back(notification.get<std::string>());
          } else
            std::this_thread::sleep_for(std::chrono::seconds(1));
        } catch (const std::exception &) {
          std::this_thread::sleep_for(std::chrono::seconds(1));
        }
      }
    }).detach();
  }
}

//------------------------------------------------------------------------------
// TS 24.545: end the location subscription at the location management server.
void McServer::seal_unsubscribe() {
  if (seal_subscription_.empty()) return;
  const auto response = seal_post("/subscriptions", seal::unsubscription_xml(own_service_uri(), seal_subscription_));
  event("seal_unsubscribed", {{"subscription", seal_subscription_}, {"status", response.status}});
  seal_subscription_.clear();
  seal_status_["subscription"] = "";
  seal_stop_channel();
}

//------------------------------------------------------------------------------
// Helper: with no subscription left, the polling thread ends after its current long poll (it holds the channel
// until then); a later subscription starts a new one.
void McServer::seal_stop_channel() {
  if (!seal_channel_) return;
  seal_channel_->running = false;
  seal_channel_.reset();
}

//------------------------------------------------------------------------------
// TS 24.545 clause 6.2.8.1: request the current (or historical) location of users on demand.
// seal-locate [history] <MCPTT ID>[,...]
void McServer::seal_locate(const std::string &users, bool history) {
  const auto response =
      seal_post("/location-requests", seal::request_xml(own_service_uri(), comma_list(users), history));
  seal_status_["last_request"] = {{"users", comma_list(users)}, {"status", response.status}, {"history", history}};
  if (response.status != 200) throw std::runtime_error("SEAL location request: " + std::to_string(response.status));
  const auto answer = seal::parse_answer(response.body);
  seal_record(answer, "request");
  seal_status_["last_request"]["reports"] = answer.reports.size();
  event("seal_location_answer", {{"users", comma_list(users)}, {"reports", answer.reports.size()}});
}

//------------------------------------------------------------------------------
// Helper: run a seal-subscribe, seal-unsubscribe or seal-locate command of the control interface.
void McServer::seal_command(const std::string &command) {
  std::istringstream in(command);
  std::string verb, first, second, third;
  in >> verb >> first >> second >> third;
  if (verb == "seal-subscribe" && !first.empty())
    seal_subscribe(first, second.empty() ? 1u : static_cast<unsigned>(std::stoul(second)),
                   third.empty() ? 300u : static_cast<unsigned>(std::stoul(third)));
  else if (verb == "seal-unsubscribe")
    seal_unsubscribe();
  else if (verb == "seal-locate" && first == "history" && !second.empty())
    seal_locate(second, true);
  else if (verb == "seal-locate" && !first.empty())
    seal_locate(first, false);
  else
    throw std::runtime_error(
        "seal-subscribe <ids> [interval] [expiry] | seal-unsubscribe | seal-locate [history] <ids>");
}

//------------------------------------------------------------------------------
// TS 24.545: handle the location notifications the polling thread received: record the reports of the current
// subscription, and note a subscription the location management server ended.
void McServer::seal_tick() {
  if (!seal_channel_) return;
  std::deque<std::string> received;
  {
    std::lock_guard lock(seal_channel_->mutex);
    received.swap(seal_channel_->received);
  }
  for (const auto &doc : received) {
    seal::Answer answer;
    try {
      answer = seal::parse_answer(doc);
    } catch (const std::exception &error) {
      event("seal_notification_rejected", {{"reason", error.what()}});
      continue;
    }
    // TLM-1: the subscription ended at the location management server.
    if (!answer.notification && answer.expiry == 0) {
      if (answer.subscription == seal_subscription_) {
        seal_subscription_.clear();
        seal_status_["subscription"] = "";
        seal_status_["ended"] = true;
      }
      continue;
    }
    if (answer.subscription != seal_subscription_) continue;
    seal_record(answer, "notification");
    seal_status_["notifications"] = seal_status_.value("notifications", 0u) + 1;
    event("seal_location_notification",
          {{"trigger", answer.trigger}, {"reports", answer.reports.size()}, {"users", answer.users}});
  }
  // TLM-1 ended the subscription: nothing more to poll for.
  if (seal_subscription_.empty()) seal_stop_channel();
}

} // namespace mcx
