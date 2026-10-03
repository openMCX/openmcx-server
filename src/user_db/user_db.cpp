// mcx-user-db: the Diameter user database that serves the MCPTT user profile of each configured user by Data-Pull,
// following the site configuration that MCX Admin rewrites.
//
// Specifications: TS 29.283, TS 24.484 V19.6.0 (Rel-19), RFC 6733.
#include "mcx/banner.hpp"
#include "mcx/diameter.hpp"

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>

namespace {

std::atomic_bool stopping = false;

//------------------------------------------------------------------------------
// Helper: the SIGINT and SIGTERM handler; asks the main loop to stop.
void stop_handler(int) { stopping.store(true); }

//------------------------------------------------------------------------------
// Helper: escapes an XML text or attribute value; refuses control characters other than tab, CR and LF.
std::string xml_escape(std::string_view text) {
  std::string result;
  result.reserve(text.size());
  for (char character : text) {
    switch (character) {
    case '&': result += "&amp;"; break;
    case '<': result += "&lt;"; break;
    case '>': result += "&gt;"; break;
    case '"': result += "&quot;"; break;
    case '\'': result += "&apos;"; break;
    default:
      if (static_cast<unsigned char>(character) < 0x20 && character != '\t' && character != '\n' && character != '\r')
        throw std::runtime_error("control character in configured identity");
      result += character;
    }
  }
  return result;
}

//------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2 (the MCPTT user profile configuration document): a minimal profile of a configured user
// with its name, alias, MCPTT ID and, if any, its groups; the SIP URI and client ID go in a local extension.
std::string generated_profile(const nlohmann::json &user) {
  const auto username = user.at("username").get<std::string>();
  const auto mcptt_id = user.at("mcptt_id").get<std::string>();
  const auto sip_uri = user.at("sip_uri").get<std::string>();
  const auto client_id = user.at("client_id").get<std::string>();
  std::string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                    "<mcptt-user-profile xmlns=\"urn:3gpp:mcptt:user-profile:1.0\" "
                    "XUI-URI=\"" +
                    xml_escape(mcptt_id) +
                    "\" user-profile-index=\"0\">"
                    "<Name>" +
                    xml_escape(username) +
                    "</Name><Status>true</Status>"
                    "<ProfileName>mcptt-user-profile-0.xml</ProfileName><Common index=\"0\">"
                    "<UserAlias><alias-entry>" +
                    xml_escape(username) + "</alias-entry></UserAlias><MCPTTUserID><uri-entry>" + xml_escape(mcptt_id) +
                    "</uri-entry></MCPTTUserID>"
                    "<MissionCriticalOrganization>open-mcx</MissionCriticalOrganization>"
                    "</Common>";
  if (user.contains("groups")) {
    xml += "<OnNetwork index=\"0\"><MCPTTGroupInfo>";
    for (const auto &group : user.at("groups"))
      xml += "<entry><uri-entry>" + xml_escape(group.get<std::string>()) + "</uri-entry></entry>";
    xml += "</MCPTTGroupInfo></OnNetwork>";
  }
  // The SIP URI and client ID have no element in the TS 24.484 schema: they are
  // in this implementation's namespace, as in the profiles the CMS serves.
  return xml + "<profile-extension xmlns=\"urn:openmcx:ns:userProfile:1.0\"><sip-uri>" + xml_escape(sip_uri) +
         "</sip-uri><client-id>" + xml_escape(client_id) + "</client-id></profile-extension></mcptt-user-profile>";
}

//------------------------------------------------------------------------------
// Helper: the MCPTT user profile of each user of the site configuration, keyed by MCPTT ID (the configured XML, or a
// generated one); throws on a duplicate MCPTT ID.
std::unordered_map<std::string, std::string> load_profiles(const std::string &path) {
  std::ifstream input(path);
  if (!input) throw std::runtime_error("cannot open site configuration " + path);
  nlohmann::json config;
  input >> config;
  std::unordered_map<std::string, std::string> profiles;
  for (const auto &user : config.at("users")) {
    const auto identity = user.at("mcptt_id").get<std::string>();
    const auto profile =
        user.contains("mcptt_profile_xml") ? user.at("mcptt_profile_xml").get<std::string>() : generated_profile(user);
    if (!profiles.emplace(identity, profile).second)
      throw std::runtime_error("duplicate MCPTT ID in site configuration");
  }
  return profiles;
}

} // namespace

//------------------------------------------------------------------------------
// TS 29.283: runs the Diameter Data Management server with the profiles of the site configuration and, with --watch,
// reloads them when the file changes.
int main(int argc, char **argv) {
  try {
    std::string config_path, diameter_config_path;
    bool watch = false;
    for (int index = 1; index < argc; ++index) {
      const std::string argument = argv[index];
      if (argument == "--watch") {
        watch = true;
      } else if ((argument == "--config" || argument == "--diameter-config") && index + 1 < argc) {
        auto &destination = argument == "--config" ? config_path : diameter_config_path;
        destination = argv[++index];
      } else {
        throw std::runtime_error("usage: mcx-user-db --config site.json --diameter-config path [--watch]");
      }
    }
    if (config_path.empty() || diameter_config_path.empty())
      throw std::runtime_error("usage: mcx-user-db --config site.json --diameter-config path [--watch]");
    mcx::print_banner("mcx-user-db");
    auto profiles = load_profiles(config_path);
    std::signal(SIGINT, stop_handler);
    std::signal(SIGTERM, stop_handler);
    // A Diameter peer that closes its TLS connection (a server restarting) must
    // surface as a write error, not stop this process with SIGPIPE.
    std::signal(SIGPIPE, SIG_IGN);
    mcx::DiameterProfileServer server(diameter_config_path, std::move(profiles));
    std::cout << "mcx-user-db ready on TS 29.283 Diameter Data Management" << std::endl;
    // --watch: the profiles follow the configuration file, which MCX Admin rewrites
    // (a whole new file renamed in place) when an account or a right changes. A file
    // that cannot be read or is invalid leaves the profiles as they were.
    auto modified = [&] {
      std::error_code error;
      const auto time = std::filesystem::last_write_time(config_path, error);
      return error ? std::filesystem::file_time_type{} : time;
    };
    auto seen = modified();
    while (!stopping.load()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      if (!watch) continue;
      const auto now = modified();
      if (now == seen) continue;
      seen = now;
      try {
        auto next = load_profiles(config_path);
        const auto count = next.size();
        server.replace_profiles(std::move(next));
        std::cout << "{\"event\":\"profiles_reloaded\",\"users\":" << count << "}" << std::endl;
      } catch (const std::exception &error) {
        std::cerr << "mcx-user-db: profiles not reloaded: " << error.what() << '\n';
      }
    }
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "mcx-user-db: " << error.what() << '\n';
    return 1;
  }
}
