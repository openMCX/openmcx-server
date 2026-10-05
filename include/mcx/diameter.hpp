// Diameter data management client and server: the Data-Pull-Request and Data-Pull-Answer carrying the MCPTT user
// profile; and the process's freeDiameter core, which this application shares with Rx (TS 29.214).
//
// Specifications: TS 29.283, RFC 6733.
#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>

namespace mcx {

//------------------------------------------------------------------------------
// RFC 6733 section 5.3: the applications a process's freeDiameter core advertises in its
// Capabilities-Exchange-Request: the Diameter Data Management application (TS 29.283, MCPTT-2) and Rx (TS 29.214,
// the MC service server as AF on MCPTT-5).
struct DiameterApplications {
  bool data_management = false;
  bool rx = false;
};

//------------------------------------------------------------------------------
// The process's freeDiameter core (src/common/diameter_core.hpp). libfdcore keeps its state in globals: a process
// initialises one, with every application it serves, and its Diameter clients share it; the first client starts it.
class DiameterCore;
std::shared_ptr<DiameterCore> start_diameter_core(const std::string &native_config_path,
                                                  DiameterApplications applications);

//------------------------------------------------------------------------------
// TS 29.283: the Application-Id of the Diameter Data Management application.
inline constexpr unsigned diameter_data_management_application_id = 16777351;
//------------------------------------------------------------------------------
// TS 29.283: the Command-Code of Data-Pull-Request and Data-Pull-Answer.
inline constexpr unsigned diameter_data_pull_command_code = 8388728;
//------------------------------------------------------------------------------
// TS 29.214 clause 5.6: the Application-Id of Rx.
inline constexpr unsigned diameter_rx_application_id = 16777236;

//------------------------------------------------------------------------------
// TS 29.283: the Diameter client that pulls MCPTT user profiles with Data-Pull-Request.
class DiameterProfileClient {
public:
  explicit DiameterProfileClient(std::string native_config_path,
                                 std::chrono::milliseconds timeout = std::chrono::seconds(5));
  // On a core started with the Diameter Data Management application, shared with other Diameter clients.
  explicit DiameterProfileClient(std::shared_ptr<DiameterCore> core,
                                 std::chrono::milliseconds timeout = std::chrono::seconds(5));
  ~DiameterProfileClient();
  DiameterProfileClient(const DiameterProfileClient &) = delete;
  DiameterProfileClient &operator=(const DiameterProfileClient &) = delete;
  DiameterProfileClient(DiameterProfileClient &&) noexcept;
  DiameterProfileClient &operator=(DiameterProfileClient &&) noexcept;

  // TS 29.283: retrieves the bit-0 MCPTT user profile through Data-Pull-Request and Data-Pull-Answer (DPR/DPA). The
  // returned User-Data XML is limited to 1 MiB.
  std::string pull(std::string_view mcptt_id);

private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

//------------------------------------------------------------------------------
// TS 29.283: the Diameter server that answers Data-Pull-Request with the MCPTT user profiles it serves.
class DiameterProfileServer {
public:
  DiameterProfileServer(std::string native_config_path, std::unordered_map<std::string, std::string> profiles);
  ~DiameterProfileServer();
  DiameterProfileServer(const DiameterProfileServer &) = delete;
  DiameterProfileServer &operator=(const DiameterProfileServer &) = delete;
  DiameterProfileServer(DiameterProfileServer &&) noexcept;
  DiameterProfileServer &operator=(DiameterProfileServer &&) noexcept;
  // Replaces the profiles served, as a whole, while the server runs (a user
  // database following MCX Admin). Invalid profiles are refused, keeping the old.
  void replace_profiles(std::unordered_map<std::string, std::string> profiles);

private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace mcx
