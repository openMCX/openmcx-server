//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The SIP REFER of a call over a pre-established session (include/mcx/refer.hpp): the escaping of the headers portion
// of a SIP URI, the resource list entry with its hname "body" as TS 37.579-1 table 5.5.2.12-2 lays it out, the
// Refer-To, Target-Dialog and Replaces values, and what a participating function reads from a received REFER.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 37.579-1 V18.1.0 (Rel-18), RFC 3261, RFC 3515, RFC 4488,
// RFC 4538, RFC 2392, RFC 5366, RFC 3891.

#include "mcx/refer.hpp"

#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

//------------------------------------------------------------------------------
// Checks that the operation throws; what names what would have been wrongly accepted.
static void rejects(const std::function<void()> &operation, const std::string &what) {
  try {
    operation();
  } catch (const std::exception &) {
    return;
  }
  throw std::runtime_error(what + " accepted");
}

static void expect(bool condition, const std::string &what) {
  if (!condition) throw std::runtime_error(what);
}

static const std::string kInfo = "<?xml version=\"1.0\"?><mcpttinfo xmlns=\"urn:3gpp:ns:mcpttInfo:1.0\"><mcptt-Params>"
                                 "<session-type>chat</session-type></mcptt-Params></mcpttinfo>";

//------------------------------------------------------------------------------
// Helper: the entry of a chat group call REFER with its MCPTT-Info and an SDP offer.
static mcx::ReferEntry chat_entry() {
  mcx::ReferEntry entry;
  entry.target = "sip:chat-1@mcptt.example";
  entry.headers = mcx::refer_accept_contacts();
  entry.body = {{mcx::mcptt_mime, kInfo, "info1@ue"}, {"application/sdp", "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\n"}};
  return entry;
}

//------------------------------------------------------------------------------
// RFC 3261 sections 19.1.1 and 25.1: unreserved and hnv-unreserved characters stay; everything else is %HH; the
// escapes decode back and malformed ones are refused.
static void Rfc3261_25_1_HeaderEscaping() {
  expect(mcx::escape_uri_header("a b;c=d&e%\"<>\r\n") == "a%20b%3Bc%3Dd%26e%25%22%3C%3E%0D%0A", "escaped");
  expect(mcx::escape_uri_header("Az09-_.!~*'()[]/?:+$") == "Az09-_.!~*'()[]/?:+$", "unescaped characters");
  expect(mcx::unescape_uri_header("a%20b%3bc") == "a b;c", "lower-case escapes decode");
  rejects([] { (void)mcx::unescape_uri_header("a%4"); }, "truncated escape");
  rejects([] { (void)mcx::unescape_uri_header("a%zz"); }, "non-hexadecimal escape");
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.2.2.2.1 step 3 a and b, TS 37.579-1 table 5.5.2.12-2: the two Accept-Contact header fields in
// the headers portion, escaped (the ICSI's own %3A becomes %253A).
static void Clause_10_1_2_2_2_1_EntryHeaders() {
  mcx::ReferEntry entry;
  entry.target = "sip:chat-1@mcptt.example";
  entry.headers = mcx::refer_accept_contacts();
  expect(mcx::refer_entry_uri(entry, "b1") ==
             "sip:chat-1@mcptt.example?Accept-Contact=*%3B+g.3gpp.mcptt%3Brequire%3Bexplicit&Accept-Contact=*%3B+g."
             "3gpp.icsi-ref%3D%22urn%253Aurn-7%253A3gpp-service.ims.icsi.mcptt%22%3Brequire%3Bexplicit",
         "entry URI with the Accept-Contact header fields");
  const auto parsed = mcx::parse_refer_entry_uri(mcx::refer_entry_uri(entry, "b1"));
  expect(parsed.target == entry.target && parsed.body.empty(), "target without body");
  expect(parsed.headers.size() == 2 && parsed.headers[1].value == mcx::icsi_accept(mcx::mcptt_service),
         "Accept-Contact decoded");
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.2.2.2.1 step 3 c, TS 37.579-1 table 5.5.2.12-2: the hname "body" carries a multipart/mixed body
// (its Content-Type also in the headers portion) with the MCPTT-Info and the SDP offer, Content-IDs kept.
static void Clause_10_1_2_2_2_1_EntryBody() {
  const auto uri = mcx::refer_entry_uri(chat_entry(), "inner-b");
  expect(uri.find("&Content-Type=multipart/mixed%3Bboundary%3Dinner-b&body=--inner-b%0D%0AContent-Type:%20") !=
             std::string::npos,
         "Content-Type then the escaped multipart body");
  expect(uri.find_first_of(" \r\n<>\"") == std::string::npos, "nothing unescaped that a URI cannot hold");
  const auto parsed = mcx::parse_refer_entry_uri(uri);
  expect(parsed.headers.size() == 2, "Content-Type and body are not left among the header fields");
  expect(parsed.body.size() == 2 && parsed.body[0].body == kInfo && parsed.body[0].content_id == "info1@ue",
         "MCPTT-Info with its Content-ID");
  expect(parsed.body[1].content_type == "application/sdp", "SDP offer");
  rejects([] { (void)mcx::parse_refer_entry_uri("sip:g@x?body=abc"); }, "body without Content-Type");
  rejects([] { (void)mcx::parse_refer_entry_uri("sip:g@x?Content-Type=a/b&body=1&body=2"); }, "two bodies");
  auto entry = chat_entry();
  entry.target = "sip:g@x?Subject=x";
  rejects([&] { (void)mcx::refer_entry_uri(entry, "b"); }, "target with a headers portion");
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 10.1.1.3.1.2 conditions 1 to 3 and step 9: the participating function finds the resource list
// part by the Refer-To's cid URL and reads its single entry, the "&" of the URI escaped as "&amp;" in the XML.
static void Clause_10_1_1_3_1_2_ReadRefer() {
  const auto part = mcx::refer_resource_list_part(chat_entry(), "list@ue", "inner-b");
  expect(part.content_id == "list@ue" && part.content_type == mcx::resource_lists_mime, "resource list part");
  expect(part.body.find("&amp;Accept-Contact=") != std::string::npos, "& escaped in the attribute");
  const auto headers =
      mcx::pre_established_refer_headers(mcx::cid_refer_to("list@ue"), {"pre-call@ue", "ue-tag", "server-tag"});
  const auto request = mcx::parse_pre_established_refer(headers, {{mcx::mcptt_mime, kInfo, "other"}, part});
  expect(!request.leave && request.entry_uris.size() == 1, "a call with one entry");
  expect(request.entry.target == "sip:chat-1@mcptt.example" && request.entry.body.size() == 2, "entry read");

  rejects([&] { (void)mcx::parse_pre_established_refer(headers, {{mcx::mcptt_mime, kInfo, "list@ue"}}); },
          "cid naming a body that is not a resource list");
  rejects([&] { (void)mcx::parse_pre_established_refer({}, {part}); }, "REFER without Refer-To");
  rejects([&] { (void)mcx::parse_pre_established_refer({{"Refer-To", "<sip:s@x;method=INVITE>"}}, {}); },
          "method other than BYE");
  rejects([] { (void)mcx::parse_refer_resource_list(mcx::refer_resource_list_of({"sip:a@x", "sip:b@x"})); },
          "two entries where one is expected");
  expect(mcx::refer_resource_list_entries(mcx::refer_resource_list_of({"sip:a@x", "sip:b@x"})).size() == 2,
         "first-to-answer entries (TS 24.379 clause 11.1.1.2.2.1 step 8)");
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 6.2.4.2 steps 6 and 7, 6.2.5.2 steps 6 and 7, clause 11.1.3.2.1.2: the Refer-To of a REFER "BYE"
// and its reading; RFC 3515 section 2.1 with RFC 2392: the cid URL, compact form "r", other URI parameters kept.
static void Clause_6_2_4_2_ReferBye() {
  expect(mcx::bye_refer_to("sip:call-9@mcptt.example") == "<sip:call-9@mcptt.example;method=BYE>", "BYE Refer-To");
  const auto leave = mcx::parse_pre_established_refer({{"r", "<sip:call-9@mcptt.example;method=BYE>"}}, {});
  expect(leave.leave && leave.session_identity == "sip:call-9@mcptt.example", "leave with the session identity");
  const auto kept = mcx::parse_refer_to("<sip:call-9@x;lr;method=bye>;extra=1");
  expect(kept.uri == "sip:call-9@x;lr" && kept.method == "bye", "other URI parameters and the method");
  expect(mcx::cid_refer_to("info1@ue") == "<cid:info1@ue>", "cid URL");
  rejects([] { (void)mcx::cid_refer_to("a b@ue"); }, "Content-ID with a space (RFC 2045 msg-id)");
  expect(mcx::parse_refer_to("<cid:a%2Bb@ue>").content_id == "a+b@ue", "cid URL decoded");
  expect(mcx::parse_refer_to("cid:x@y").content_id == "x@y", "addr-spec form");
  const auto headers = mcx::pre_established_refer_headers(mcx::bye_refer_to("sip:c@x"), {"c", "l", "r"});
  for (const auto &header : headers) expect(header.name != "Require", "no multiple-refer for a REFER BYE");
}

//------------------------------------------------------------------------------
// RFC 4538 section 7 and RFC 3891 section 6.1: Target-Dialog and Replaces values; a missing tag is refused.
static void Rfc4538_7_TargetDialogAndReplaces() {
  const mcx::DialogIdentifiers dialog{"abc@10.0.0.1", "ue1", "srv2"};
  expect(mcx::target_dialog_value(dialog) == "abc@10.0.0.1;local-tag=ue1;remote-tag=srv2", "Target-Dialog");
  expect(mcx::parse_target_dialog(" abc@10.0.0.1 ; remote-tag=srv2;local-tag=ue1;x=1") == dialog, "parsed");
  rejects([] { (void)mcx::parse_target_dialog("abc;local-tag=1"); }, "Target-Dialog without remote-tag");
  const mcx::ReplacesValue replaces{"pre@x", "t1", "f1", true};
  expect(mcx::replaces_value(replaces) == "pre@x;to-tag=t1;from-tag=f1;early-only", "Replaces");
  expect(mcx::parse_replaces("pre@x;from-tag=f1;to-tag=t1;early-only") == replaces, "Replaces parsed");
  rejects([] { (void)mcx::parse_replaces("pre@x;to-tag=t1"); }, "Replaces without from-tag");
  rejects([] { (void)mcx::target_dialog_value({"a b", "l", "r"}); }, "Call-ID with a space");
  // RFC 3891 section 3: the participating function (server tag "srv2") names the session to the client ("ue1").
  const auto sent = mcx::replaces_for({"abc@10.0.0.1", "srv2", "ue1"});
  expect(sent.to_tag == "ue1" && sent.from_tag == "srv2", "to-tag is the recipient's tag");
  expect(mcx::replaces_names(mcx::parse_replaces(mcx::replaces_value(sent)), dialog), "client matches its session");
  expect(!mcx::replaces_names(sent, {"abc@10.0.0.1", "srv2", "ue1"}), "the sender's own view does not match");
}

//------------------------------------------------------------------------------
// RFC 4488 section 4, TS 24.379 clause 10.1.1.3.1.2 step 6, TS 37.579-1 table 5.5.2.12-1: the REFER's header fields
// and the no-subscription test.
static void Clause_10_1_1_3_1_2_NoSubscription() {
  const auto headers = mcx::pre_established_refer_headers(mcx::cid_refer_to("l@ue"), {"c", "l", "r"});
  expect(mcx::refer_without_subscription(headers), "Refer-Sub false and norefersub");
  bool multiple = false;
  for (const auto &header : headers) multiple |= header.name == "Require" && header.value == "multiple-refer";
  expect(multiple, "Require: multiple-refer with a cid Refer-To");
  expect(mcx::refer_without_subscription({{"refer-sub", "False"}, {"k", "timer, norefersub"}}), "compact Supported");
  expect(!mcx::refer_without_subscription({{"Refer-Sub", "false"}}), "without norefersub");
  expect(!mcx::refer_without_subscription({{"Supported", "norefersub"}}), "without Refer-Sub");
}

int main() {
  const std::vector<std::pair<const char *, void (*)()>> tests = {
      {"Rfc3261_25_1_HeaderEscaping", Rfc3261_25_1_HeaderEscaping},
      {"Clause_10_1_2_2_2_1_EntryHeaders", Clause_10_1_2_2_2_1_EntryHeaders},
      {"Clause_10_1_2_2_2_1_EntryBody", Clause_10_1_2_2_2_1_EntryBody},
      {"Clause_10_1_1_3_1_2_ReadRefer", Clause_10_1_1_3_1_2_ReadRefer},
      {"Clause_6_2_4_2_ReferBye", Clause_6_2_4_2_ReferBye},
      {"Rfc4538_7_TargetDialogAndReplaces", Rfc4538_7_TargetDialogAndReplaces},
      {"Clause_10_1_1_3_1_2_NoSubscription", Clause_10_1_1_3_1_2_NoSubscription},
  };
  int failures = 0;
  for (const auto &[name, test] : tests) {
    try {
      test();
    } catch (const std::exception &error) {
      std::cerr << name << ": " << error.what() << '\n';
      ++failures;
    }
  }
  if (failures == 0) std::cout << tests.size() << " REFER tests passed\n";
  return failures == 0 ? 0 : 1;
}
