//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The subscription to group dynamic data (include/mcx/group_dynamic_data.hpp): the per-group dynamic data PIDF of
// TS 24.281 clause 8.3.1.2 and the per-group dynamic data filter of clause 8.3.2.2 (written, read, round trips, what
// is refused), the Expires rule and answers of clause 8.2.2.3.9, and the subscriptions of clause 8.2.2.3.10 (a
// NOTIFY on every change and only then).
//
// Specifications: TS 24.281 V19.6.0 (Rel-19), RFC 3863, RFC 4661, RFC 6665.

#include "mcx/group_dynamic_data.hpp"

#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace mcx;

static void expect(bool condition, const std::string &what) {
  if (!condition) throw std::runtime_error(what);
}

static void rejects(const std::function<void()> &operation, const std::string &what) {
  try {
    operation();
  } catch (const std::exception &) {
    return;
  }
  throw std::runtime_error(what + " accepted");
}

static bool has(const std::string &text, const std::string &part) { return text.find(part) != std::string::npos; }

static GroupDynamicDataDocument sample() {
  GroupDynamicDataDocument document;
  document.group = "sip:group-a@mcvideo.example";
  document.group_status = "emergency";
  document.modified_by = "sip:alice@mcvideo.example";
  document.call_ongoing = true;
  document.regroup_alias = "sip:regroup-1@mcvideo.example";
  document.members = {
      {"sip:alice@mcvideo.example",
       {{"sip:alice-client@mcvideo.example", "2026-11-14T12:00:00Z"}},
       {"sip:alias-driver@mcvideo.example"}},
      {"sip:bob@mcvideo.example",
       {{"sip:bob-1@mcvideo.example", "2026-11-14T12:00:00Z"}, {"sip:bob-2@mcvideo.example", "2026-11-14T13:00:00Z"}},
       {}}};
  return document;
}

//------------------------------------------------------------------------------
// TS 24.281 clause 8.3.1.2 (per-group dynamic data): items 1 to 15 written, and read back the same.
static void pidf_coding() {
  const auto document = sample();
  const auto xml = group_dynamic_data_xml(document);
  expect(has(xml, "<presence xmlns=\"urn:ietf:params:xml:ns:pidf\""), "presence root in the PIDF namespace (item 1)");
  expect(has(xml, "xmlns:mcvideoPI10=\"urn:3gpp:ns:mcvideoPresInfo:1.0\""), "prefix of table 8.3.1.2-2");
  expect(has(xml, "entity=\"sip:group-a@mcvideo.example\""), "entity is the group (item 2)");
  expect(
      has(xml, "<mcvideoPI10:groupStatus ModifiedBy=\"sip:alice@mcvideo.example\">emergency</mcvideoPI10:groupStatus>"),
      "groupStatus with ModifiedBy (items 3 and 4)");
  expect(has(xml, "groupCallOngoing=\"true\""), "groupCallOngoing (item 8)");
  expect(has(xml, "groupRegroupAlias=\"sip:regroup-1@mcvideo.example\""), "groupRegroupAlias (item 7)");
  expect(has(xml, "<tuple id=\"sip:bob@mcvideo.example\"><status>"), "one tuple per member with status (items 9-11)");
  expect(has(xml, "<mcvideoPI10:affiliation client=\"sip:bob-2@mcvideo.example\" expires=\"2026-11-14T13:00:00Z\"/>"),
         "affiliation per client with client and expires (items 12-14, clause 8.2.2.3.10 step 2 a)");
  expect(has(xml, "<mcvideoPI10:functionalAlias functionalAliasID=\"sip:alias-driver@mcvideo.example\"/>"),
         "functionalAlias (item 15)");
  expect(xml.find("<tuple") < xml.find("groupStatus"), "tuples before the extensions (RFC 3863 section 4.1.2)");
  expect(parse_group_dynamic_data(xml) == document, "PIDF round trip");

  // No dynamic state, no members: only the entity.
  GroupDynamicDataDocument quiet;
  quiet.group = "sip:group-b@mcvideo.example";
  const auto empty = group_dynamic_data_xml(quiet);
  expect(!has(empty, "groupStatus") && !has(empty, "additionalData") && !has(empty, "<tuple"), "nothing to say");
  expect(parse_group_dynamic_data(empty) == quiet, "empty PIDF round trip");
  quiet.call_ongoing = false;
  expect(has(group_dynamic_data_xml(quiet), "groupCallOngoing=\"false\""), "no call ongoing is said");

  // Table 8.3.1.2-3: in-peril.
  auto peril = sample();
  peril.group_status = "in-peril";
  expect(parse_group_dynamic_data(group_dynamic_data_xml(peril)).group_status == "in-peril", "in-peril");
  peril.group_status = "panic";
  rejects([&] { (void)group_dynamic_data_xml(peril); }, "groupStatus outside table 8.3.1.2-3");
  rejects([] { (void)parse_group_dynamic_data("<presence xmlns=\"urn:example\" entity=\"sip:g@x\"/>"); },
          "wrong PIDF namespace");
  rejects([] { (void)parse_group_dynamic_data("<presence xmlns=\"urn:ietf:params:xml:ns:pidf\"/>"); },
          "PIDF without entity");
  GroupDynamicDataDocument no_group;
  rejects([&] { (void)group_dynamic_data_xml(no_group); }, "PIDF without group");
}

//------------------------------------------------------------------------------
// RFC 4661 section 3.2 with clause 8.3.2.2 item 7 B: a filter selecting items restricts the body.
static void pidf_filtered() {
  const auto document = sample();
  GroupDynamicDataFilter call;
  call.call_ongoing = true;
  const auto only_call = group_dynamic_data_xml(document, &call);
  expect(has(only_call, "groupCallOngoing=\"true\""), "call ongoing selected");
  expect(!has(only_call, "groupStatus") && !has(only_call, "<tuple") && !has(only_call, "groupRegroupAlias"),
         "nothing else selected");
  expect(has(only_call, "entity=\"sip:group-a@mcvideo.example\""), "entity always");
  GroupDynamicDataFilter members;
  members.affiliated = true;
  members.group_status = true;
  const auto selected = group_dynamic_data_xml(document, &members);
  expect(has(selected, "<tuple") && has(selected, "groupStatus") && !has(selected, "additionalData"),
         "members and status selected");
  GroupDynamicDataFilter none;
  expect(group_dynamic_data_xml(document, &none) == group_dynamic_data_xml(document), "a filter of no item: all");
}

//------------------------------------------------------------------------------
// TS 24.281 clause 8.3.2.2 (per-group dynamic data restrictions): written as items 1 to 7, read back, read from the
// values as the clause prints them, and told from the other two kinds of filter.
static void filter_coding() {
  GroupDynamicDataFilter filter;
  filter.group_status = filter.call_ongoing = filter.affiliated = true;
  const auto xml = group_dynamic_data_filter_xml(filter);
  expect(has(xml, "<filter-set xmlns=\"urn:ietf:params:xml:ns:simple-filter\">"), "filter-set (item 1)");
  expect(has(xml, "<ns-binding prefix=\"pidf\" urn=\"urn:ietf:params:xml:ns:pidf\"/>"), "pidf binding (item 3)");
  expect(has(xml, "<ns-binding prefix=\"mcvideoPI10\" urn=\"urn:3gpp:ns:mcvideoPresInfo:1.0\"/>"),
         "mcvideoPI10 binding (item 4)");
  expect(has(xml, "<filter id=\"gdd\"><what>"), "filter with id, without uri or domain (items 5 and 6)");
  expect(has(xml, "<include>//pidf:presence/pidf:groupStatus/@pidf:ModifiedBy</include>"), "item 7 B a");
  expect(has(xml, "<include>//pidf:presence/pidf:additionalData/@pidf:groupCallOngoing</include>"), "item 7 B d");
  expect(has(xml, "@pidf:client [@pidf:status=&quot;affiliated&quot;]</include>"), "item 7 B e");
  const auto parsed = parse_group_dynamic_data_filter(xml);
  expect(parsed && *parsed == filter, "filter round trip");

  filter.group = "sip:group-a@mcvideo.example";
  filter.broadcast_alias = filter.regroup_alias = true;
  const auto named = parse_group_dynamic_data_filter(group_dynamic_data_filter_xml(filter));
  expect(named && *named == filter && named->group == "sip:group-a@mcvideo.example", "filter naming the group");

  // As a client writes it: the values of item 7 B without the space of e), the MCVideo prefix, another id.
  const std::string client =
      "<?xml version=\"1.0\"?><filter-set xmlns=\"urn:ietf:params:xml:ns:simple-filter\"><ns-bindings>"
      "<ns-binding prefix=\"pidf\" urn=\"urn:ietf:params:xml:ns:pidf\"/>"
      "<ns-binding prefix=\"mcvideoPI10\" urn=\"urn:3gpp:ns:mcvideoPresInfo:1.0\"/></ns-bindings>"
      "<filter id=\"123\"><what>"
      "<include>//pidf:presence/pidf:tuple/pidf:status/pidf:affiliation/@pidf:client[@pidf:status=\"affiliated\"]"
      "</include><include> //pidf:presence/mcvideoPI10:additionalData/@mcvideoPI10:groupRegroupAlias </include>"
      "</what></filter></filter-set>";
  const auto read = parse_group_dynamic_data_filter(client);
  expect(read && read->affiliated && read->regroup_alias && !read->group_status && read->id == "123",
         "client filter read");

  // The per-client filter of the affiliation status determination (clause 8.2.1.3): another kind.
  const std::string per_client =
      "<filter-set xmlns=\"urn:ietf:params:xml:ns:simple-filter\"><ns-bindings>"
      "<ns-binding prefix=\"pidf\" urn=\"urn:ietf:params:xml:ns:pidf\"/></ns-bindings><filter id=\"1\"><what>"
      "<include>//pidf:presence/pidf:tuple[@id=\"sip:client@x\"]</include></what></filter></filter-set>";
  expect(!parse_group_dynamic_data_filter(per_client), "per-client filter is not a group dynamic data filter");

  // Items 5 B, 5 C and 7 A, and the namespace.
  const auto broken = [](const std::string &filter_attributes, const std::string &include_attributes) {
    return "<filter-set xmlns=\"urn:ietf:params:xml:ns:simple-filter\"><filter id=\"1\"" + filter_attributes +
           "><what><include" + include_attributes +
           ">//pidf:presence/pidf:additionalData/@pidf:groupCallOngoing</include></what></filter></filter-set>";
  };
  expect(parse_group_dynamic_data_filter(broken("", "")).has_value(), "well-formed filter");
  rejects([&] { (void)parse_group_dynamic_data_filter(broken(" uri=\"sip:a@x\"", "")); }, "filter with uri");
  rejects([&] { (void)parse_group_dynamic_data_filter(broken(" domain=\"x\"", "")); }, "filter with domain");
  rejects([&] { (void)parse_group_dynamic_data_filter(broken("", " type=\"xpath\"")); }, "include with type");
  rejects([] { (void)parse_group_dynamic_data_filter("<filter-set xmlns=\"urn:example\"/>"); },
          "wrong simple-filter namespace");
  rejects(
      [] {
        (void)parse_group_dynamic_data_filter(
            "<filter-set xmlns=\"urn:ietf:params:xml:ns:simple-filter\"><filter><what><include>"
            "//pidf:presence/pidf:additionalData/@pidf:groupCallOngoing</include></what></filter></filter-set>");
      },
      "filter without id");
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 9.3.1.2 and 9.3.2.2: the MCPTT documents, in the namespace urn:3gpp:ns:mcpttPresInfo:1.0 with the
// prefix mcpttPI10 (table 9.3.1.2-2); an MCVideo body is not read as MCPTT dynamic data.
static void mcptt_coding() {
  auto document = sample();
  document.group = "sip:group-a@mcptt.example";
  const auto xml = group_dynamic_data_xml(document, nullptr, Service::mcptt);
  expect(has(xml, "xmlns:mcpttPI10=\"urn:3gpp:ns:mcpttPresInfo:1.0\""), "prefix of table 9.3.1.2-2");
  expect(has(xml, "<mcpttPI10:groupStatus ModifiedBy=") && has(xml, "<mcpttPI10:affiliation client=") &&
             !has(xml, "mcvideoPI10"),
         "MCPTT elements");
  expect(parse_group_dynamic_data(xml, Service::mcptt) == document, "MCPTT PIDF round trip");
  const auto foreign = parse_group_dynamic_data(group_dynamic_data_xml(document), Service::mcptt);
  expect(foreign.group_status.empty() && foreign.members.size() == 2 && foreign.members[0].clients.empty(),
         "MCVideo elements are not MCPTT ones");

  GroupDynamicDataFilter filter;
  filter.group = document.group;
  filter.group_status = filter.affiliated = true;
  const auto filter_xml = group_dynamic_data_filter_xml(filter, Service::mcptt);
  expect(has(filter_xml, "<ns-binding prefix=\"mcpttPI10\" urn=\"urn:3gpp:ns:mcpttPresInfo:1.0\"/>"),
         "mcpttPI10 binding (clause 9.3.2.2 item 4)");
  expect(!has(filter_xml, "mcvideo"), "no MCVideo binding");
  const auto parsed = parse_group_dynamic_data_filter(filter_xml);
  expect(parsed && *parsed == filter, "MCPTT filter round trip");
  const std::string prefixed =
      "<filter-set xmlns=\"urn:ietf:params:xml:ns:simple-filter\"><filter id=\"7\"><what><include>"
      "//pidf:presence/mcpttPI10:additionalData/@mcpttPI10:groupCallOngoing</include></what></filter></filter-set>";
  const auto read = parse_group_dynamic_data_filter(prefixed);
  expect(read && read->call_ongoing, "an item written with the mcpttPI10 prefix");
}

//------------------------------------------------------------------------------
// TS 24.281 clause 8.2.1.6 steps 4 and 5 and clause 8.2.2.3.9 steps 3 to 6.
static void subscribe_rules() {
  expect(classify_gdd_expires("4294967295") == GddExpires::subscribe, "Expires 4294967295 subscribes");
  expect(classify_gdd_expires(" 0 ") == GddExpires::fetch, "Expires 0 fetches or ends");
  expect(classify_gdd_expires(std::nullopt) == GddExpires::too_brief, "no Expires is too brief (step 3)");
  expect(classify_gdd_expires("3600") == GddExpires::too_brief, "Expires 3600 is too brief (step 3)");
  expect(classify_gdd_expires("4294967296") == GddExpires::malformed, "beyond 2^32-1");
  expect(classify_gdd_expires("12a") == GddExpires::malformed, "not a number");
  expect(classify_gdd_expires("-1") == GddExpires::malformed, "negative");
  expect(gdd_subscribe_status(GddExpires::too_brief, true, true) == 423, "423 first (step 3)");
  expect(gdd_subscribe_status(GddExpires::too_brief, false, false) == 423, "423 before the group checks");
  expect(gdd_subscribe_status(GddExpires::malformed, true, true) == 400, "400 for a malformed Expires");
  expect(gdd_subscribe_status(GddExpires::subscribe, false, false) == 403, "403 unknown group (step 4)");
  expect(gdd_subscribe_status(GddExpires::subscribe, true, false) == 403, "403 not authorised (step 5)");
  expect(gdd_subscribe_status(GddExpires::subscribe, true, true) == 200, "200 (step 6)");
  expect(gdd_subscribe_status(GddExpires::fetch, true, true) == 200, "200 for a fetch");
}

//------------------------------------------------------------------------------
// TS 24.281 clauses 8.2.2.3.9 and 8.2.2.3.10: the initial NOTIFY records the body; a NOTIFY on every change of a
// group's data, only to that group's subscriptions, and none while nothing changes; the end in the dialog.
static void subscription_lifecycle() {
  GroupDynamicDataSubscriptions subscriptions;
  std::map<std::string, GroupDynamicDataDocument> groups{{"sip:g1@x", {}}, {"sip:g2@x", {}}};
  groups["sip:g1@x"].group = "sip:g1@x";
  groups["sip:g2@x"].group = "sip:g2@x";
  const auto body_of = [&](const GroupDynamicDataSubscriptions::Subscription &held) {
    return group_dynamic_data_xml(groups.at(held.group), &held.filter);
  };
  subscriptions.add("d1", {"sip:g1@x", "sip:alice@x", {}, {}, {}});
  subscriptions.add("d2", {"sip:g2@x", "sip:bob@x", "peer-a", {}, {}});
  GroupDynamicDataFilter only_call;
  only_call.call_ongoing = true;
  subscriptions.add("d3", {"sip:g1@x", "sip:carol@x", {}, only_call, {}});
  expect(subscriptions.size() == 3 && subscriptions.contains("d2"), "three subscriptions");

  // Step 6 of clause 8.2.2.3.9, then the initial NOTIFY of each.
  for (const auto *dialog : {"d1", "d2", "d3"})
    expect(!subscriptions.current(dialog, body_of).empty(), std::string("initial NOTIFY of ") + dialog);
  expect(subscriptions.changed(body_of).empty(), "no change, no NOTIFY");

  groups["sip:g1@x"].group_status = "emergency";
  groups["sip:g1@x"].modified_by = "sip:alice@x";
  auto changes = subscriptions.changed(body_of);
  expect(changes.size() == 1 && changes[0].first == "d1" && has(changes[0].second, "emergency"),
         "emergency notified to g1's unfiltered subscription only (d3 asked for the call only)");
  expect(subscriptions.changed(body_of).empty(), "the same state is not sent twice");

  groups["sip:g1@x"].call_ongoing = true;
  changes = subscriptions.changed(body_of);
  expect(changes.size() == 2, "a call on g1 notified to both of its subscriptions");

  groups["sip:g2@x"].members.push_back({"sip:bob@x", {{"sip:bob-1@x", "2026-11-14T12:00:00Z"}}, {}});
  changes = subscriptions.changed(body_of);
  expect(changes.size() == 1 && changes[0].first == "d2" && has(changes[0].second, "<tuple id=\"sip:bob@x\">"),
         "a new affiliation notified to g2's subscription");

  // De-subscribe (Expires 0 in the dialog): the final NOTIFY, then nothing.
  const auto last = subscriptions.current("d1", body_of);
  expect(has(last, "emergency"), "final NOTIFY carries the current state");
  expect(subscriptions.erase("d1") && !subscriptions.erase("d1"), "ended once");
  groups["sip:g1@x"].group_status.clear();
  changes = subscriptions.changed(body_of);
  expect(changes.empty(), "an ended subscription is not notified, d3's filter hides the status");
  expect(subscriptions.find("d1") == nullptr && subscriptions.find("d2")->peer == "peer-a", "find");
}

int main() {
  const std::pair<const char *, void (*)()> cases[] = {{"pidf_coding", pidf_coding},
                                                       {"pidf_filtered", pidf_filtered},
                                                       {"filter_coding", filter_coding},
                                                       {"mcptt_coding", mcptt_coding},
                                                       {"subscribe_rules", subscribe_rules},
                                                       {"subscription_lifecycle", subscription_lifecycle}};
  int failed = 0;
  for (const auto &[name, run] : cases) try {
      run();
      std::cout << "ok   " << name << '\n';
    } catch (const std::exception &error) {
      ++failed;
      std::cout << "FAIL " << name << ": " << error.what() << '\n';
    }
  return failed ? 1 : 0;
}
