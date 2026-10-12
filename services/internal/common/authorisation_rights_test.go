//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

package common

import (
	"encoding/xml"
	"slices"
	"strings"
	"testing"
)

// ------------------------------------------------------------------------------
// TestUserProfileGroupCallRights: the group call rights of a user's configuration become the TS 24.484 elements the
// controlling function reads (TS 24.379 clause 6.3.3.1.13): <allow-emergency-group-call> and the others, one
// <allow-activate-emergency-alert> for a private or a group alert right, and the <MCPTT-group-call> entries of a
// dedicated group or of the group the user selects.
func TestUserProfileGroupCallRights(test *testing.T) {
	user := User{MCPTTID: "sip:alice@mcx.test", GroupCall: &GroupCallPolicy{Emergency: true, EmergencyGroup: "sip:ops@mcx.test",
		EmergencyCancel: true, Imminent: true, ImminentCancel: true, Alert: true}}
	raw, err := xml.Marshal(userProfileXML(user))
	if err != nil {
		test.Fatal(err)
	}
	doc := string(raw)
	for _, element := range []string{"allow-emergency-group-call", "allow-cancel-group-emergency", "allow-imminent-peril-call",
		"allow-cancel-imminent-peril", "allow-activate-emergency-alert"} {
		if strings.Count(doc, ">true</"+element+">") != 1 {
			test.Errorf("%s not granted once in %s", element, doc)
		}
	}
	if strings.Contains(doc, "allow-cancel-emergency-alert") {
		test.Error("an alert cancellation right that was not granted")
	}
	for _, want := range []string{`<MCPTT-group-call>`, `<EmergencyCall><MCPTTGroupInitiation><entry entry-info="DedicatedGroup"><uri-entry>sip:ops@mcx.test</uri-entry>`,
		`<ImminentPerilCall><MCPTTGroupInitiation><entry entry-info="UseCurrentlySelectedGroup">`,
		`<EmergencyAlert><entry entry-info="UseCurrentlySelectedGroup">`} {
		if !strings.Contains(doc, want) {
			test.Errorf("%s missing in %s", want, doc)
		}
	}
	// A private alert right alone grants the same single element.
	private := User{MCPTTID: "sip:bob@mcx.test", PrivateCall: &PrivateCallPolicy{Alert: true}}
	raw, _ = xml.Marshal(userProfileXML(private))
	if strings.Count(string(raw), ">true</allow-activate-emergency-alert>") != 1 {
		test.Errorf("the private alert right: %s", raw)
	}
}

// ------------------------------------------------------------------------------
// TestGroupDocumentRules: a group's rights become TS 24.481 rules: an <is-list-member> rule with the actions every
// member has, <identity> rules for the members its lists name; read back, the document gives the same rights; a
// prearranged group says <on-network-invite-members> with its maximum duration, a chat group does not.
func TestGroupDocumentRules(test *testing.T) {
	group := Group{ID: "sip:ops@mcx.test", Members: []string{"sip:alice@mcx.test", "sip:bob@mcx.test"},
		AllowEmergencyCall: true, PriorityPolicy: map[string]any{"alert_users": []any{"sip:bob@mcx.test"}},
		MCData: &GroupMCData{Members: []string{"sip:alice.mcdata@mcx.test"}, SDSSupported: true, AllowSDS: true,
			TransmitMembers: []string{"sip:alice.mcdata@mcx.test"}}}
	raw, err := groupDocument(group, true)
	if err != nil {
		test.Fatal(err)
	}
	doc := string(raw)
	for _, want := range []string{"is-list-member", ">true</allow-MCPTT-emergency-call>", `id="sip:bob@mcx.test"`,
		">true</allow-MCPTT-emergency-alert>", `id="sip:alice.mcdata@mcx.test"`, ">true</mcdata-allow-transmit-data-in-this-group>",
		">true</on-network-invite-members>", ">PT3600S</on-network-maximum-duration>"} {
		if !strings.Contains(doc, want) {
			test.Errorf("%s missing in %s", want, doc)
		}
	}
	// A third-party document: the rules alone (no OpenMCX configuration) give the same rights.
	third := strings.Split(doc, "<configuration")[0] + "</list-service></group>"
	if !strings.Contains(doc, "<configuration") {
		third = doc
	}
	parsed, err := parseGroupDocument([]byte(third))
	if err != nil {
		test.Fatalf("%v: %s", err, third)
	}
	if !parsed.AllowEmergencyCall || !slices.Contains(policyIDs(parsed.PriorityPolicy, "alert_users"), "sip:bob@mcx.test") {
		test.Errorf("read back: %+v", parsed)
	}
	chat := group
	chat.Type = "chat"
	raw, _ = groupDocument(chat, true)
	if strings.Contains(string(raw), "on-network-invite-members") {
		test.Error("a chat group invites its members")
	}
}

// ------------------------------------------------------------------------------
// TestGroupDocumentJoinAndReceiveOnly: <join-handling> for every member by default, for the members join_members names
// otherwise; <on-network-recvonly> in a receive-only member's <entry>; both read back.
func TestGroupDocumentJoinAndReceiveOnly(test *testing.T) {
	group := Group{ID: "sip:ops@mcx.test", Members: []string{"sip:alice@mcx.test", "sip:bob@mcx.test"},
		PriorityPolicy: map[string]any{"receive_only_users": []any{"sip:bob@mcx.test"}}}
	raw, _ := groupDocument(group, true)
	doc := string(raw)
	if !strings.Contains(doc, ">true</join-handling>") || !strings.Contains(doc, "on-network-recvonly") {
		test.Fatalf("join and receive-only: %s", doc)
	}
	parsed, err := parseGroupDocument([]byte(strings.Split(doc, "<configuration")[0] + "</list-service></group>"))
	if err != nil || !slices.Contains(policyIDs(parsed.PriorityPolicy, "receive_only_users"), "sip:bob@mcx.test") {
		test.Fatalf("read back %v: %+v", err, parsed)
	}
	group.CallPolicy = map[string]any{"join_members": []any{"sip:alice@mcx.test"}}
	raw, _ = groupDocument(group, true)
	parsed, _ = parseGroupDocument([]byte(strings.Split(string(raw), "<configuration")[0] + "</list-service></group>"))
	if joiners := policyIDs(parsed.CallPolicy, "join_members"); len(joiners) != 1 || joiners[0] != "sip:alice@mcx.test" {
		test.Fatalf("join_members read back: %v in %s", parsed.CallPolicy, raw)
	}
}

// ------------------------------------------------------------------------------
// TestUserProfileParticipationRights: <allow-private-call-participation> unless callable is false;
// <allow-adhoc-group-call-participation> from adhoc_call participation.
func TestUserProfileParticipationRights(test *testing.T) {
	raw, _ := xml.Marshal(userProfileXML(User{MCPTTID: "sip:a@mcx.test", AdhocCall: &AdhocCallPolicy{Allow: true, Participation: true}}))
	if !strings.Contains(string(raw), ">true</allow-private-call-participation>") ||
		!strings.Contains(string(raw), ">true</allow-adhoc-group-call-participation>") {
		test.Fatalf("participation rights: %s", raw)
	}
	never := false
	raw, _ = xml.Marshal(userProfileXML(User{MCPTTID: "sip:b@mcx.test", PrivateCall: &PrivateCallPolicy{Callable: &never}}))
	if strings.Contains(string(raw), "allow-private-call-participation") {
		test.Fatalf("a user that may not be called: %s", raw)
	}
}

// ------------------------------------------------------------------------------
// TestUserProfilePrivateEmergencyRecipient: <PrivateCall><EmergencyCall><MCPTTPrivateRecipient> of TS 24.484, with the
// single pre-configured recipient or "LocallyDetermined".
func TestUserProfilePrivateEmergencyRecipient(test *testing.T) {
	one := User{MCPTTID: "sip:a@mcx.test", PrivateCall: &PrivateCallPolicy{Allow: true, Emergency: true,
		EmergencyRecipients: []string{"sip:b@mcx.test"}}}
	raw, _ := xml.Marshal(userProfileXML(one))
	if !strings.Contains(string(raw), `<EmergencyCall><MCPTTPrivateRecipient><entry entry-info="UsePreConfigured"><uri-entry>sip:b@mcx.test</uri-entry>`) ||
		!strings.Contains(string(raw), "<ProSeUserID-entry><User-Info-ID>000000000000</User-Info-ID></ProSeUserID-entry>") {
		test.Fatalf("pre-configured recipient: %s", raw)
	}
	one.PrivateCall.EmergencyAny = true
	raw, _ = xml.Marshal(userProfileXML(one))
	if !strings.Contains(string(raw), `<MCPTTPrivateRecipient><entry entry-info="LocallyDetermined">`) {
		test.Fatalf("locally determined recipient: %s", raw)
	}
}

// ------------------------------------------------------------------------------
// TS 24.484 clauses 8.3.2.1 item 8g and 9.3.2.1: the served MCPTT and MCVideo user profiles carry one
// <MissionCriticalOrganization>, the system's (Config.Organization, else the domain).
func TestUserProfileMissionCriticalOrganization(test *testing.T) {
	svc := &service{cfg: Config{Domain: "mcx.test"}}
	user := User{MCPTTID: "sip:a.mcptt@mcx.test", MCVideoID: "sip:a.mcvideo@mcx.test"}
	raw, _ := xml.Marshal(svc.servedProfileXML(user))
	if !strings.Contains(string(raw), "<MissionCriticalOrganization>mcx.test</MissionCriticalOrganization>") {
		test.Fatalf("MCPTT profile without the domain as organisation: %s", raw)
	}
	svc.cfg.Organization = "Alpha Fire"
	raw, _ = xml.Marshal(svc.servedProfileXML(user))
	if !strings.Contains(string(raw), "<MissionCriticalOrganization>Alpha Fire</MissionCriticalOrganization>") {
		test.Fatalf("MCPTT profile without the configured organisation: %s", raw)
	}
	video, err := svc.mcvideoProfileXML(user)
	raw, _ = xml.Marshal(video)
	if err != nil || !strings.Contains(string(raw), "<MissionCriticalOrganization>Alpha Fire</MissionCriticalOrganization>") {
		test.Fatalf("MCVideo profile without the organisation: %v %s", err, raw)
	}
}
