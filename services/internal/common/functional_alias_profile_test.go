//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

package common

import (
	"encoding/xml"
	"strings"
	"testing"
)

// ------------------------------------------------------------------------------
// TS 24.484 clauses 8.3.2.1 item 10 g ii, 9.3.2.1 and 10.3.2.1: each service's user profile lists in the <anyExt> of
// <OnNetwork> the functional aliases whose user list for that service names the user, valid against the profile
// schemas; a user no list names gets no <FunctionalAliasList>.
func TestFunctionalAliasListInProfiles(test *testing.T) {
	cfg := mcvideoConfig(testConfig())
	cfg.Endpoints.Content = "https://content.mcx.test"
	cfg.Endpoints.MsgStore = "https://msgstore.mcx.test"
	cfg.Users[0].MCDataID = "sip:alice.mcdata@mcx.test"
	cfg.Users[1].MCDataID = "sip:bob.mcdata@mcx.test"
	cfg.FunctionalAliases = []FunctionalAlias{
		{ID: "sip:dispatcher@mcx.test", Users: []string{cfg.Users[0].MCPTTID}, MaxSimultaneousActivations: 1},
		{ID: "sip:medic@mcx.test", Users: []string{cfg.Users[0].MCPTTID, cfg.Users[1].MCPTTID},
			MCVideoUsers: []string{"sip:alice.mcvideo@mcx.test"}, MCDataUsers: []string{"sip:alice.mcdata@mcx.test"},
			MaxSimultaneousActivations: 2},
	}
	svc := &service{cfg: cfg}
	entry := func(alias string) string { return "<entry><uri-entry>" + alias + "</uri-entry></entry>" }

	mcptt, err := xml.Marshal(svc.servedProfileXML(cfg.Users[0]))
	if err != nil {
		test.Fatal(err)
	}
	if err := userProfileSchema.validate(mcptt); err != nil {
		test.Fatalf("MCPTT profile fails its schema: %v\n%s", err, mcptt)
	}
	if want := "<FunctionalAliasList>" + entry("sip:dispatcher@mcx.test") + entry("sip:medic@mcx.test") +
		"</FunctionalAliasList>"; !strings.Contains(string(mcptt), want) {
		test.Fatalf("MCPTT profile lacks %s:\n%s", want, mcptt)
	}
	var doc profileXML
	if err := xml.Unmarshal(mcptt, &doc); err != nil || doc.OnNetwork == nil || doc.OnNetwork.AnyExt == nil ||
		doc.OnNetwork.AnyExt.FunctionalAliasList == nil || len(doc.OnNetwork.AnyExt.FunctionalAliasList.Entries) != 2 {
		test.Fatalf("MCPTT <FunctionalAliasList> does not read back: %v", err)
	}

	video, err := svc.mcvideoProfileXML(cfg.Users[0])
	if err != nil {
		test.Fatal(err)
	}
	raw, _ := xml.Marshal(video)
	if err := mcvideoProfileSchema.validate(raw); err != nil {
		test.Fatalf("MCVideo profile fails its schema: %v\n%s", err, raw)
	}
	if want := "<FunctionalAliasList>" + entry("sip:medic@mcx.test") + "</FunctionalAliasList>"; !strings.Contains(string(raw), want) {
		test.Fatalf("MCVideo profile lacks %s:\n%s", want, raw)
	}

	data, _ := xml.Marshal(svc.mcdataProfileXML(cfg.Users[0]))
	if err := mcdataProfileSchema.validate(data); err != nil {
		test.Fatalf("MCData profile fails its schema: %v\n%s", err, data)
	}
	if want := "<FunctionalAliasList>" + entry("sip:medic@mcx.test") + "</FunctionalAliasList>"; !strings.Contains(string(data), want) {
		test.Fatalf("MCData profile lacks %s:\n%s", want, data)
	}

	// bob is in medic's MCPTT user list only.
	bob, _ := xml.Marshal(svc.servedProfileXML(cfg.Users[1]))
	if !strings.Contains(string(bob), "<FunctionalAliasList>"+entry("sip:medic@mcx.test")+"</FunctionalAliasList>") {
		test.Fatalf("bob's MCPTT profile lacks medic:\n%s", bob)
	}
	bobData, _ := xml.Marshal(svc.mcdataProfileXML(cfg.Users[1]))
	if strings.Contains(string(bobData), "FunctionalAliasList") {
		test.Fatalf("bob's MCData profile lists an alias:\n%s", bobData)
	}
	bobVideo, _ := svc.mcvideoProfileXML(cfg.Users[1])
	if raw, _ := xml.Marshal(bobVideo); strings.Contains(string(raw), "FunctionalAliasList") {
		test.Fatalf("bob's MCVideo profile lists an alias:\n%s", raw)
	}
}
