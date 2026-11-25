//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

package common

import (
	"encoding/xml"
	"reflect"
	"strings"
	"testing"
)

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1 item 10 e) and f) (TS 24.379 clause 9.2.1.7.2): a user's affiliation rules are in the
// <anyExt> of the <MCPTTGroupInfo> entry of their group, valid against the profile schema; a group without rules has a
// bare entry.
func TestAffiliationRulesInProfile(test *testing.T) {
	cfg := testConfig()
	area := GeoArea{Polygon: [][2]float64{{45.0005, 9.999}, {45.0005, 10.001}, {45.0013, 10.001}}}
	cfg.FunctionalAliases = []FunctionalAlias{{ID: "sip:fa@mcx.test", Users: []string{cfg.Users[0].MCPTTID},
		MaxSimultaneousActivations: 1}}
	group := cfg.Users[0].Groups[0]
	cfg.Users[0].AffiliationRules = map[string]*GroupAffiliationRules{group: {
		Affiliate:                 &AffiliationRule{Exit: []GeoArea{area}, Aliases: []string{"sip:fa@mcx.test"}},
		Deaffiliate:               &AffiliationRule{Enter: []GeoArea{area}},
		ManualDeaffiliationLocked: true}}
	if err := cfg.Validate(); err != nil {
		test.Fatal(err)
	}
	svc := &service{cfg: cfg}
	raw, err := xml.Marshal(svc.servedProfileXML(cfg.Users[0]))
	if err != nil {
		test.Fatal(err)
	}
	if err := userProfileSchema.validate(raw); err != nil {
		test.Fatalf("MCPTT profile fails its schema: %v\n%s", err, raw)
	}
	text := string(raw)
	for _, want := range []string{
		"<entry><uri-entry>" + group + "</uri-entry><anyExt><RulesForAffiliation><ListOfLocationCriteria><ExitSpecificArea>" +
			"<PolygonArea><Corner>",
		"<ListOfActiveFunctionalAliasCriteria><entry index=\"1\"><uri-entry>sip:fa@mcx.test</uri-entry></entry>" +
			"</ListOfActiveFunctionalAliasCriteria></RulesForAffiliation>",
		"<RulesForDeaffiliation><ListOfLocationCriteria><EnterSpecificArea><PolygonArea>",
		"<manual-deaffiliation-not-allowed-if-affiliation-rules-are-met>true</manual-deaffiliation-not-allowed-if-affiliation-rules-are-met>",
	} {
		if !strings.Contains(text, want) {
			test.Fatalf("missing %s in\n%s", want, text)
		}
	}

	// Checks: a group the user is not in, an unknown alias, a rule without criteria, a polygon of two corners.
	for name, rules := range map[string]map[string]*GroupAffiliationRules{
		"group":    {"sip:other@mcx.test": {Deaffiliate: &AffiliationRule{Enter: []GeoArea{area}}}},
		"alias":    {group: {Affiliate: &AffiliationRule{Aliases: []string{"sip:nobody@mcx.test"}}}},
		"criteria": {group: {Affiliate: &AffiliationRule{}}},
		"polygon":  {group: {Affiliate: &AffiliationRule{Enter: []GeoArea{{Polygon: area.Polygon[:2]}}}}},
	} {
		bad := testConfig()
		bad.FunctionalAliases = cfg.FunctionalAliases
		bad.Users[0].AffiliationRules = rules
		if bad.Validate() == nil {
			test.Errorf("%s: invalid affiliation rules accepted", name)
		}
	}
}

// ------------------------------------------------------------------------------
// TS 24.481 clauses 7.2.4.2 and 7.2.8 (TS 24.379 clause 9.2.1.7.3): a group's permitted and mandatory geographic areas
// in its document, valid against the group document schema, and read back from a document PUT.
func TestGroupGeographicAreas(test *testing.T) {
	center := [2]float64{45.0, 10.0}
	group := Group{ID: "sip:operations@mcx.test", Members: []string{"sip:alice@mcx.test"},
		PermittedArea: []GeoArea{{Center: &center, Radius: 500, OffsetAngle: 0, IncludedAngle: 179}},
		MandatoryArea: []GeoArea{{Polygon: [][2]float64{{44.99, 9.99}, {44.99, 10.01}, {45.01, 10.01}, {45.01, 9.99}}}}}
	raw, err := groupDocument(group, true)
	if err != nil {
		test.Fatal(err)
	}
	if err := groupDocumentSchema.validate(raw); err != nil {
		test.Fatalf("group document fails its schema: %v\n%s", err, raw)
	}
	if !strings.Contains(string(raw), `<mandatory-geographic-area xmlns="urn:3gpp:ns:mcpttGroupInfo:1.0"><PolygonArea>`) {
		test.Fatalf("no mandatory area in\n%s", raw)
	}
	back, err := parseGroupDocument(raw)
	if err != nil {
		test.Fatal(err)
	}
	// The TS 23.032 codes are quantised (about a metre): the areas read back give the same codes.
	if !reflect.DeepEqual(groupAreaOf(back.MandatoryArea), groupAreaOf(group.MandatoryArea)) ||
		!reflect.DeepEqual(groupAreaOf(back.PermittedArea), groupAreaOf(group.PermittedArea)) ||
		back.PermittedArea[0].Radius != 500 {
		test.Fatalf("areas read back as %+v / %+v", back.MandatoryArea, back.PermittedArea)
	}
	if bare, _ := groupDocument(Group{ID: group.ID, Members: group.Members}, true); strings.Contains(string(bare),
		"geographic-area") {
		test.Fatal("a group without areas has a geographic area element")
	}
	bad := testConfig()
	bad.Groups[0].MandatoryArea = []GeoArea{{Polygon: [][2]float64{{91, 0}, {0, 0}, {0, 1}}}}
	if bad.Validate() == nil {
		test.Error("a mandatory area out of range accepted")
	}
}
