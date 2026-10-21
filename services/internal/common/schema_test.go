//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

package common

import (
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// ------------------------------------------------------------------------------
// The XML schemas the servers validate with compile: the group document (TS 24.481 clause 7.2.4), the GMOP
// document (TS 24.481 clause 7.3.3) and the user profile document (TS 24.484 clause 8.3.2.3).
func TestSchemasCompile(test *testing.T) {
	for _, schema := range []*documentSchema{groupDocumentSchema, gmopDocumentSchema, userProfileSchema} {
		if err := schema.load(); err != nil {
			test.Fatalf("%s: %v", schema.name, err)
		}
	}
}

// ------------------------------------------------------------------------------
// The group documents the GMS generates conform to the schema of TS 24.481 clause 7.2.4 and the constraints of
// TS 24.481 clause 7.2.7, with and without <list>: those of the test configurations are checked when a handler
// starts; this covers the optional parts.
func TestGeneratedGroupDocumentsConform(test *testing.T) {
	group := Group{ID: "sip:g@x", Members: []string{"sip:a@x", "sip:b@x"}, UserPriorities: map[string]int{"sip:b@x": 7},
		AllowGettingMemberList: true, PreconfiguredUseOnly: true, ProtectMedia: true,
		CallPolicy:                map[string]interface{}{"max_participants": float64(4)},
		TemporaryConstituents:     []string{"sip:c1@x"},
		RegroupedBy:               &TemporaryRegroup{TGI: "sip:t@x", Requestor: "sip:a@x", Constituents: []string{"sip:g@x"}},
		ForbiddenDeaffiliationFAs: []string{"sip:f1@x"}, ForbiddenDeaffiliationIfLastFAs: []string{"sip:f2@x", "sip:f3@x"},
		MCData: &GroupMCData{Members: []string{"sip:a.data@x"}, AllowEnhancedStatus: true,
			EnhancedStatusValues: []EnhancedStatusValue{{ID: "1", Value: "busy"}}}}
	for _, withList := range []bool{true, false} {
		raw, err := groupDocument(group, withList)
		if err == nil {
			err = validateGroupDocument(raw, "")
		}
		if err != nil {
			test.Fatalf("%v\n%s", err, raw)
		}
	}
}

// ------------------------------------------------------------------------------
// The user profile documents the CMS generates (TS 24.484 clause 8.3.2.1) conform to the schema of TS 24.484
// clause 8.3.2.3.
func TestGeneratedProfileDocumentsConform(test *testing.T) {
	user := User{MCID: "a", MCPTTID: "sip:a@x", SIPURI: "sip:a@ims.x", ClientID: "c", Groups: []string{"sip:g@x"}, MaxAffiliations: 2,
		PrivateCall: &PrivateCallPolicy{Allow: true, IncomingFrom: []string{"sip:b@x"}, Emergency: true, EmergencyRecipients: []string{"sip:b@x"},
			Alert: true, AlertRecipients: []string{"sip:b@x"}, ForwardManual: true, IncomingAny: true},
		AdhocCall: &AdhocCallPolicy{Allow: true}, FunctionalAliasTakeover: true,
		MCData: &MCDataPolicy{TransmitData: true, EmergencyGroupCancel: true, AlertCancelAnyUser: true}}
	raw, err := xml.Marshal(userProfileXML(user))
	if err != nil {
		test.Fatal(err)
	}
	if err := userProfileSchema.validate(raw); err != nil {
		test.Fatalf("%v\n%s", err, raw)
	}
	var doc profileXML
	if err := xml.Unmarshal(raw, &doc); err != nil {
		test.Fatal(err)
	}
	if doc.mcpttID() != "sip:a@x" {
		test.Fatalf("profile identity %q: %s", doc.mcpttID(), raw)
	}
}

// ------------------------------------------------------------------------------
// RFC 4825 section 8.2.5 with OMA-TS-XDM_Group-V1_1_1 clause 5.1.6 and TS 24.481 clause 7.2.7: a group document
// (or an element operation on it) that does not conform is refused with 409 and its error element; so is a
// GMOP document that does not conform to TS 24.481 clause 7.3.3.
func TestGroupDocumentValidationErrors(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	cfg.Users[0].GroupManagement = &GroupManagementPolicy{Create: true, Temporary: true}
	handler := roleHandler(test, RoleGMS, cfg, key, test.TempDir())
	alice := tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID)
	put := func(path, contentType, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest("PUT", path, strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+alice)
		request.Header.Set("Content-Type", contentType)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, request)
		return rr
	}
	tree := groupsAUID + "/users/" + url.PathEscape("sip:alice@mcx.test") + "/"
	doc := func(inner string) string {
		return `<?xml version="1.0" encoding="UTF-8"?><group xmlns="urn:oma:xml:poc:list-service" xmlns:gi="urn:3gpp:ns:mcpttGroupInfo:1.0"` +
			` xmlns:cp="urn:ietf:params:xml:ns:common-policy" xmlns:oxe="urn:oma:xml:xdm:extensions"><list-service uri="sip:squad@mcx.test">` +
			inner + `</list-service></group>`
	}
	valid := `<list><entry uri="sip:alice@mcx.test"><gi:user-priority>3</gi:user-priority></entry></list>` +
		`<cp:ruleset><cp:rule id="m"><cp:conditions><is-list-member/></cp:conditions><cp:actions>` +
		`<gi:on-network-allow-getting-member-list>true</gi:on-network-allow-getting-member-list></cp:actions></cp:rule></cp:ruleset>` +
		`<oxe:supported-services><oxe:service enabler="urn:urn-7:3gpp-service.ims.icsi.mcptt"><oxe:group-media><gi:mcptt-speech/></oxe:group-media></oxe:service></oxe:supported-services>` +
		`<gi:protect-media>false</gi:protect-media>`
	for _, tc := range []struct {
		name, body, want string
	}{
		{"not well-formed", `<group xmlns="urn:oma:xml:poc:list-service"><list-service uri="sip:squad@mcx.test">`, "<not-well-formed"},
		{"not UTF-8", doc("<list><entry uri=\"sip:\xff@mcx.test\"/></list>"), "<not-utf-8"},
		{"another root", `<?xml version="1.0"?><resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"/>`, "<schema-validation-error"},
		{"no uri", strings.Replace(doc(""), ` uri="sip:squad@mcx.test"`, "", 1), "<schema-validation-error"},
		{"entry-ref", doc(`<list><entry-ref ref="x"/></list>`), "<schema-validation-error"},
		{"wrong order", doc(`<max-participant-count>3</max-participant-count><list/>`), "<schema-validation-error"},
		{"bad boolean", doc(`<gi:protect-media>sometimes</gi:protect-media>`), "<schema-validation-error"},
		{"priority out of range", doc(`<list><entry uri="sip:alice@mcx.test"><gi:user-priority>256</gi:user-priority></entry></list>`), "<schema-validation-error"},
		{"rule without id", doc(`<cp:ruleset><cp:rule/></cp:ruleset>`), "<schema-validation-error"},
		{"undeclared MCS element", doc(`<gi:on-network-colour>red</gi:on-network-colour>`), "<schema-validation-error"},
		{"two list-services", strings.Replace(doc(""), "</group>", `<list-service uri="sip:other@mcx.test"/></group>`, 1),
			`<constraint-failure phrase="No more than one list-service element allowed"`},
		{"duplicate entry", doc(`<list><entry uri="sip:alice@mcx.test"/><entry uri="sip:alice@mcx.test"/></list>`), `<constraint-failure phrase="Duplicate entry"`},
		{"entry URI syntax", doc(`<list><entry uri="alice"/></list>`), `<constraint-failure phrase="URI syntax error"`},
		{"external list of another type", doc(`<list><external anchor="https://x/xcap-root/org.openmobilealliance.groups/users/sip:alice@mcx.test/l"/></list>`),
			`<constraint-failure phrase="Wrong type of list"`},
		{"external list of another user", doc(`<list><external anchor="https://x/xcap-root/resource-lists/users/sip:bob@mcx.test/index"/></list>`),
			`<constraint-failure phrase="Access denied to list"`},
		{"complex rule", doc(`<cp:ruleset><cp:rule id="r"><cp:conditions><is-list-member/><cp:identity><cp:one id="sip:bob@mcx.test"/></cp:identity></cp:conditions></cp:rule></cp:ruleset>`),
			`<constraint-failure phrase="Complex rules are not allowed"`},
		{"searchable", doc(`<oxe:searchable>true</oxe:searchable>`), `<constraint-failure phrase="Search not supported"`},
		{"automatic advertisement", doc(`<oxe:automatic-group-advertisement>true</oxe:automatic-group-advertisement>`),
			`<constraint-failure phrase="Automatic group advertisement not supported"`},
		{"invite without duration", doc(`<gi:on-network-invite-members>true</gi:on-network-invite-members>`), "<constraint-failure"},
	} {
		rr := put(tree+"bad", groupDocumentMIME, tc.body)
		if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), tc.want) ||
			rr.Header().Get("Content-Type") != "application/xcap-error+xml" {
			test.Fatalf("%s: status=%d body=%s", tc.name, rr.Code, rr.Body.String())
		}
	}
	if rr := put(tree+"squad", groupDocumentMIME, doc(valid)); rr.Code != http.StatusCreated {
		test.Fatalf("a valid document status=%d body=%s", rr.Code, rr.Body.String())
	}
	// An element operation is checked on the resulting document.
	entry := groupsAUID + "/global/byGroupID/" + url.PathEscape("sip:squad@mcx.test") + "/~~/" +
		url.PathEscape(`group/list-service/list/entry[@uri="sip:bob@mcx.test"]`)
	if rr := put(entry, "application/xcap-el+xml", `<entry xmlns="urn:oma:xml:poc:list-service" uri="sip:bob@mcx.test"><user-priority xmlns="urn:3gpp:ns:mcpttGroupInfo:1.0">high</user-priority></entry>`); rr.Code != http.StatusConflict ||
		!strings.Contains(rr.Body.String(), "<schema-validation-error") {
		test.Fatalf("an invalid element status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr := put(entry, "application/xcap-el+xml", `<entry xmlns="urn:oma:xml:poc:list-service" uri="sip:bob@mcx.test"/>`); rr.Code != http.StatusCreated {
		test.Fatalf("a valid element status=%d body=%s", rr.Code, rr.Body.String())
	}
	// TS 24.481 clause 7.3.3: a GMOP document that does not conform.
	request := httptest.NewRequest("POST", tree+"temp", strings.NewReader(`<?xml version="1.0"?><document xmlns="urn:3gpp:ns:mcpttGMOP:1.0"><request>`+
		`<group-regroup-creation><group xmlns="urn:oma:xml:poc:list-service"/></group-regroup-creation></request></document>`))
	request.Header.Set("Authorization", "Bearer "+alice)
	request.Header.Set("Content-Type", gmopMIME)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, request)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "<schema-validation-error") {
		test.Fatalf("an invalid GMOP document status=%d body=%s", rr.Code, rr.Body.String())
	}
}

// ------------------------------------------------------------------------------
// The validator refuses a document with an external entity or an XInclude, either as not well-formed or as a
// schema violation.
func TestValidatorRefusesExternalEntities(test *testing.T) {
	for _, raw := range []string{
		`<?xml version="1.0"?><!DOCTYPE group [<!ENTITY x SYSTEM "file:///etc/passwd">]><group xmlns="urn:oma:xml:poc:list-service"/>`,
		`<?xml version="1.0"?><group xmlns="urn:oma:xml:poc:list-service" xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd"/></group>`,
	} {
		err := groupDocumentSchema.validate([]byte(raw))
		var violation *schemaViolation
		if err == nil || (!errors.Is(err, errNotWellFormed) && !errors.As(err, &violation)) {
			test.Fatalf("accepted: %v", err)
		}
	}
}
