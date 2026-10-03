package common

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// ------------------------------------------------------------------------------
// XCAP (RFC 4825) on group documents, as the procedures of TS 24.481 clause 6.3.2 to clause 6.3.12 use it: the
// node selectors of RFC 4825 section 6.3 (attribute predicate, position, prefixed step), attribute and namespace
// fetches (RFC 4825 section 8.3), element insertion (RFC 4825 section 8.2) with its no-parent error
// (RFC 4825 section 11), deletion (RFC 4825 section 8.4), serialisation, and the refusal of a DTD.
func TestXCAPSelectorsAndOperations(test *testing.T) {
	doc := []byte(`<?xml version="1.0"?><group xmlns="urn:oma:xml:poc:list-service" xmlns:g="urn:3gpp:ns:mcpttGroupInfo:1.0">` +
		`<list-service uri="sip:team@mcx.test"><list><entry uri="sip:a@x"/><entry uri="sip:b@x"><g:user-priority>3</g:user-priority></entry></list></list-service></group>`)
	root, err := parseXMLTree(doc)
	if err != nil {
		test.Fatal(err)
	}
	selector := func(text string) nodeSelector {
		test.Helper()
		parsed, err := parseNodeSelector(text, map[string]string{"g": mcpttgiNS}, pocNS)
		if err != nil {
			test.Fatalf("%s: %v", text, err)
		}
		return parsed
	}
	if nodes := selector(`group/list-service/list/entry[@uri="sip:b@x"]`).locate(root); len(nodes) != 1 {
		test.Fatalf("attribute predicate found %d", len(nodes))
	}
	if nodes := selector(`group/list-service/list/entry[2]/g:user-priority`).locate(root); len(nodes) != 1 || nodes[0].Text != "3" {
		test.Fatalf("position and prefixed step")
	}
	kind, body, err := xcapFetch(root, selector(`group/list-service/@uri`))
	if err != nil || kind != "application/xcap-att+xml" || string(body) != "sip:team@mcx.test" {
		test.Fatalf("attribute fetch %q %q %v", kind, body, err)
	}
	if kind, _, _ := xcapFetch(root, selector(`group/list-service/namespace::*`)); kind != "application/xcap-ns+xml" {
		test.Fatalf("namespace fetch %q", kind)
	}
	created, err := xcapPut(root, selector(`group/list-service/list/entry[@uri="sip:c@x"]`),
		[]byte(`<entry xmlns="urn:oma:xml:poc:list-service" uri="sip:c@x"/>`))
	if err != nil || !created || len(selector(`group/list-service/list/entry`).locate(root)) != 3 {
		test.Fatalf("element insert %v %v", created, err)
	}
	if _, err := xcapPut(root, selector(`group/list-service/list/entry[@uri="sip:d@x"]`),
		[]byte(`<entry xmlns="urn:oma:xml:poc:list-service" uri="sip:other@x"/>`)); err == nil {
		test.Fatal("an element that does not match its selector was inserted")
	}
	if _, err := xcapPut(root, selector(`group/missing/entry`), []byte(`<entry xmlns="urn:oma:xml:poc:list-service"/>`)); err == nil ||
		err.(*xcapError).Element != "no-parent" {
		test.Fatalf("no-parent expected, got %v", err)
	}
	if err := xcapDelete(root, selector(`group/list-service/list/entry[@uri="sip:a@x"]`)); err != nil {
		test.Fatal(err)
	}
	if _, err := xcapPut(root, selector(`group/list-service/@display-name`), []byte("Team")); err != nil {
		test.Fatal(err)
	}
	out := string(root.serialize())
	if strings.Contains(out, "sip:a@x") || !strings.Contains(out, `display-name="Team"`) || !strings.Contains(out, "sip:c@x") {
		test.Fatalf("unexpected document %s", out)
	}
	if again, err := parseXMLTree([]byte(out)); err != nil || len(selector(`group/list-service/list/entry`).locate(again)) != 2 {
		test.Fatalf("the serialised document does not round trip: %v", err)
	}
	if _, err := parseXMLTree([]byte(`<!DOCTYPE x><x/>`)); err == nil {
		test.Fatal("a DTD was accepted")
	}
}

// ------------------------------------------------------------------------------
// The XCAP writes of the GMS on group documents: creation in the creator's own users tree and its refusal without
// the right (TS 24.481 clause 6.3.2.3 steps b and c, with the <uniqueness-failure> and <alt-value> of step c),
// element creation (clause 6.3.6.3) seen by the servers, attribute fetch by a member (clause 6.3.11.3), the
// authorization of changes (clause 7.2.12.1), If-Match, element deletion (clause 6.3.7.3), the refused change
// of the MCS group ID, and document deletion (clause 6.3.5.3).
func TestGroupDocumentXCAPWrites(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	cfg.Users[0].GroupManagement = &GroupManagementPolicy{Create: true}
	handler := roleHandler(test, RoleGMS, cfg, key, test.TempDir())
	alice := tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID)
	bob := tokenFor(test, cfg, key, "bob", testNow, cfg.ServerClientID)
	send := func(method, path, token, contentType, body string, headers ...string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		if contentType != "" {
			request.Header.Set("Content-Type", contentType)
		}
		for index := 0; index+1 < len(headers); index += 2 {
			request.Header.Set(headers[index], headers[index+1])
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, request)
		return rr
	}
	document := func(id, members string) string {
		return `<?xml version="1.0"?><group xmlns="urn:oma:xml:poc:list-service"><list-service uri="` + id + `"><list>` + members +
			`</list></list-service></group>`
	}
	aliceTree := groupsAUID + "/users/" + url.PathEscape("sip:alice@mcx.test") + "/squad"
	// TS 24.481 clause 6.3.2.3 step b: creation in the creator's own tree.
	rr := send("PUT", aliceTree, alice, groupDocumentMIME, document("sip:squad@mcx.test", `<entry uri="sip:alice@mcx.test"/>`))
	if rr.Code != http.StatusCreated || rr.Header().Get("ETag") == "" {
		test.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr = send("PUT", groupsAUID+"/users/"+url.PathEscape("sip:bob@mcx.test")+"/x", bob, groupDocumentMIME, document("sip:x@mcx.test", "")); rr.Code != http.StatusForbidden {
		test.Fatalf("a user without the right to create groups status=%d", rr.Code)
	}
	// TS 24.481 clause 6.3.2.3 step c: an MCS group ID already in use, or of another provider.
	for _, id := range []string{"sip:team@mcx.test", "sip:squad@other.test"} {
		rr = send("PUT", groupsAUID+"/users/"+url.PathEscape("sip:alice@mcx.test")+"/dup", alice, groupDocumentMIME, document(id, ""))
		if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "<alt-value>sip:dup-") {
			test.Fatalf("uniqueness failure for %s status=%d body=%s", id, rr.Code, rr.Body.String())
		}
	}
	// TS 24.481 clause 6.3.6.3: a member is added through the group ID tree; the servers see the change.
	global := groupsAUID + "/global/byGroupID/" + url.PathEscape("sip:squad@mcx.test")
	entry := global + "/~~/" + url.PathEscape(`group/list-service/list/entry[@uri="sip:bob@mcx.test"]`)
	rr = send("PUT", entry, alice, "application/xcap-el+xml", `<entry xmlns="urn:oma:xml:poc:list-service" uri="sip:bob@mcx.test"/>`)
	if rr.Code != http.StatusCreated {
		test.Fatalf("element create status=%d body=%s", rr.Code, rr.Body.String())
	}
	etag := rr.Header().Get("ETag")
	internal := httptest.NewRequest("GET", "/internal/group?id="+url.QueryEscape("sip:squad@mcx.test"), nil)
	internal.SetBasicAuth(cfg.ServerClientID, cfg.ServerSecret)
	irr := httptest.NewRecorder()
	handler.ServeHTTP(irr, internal)
	var group map[string]any
	_ = json.Unmarshal(irr.Body.Bytes(), &group)
	if irr.Code != http.StatusOK || len(group["members"].([]any)) != 2 || group["document_version"].(float64) != 2 {
		test.Fatalf("internal view status=%d body=%s", irr.Code, irr.Body.String())
	}
	// TS 24.481 clause 6.3.11.3: attribute fetch by a member.
	if rr = send("GET", global+"/~~/"+url.PathEscape(`group/list-service/@uri`), bob, "", ""); rr.Code != http.StatusOK || rr.Body.String() != "sip:squad@mcx.test" {
		test.Fatalf("attribute fetch status=%d body=%s", rr.Code, rr.Body.String())
	}
	// TS 24.481 clause 7.2.12.1: a member who is not the owner cannot change the document.
	if rr = send("DELETE", entry, bob, "", ""); rr.Code != http.StatusForbidden {
		test.Fatalf("a member's change status=%d", rr.Code)
	}
	// If-Match with a stale entity tag (RFC 4825 section 8.5).
	if rr = send("DELETE", entry, alice, "", "", "If-Match", `"stale"`); rr.Code != http.StatusPreconditionFailed {
		test.Fatalf("stale If-Match status=%d", rr.Code)
	}
	// TS 24.481 clause 6.3.7.3: delete the element.
	if rr = send("DELETE", entry, alice, "", "", "If-Match", etag); rr.Code != http.StatusOK {
		test.Fatalf("element delete status=%d body=%s", rr.Code, rr.Body.String())
	}
	// A change of the MCS group ID is refused (a constraint-failure, RFC 4825 section 11).
	rr = send("PUT", global+"/~~/"+url.PathEscape(`group/list-service/@uri`), alice, "application/xcap-att+xml", "sip:renamed@mcx.test")
	if rr.Code != http.StatusConflict {
		test.Fatalf("changing the group ID status=%d", rr.Code)
	}
	// TS 24.481 clause 7.2.12.1: the provisioned group is managed only under the provider policy.
	team := groupsAUID + "/global/byGroupID/" + url.PathEscape("sip:team@mcx.test") + "/~~/" + url.PathEscape(`group/list-service/list/entry[@uri="sip:alice@mcx.test"]`)
	if rr = send("DELETE", team, alice, "", ""); rr.Code != http.StatusForbidden {
		test.Fatalf("an unmanaged provisioned group status=%d", rr.Code)
	}
	// TS 24.481 clause 6.3.5.3: the owner deletes the document from its tree.
	if rr = send("DELETE", aliceTree, alice, "", ""); rr.Code != http.StatusOK {
		test.Fatalf("document delete status=%d", rr.Code)
	}
	if rr = send("GET", global, alice, "", ""); rr.Code != http.StatusNotFound {
		test.Fatalf("a deleted group status=%d", rr.Code)
	}
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.12.1: a provisioned group document in another user's tree is changed by a user the MCS
// service provider policy lets manage it, and the change survives a restart of the GMS.
func TestProvisionedGroupManagedByPolicy(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	cfg.Users[1].GroupManagement = &GroupManagementPolicy{Manage: []string{"sip:team@mcx.test"}}
	dir := test.TempDir()
	handler := roleHandler(test, RoleGMS, cfg, key, dir)
	bob := tokenFor(test, cfg, key, "bob", testNow, cfg.ServerClientID)
	path := groupsAUID + "/global/byGroupID/" + url.PathEscape("sip:team@mcx.test") + "/~~/" +
		url.PathEscape(`group/list-service/list/entry[@uri="sip:alice@mcx.test"]`)
	request := httptest.NewRequest("DELETE", path, nil)
	request.Header.Set("Authorization", "Bearer "+bob)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, request)
	if rr.Code != http.StatusOK {
		test.Fatalf("a manager's change status=%d body=%s", rr.Code, rr.Body.String())
	}
	// The change survives a restart of the GMS.
	handler = roleHandler(test, RoleGMS, cfg, key, dir)
	internal := httptest.NewRequest("GET", "/internal/group?id="+url.QueryEscape("sip:team@mcx.test"), nil)
	internal.SetBasicAuth(cfg.ServerClientID, cfg.ServerSecret)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, internal)
	if !strings.Contains(rr.Body.String(), `"members":["sip:bob@mcx.test"]`) || !strings.Contains(rr.Body.String(), `"document_version":1`) {
		test.Fatalf("after restart: %s", rr.Body.String())
	}
}
