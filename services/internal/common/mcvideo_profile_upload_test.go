//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

package common

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// ------------------------------------------------------------------------------
// TS 24.484 clause 6.3.4.3 for the MCVideo user profile: a configuration manager replaces another user's MCVideo user
// profile document, which is then served and persists over a restart; a user without the right, another document name,
// another media type and a document failing the constraints are refused; a later change of the configuration
// supersedes the uploaded document.
func TestMCVideoProfileUpload(test *testing.T) {
	key := testKey(test)
	cfg := mcvideoConfig(testConfig())
	cfg.Users[1].ConfigManagement = true // bob manages the configuration
	dir := test.TempDir()
	cms := roleHandler(test, RoleCMS, cfg, key, dir)
	alice := tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID)
	bob := tokenFor(test, cfg, key, "bob", testNow, cfg.ServerClientID)
	path := mcvideoProfilePath("sip:alice.mcvideo@mcx.test", 1)
	send := func(h http.Handler, method, path, token, body, mime string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		request := bearerRequest(method, path, token, strings.NewReader(body))
		if mime != "" {
			request.Header.Set("Content-Type", mime)
		}
		h.ServeHTTP(rr, request)
		return rr
	}
	rr := send(cms, http.MethodGet, path, alice, "", "")
	if rr.Code != http.StatusOK {
		test.Fatalf("profile: %d", rr.Code)
	}
	right := `<allow-automatic-commencement xmlns="urn:3gpp:ns:mcvideo:user-profile:1.0">`
	original := rr.Body.String()
	updated := strings.Replace(original, right+"true<", right+"false<", 1)
	if updated == original {
		test.Fatalf("no automatic commencement right to withdraw:\n%s", original)
	}
	for _, testCase := range []struct {
		name, path, token, body, mime string
		want                          int
	}{
		{"a user without the right", path, alice, updated, mcvideoProfileMIME, http.StatusForbidden},
		{"another document name", mcvideoProfilePath("sip:alice.mcvideo@mcx.test", 2), bob, updated, mcvideoProfileMIME, http.StatusNotFound},
		{"another media type", path, bob, updated, userProfileMIME, http.StatusUnsupportedMediaType},
		{"another user's XUI", path, bob, strings.Replace(updated, `XUI-URI="sip:alice.mcvideo@mcx.test"`,
			`XUI-URI="sip:bob.mcvideo@mcx.test"`, 1), mcvideoProfileMIME, http.StatusConflict},
	} {
		if rr = send(cms, http.MethodPut, testCase.path, testCase.token, testCase.body, testCase.mime); rr.Code != testCase.want {
			test.Fatalf("%s: %d want %d %s", testCase.name, rr.Code, testCase.want, rr.Body.String())
		}
	}
	if rr = send(cms, http.MethodPut, path, bob, updated, mcvideoProfileMIME); rr.Code != http.StatusOK {
		test.Fatalf("upload: %d %s", rr.Code, rr.Body.String())
	}
	for name, h := range map[string]http.Handler{"served": cms, "after a restart": roleHandler(test, RoleCMS, cfg, key, dir)} {
		if rr = send(h, http.MethodGet, path, alice, "", ""); rr.Code != http.StatusOK || rr.Body.String() != updated {
			test.Fatalf("%s: %d\n%s", name, rr.Code, rr.Body.String())
		}
	}
	// Restored by the same means.
	if rr = send(cms, http.MethodPut, path, bob, original, mcvideoProfileMIME); rr.Code != http.StatusOK {
		test.Fatalf("restore: %d %s", rr.Code, rr.Body.String())
	}
	if rr = send(cms, http.MethodGet, path, alice, "", ""); rr.Body.String() != original {
		test.Fatalf("not restored:\n%s", rr.Body.String())
	}
	// A later change of alice's configuration supersedes an uploaded document.
	if rr = send(cms, http.MethodPut, path, bob, updated, mcvideoProfileMIME); rr.Code != http.StatusOK {
		test.Fatalf("upload: %d", rr.Code)
	}
	cfg.Users[0].MCVideo["max_affiliations"] = 3
	if rr = send(roleHandler(test, RoleCMS, cfg, key, dir), http.MethodGet, path, alice, "", ""); rr.Code != http.StatusOK ||
		!strings.Contains(rr.Body.String(), right+"true<") || !strings.Contains(rr.Body.String(), "<MaxAffiliationsN2>3<") {
		test.Fatalf("not superseded by the configuration:\n%s", rr.Body.String())
	}
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.1 item 10: a functional alias with location criteria in the configuration reaches the
// MCVideo user profile as the <anyExt> of its <FunctionalAliasList> entry, valid against the schema, with the
// coordinates coded as in TS 23.032 clause 6.1; an alias without criteria has no <anyExt>.
func TestMCVideoProfileFunctionalAliasLocation(test *testing.T) {
	key := testKey(test)
	cfg := mcvideoConfig(testConfig())
	area := GeoArea{Polygon: [][2]float64{{45.0005, 9.999}, {45.0005, 10.001}, {45.0013, 10.001}, {45.0013, 9.999}}}
	cfg.FunctionalAliases = append(cfg.FunctionalAliases,
		FunctionalAlias{ID: "sip:located.alias@mcx.test", MCVideoUsers: []string{"sip:alice.mcvideo@mcx.test"},
			MaxSimultaneousActivations: 1, LocationActivation: &AreaCriteria{Enter: []GeoArea{area}},
			LocationDeactivation: &AreaCriteria{Exit: []GeoArea{area, {Center: &[2]float64{-33.5, -70.25}, Radius: 300,
				IncludedAngle: 179}}}, ManualDeactivationLocked: true},
		FunctionalAlias{ID: "sip:plain.alias@mcx.test", MCVideoUsers: []string{"sip:alice.mcvideo@mcx.test"},
			MaxSimultaneousActivations: 1})
	cms := roleHandler(test, RoleCMS, cfg, key, test.TempDir())
	alice := tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID)
	rr := httptest.NewRecorder()
	cms.ServeHTTP(rr, bearerRequest("GET", mcvideoProfilePath("sip:alice.mcvideo@mcx.test", 1), alice, nil))
	body := rr.Body.String()
	if rr.Code != http.StatusOK {
		test.Fatalf("profile: %d %s", rr.Code, body)
	}
	if err := mcvideoProfileSchema.validate(rr.Body.Bytes()); err != nil {
		test.Fatalf("schema: %v\n%s", err, body)
	}
	corner := "<Corner><Longitude>" + strconv.Itoa(int(encodeLongitude(9.999))) + "</Longitude><Latitude>" +
		strconv.Itoa(int(encodeLatitude(45.0005))) + "</Latitude></Corner>"
	for _, want := range []string{
		"<entry><uri-entry>sip:located.alias@mcx.test</uri-entry><anyExt><LocationCriteriaForActivation><EnterSpecificArea><PolygonArea>" + corner,
		"</LocationCriteriaForActivation><LocationCriteriaForDeactivation><ExitSpecificArea><PolygonArea>" + corner,
		"<EllipsoidArcArea><Center><Longitude>" + strconv.Itoa(int(encodeLongitude(-70.25))) + "</Longitude><Latitude>" +
			strconv.Itoa(int(encodeLatitude(-33.5))) + "</Latitude></Center><Radius>300</Radius><OffsetAngle>0</OffsetAngle><IncludedAngle>179</IncludedAngle>",
		"<manual-deactivation-not-allowed-if-location-criteria-met>true</manual-deactivation-not-allowed-if-location-criteria-met></anyExt></entry>",
		"<entry><uri-entry>sip:plain.alias@mcx.test</uri-entry></entry>"} {
		if !strings.Contains(body, want) {
			test.Fatalf("profile lacks %s:\n%s", want, body)
		}
	}
	// TS 23.032 clause 6.1 codes, as the C++ location library makes them (location.cpp encode_latitude/longitude).
	if encodeLatitude(45) != 4194304 || encodeLatitude(-45) != 0x800000|4194304 || encodeLongitude(90) != 4194304 ||
		encodeLongitude(-90) != 0xc00000 || encodeLongitude(180) != 0x800000 {
		test.Fatal("TS 23.032 coordinate codes")
	}
	// A polygon of two corners is refused at configuration.
	bad := FunctionalAlias{ID: "sip:bad@mcx.test", LocationActivation: &AreaCriteria{Enter: []GeoArea{{Polygon: [][2]float64{{1, 2}, {3, 4}}}}}}
	if bad.checkLocationCriteria() == nil {
		test.Fatal("a two-corner polygon accepted")
	}
}
