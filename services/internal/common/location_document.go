//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The location user configuration data document the CMS serves: rendering a user's "location" record as the
// document of TS 24.484 clause 7.4.
//
// Specifications: TS 24.484 V19.6.0 (Rel-19), TS 23.280 V19.10.1 (Rel-19), TS 24.379 V19.7.0 (Rel-19), RFC 4745.
package common

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// ------------------------------------------------------------------------------
// TS 24.484 clause 7.4: the location user configuration data document, one per user, valid for each of the user's
// MC service IDs (<mc-service-id>). The record's rights map to the actions of clause 7.4.2.1 item 5:
//
//   - "request": <allow-request-location-of-users>, <allow-request-location-of-groups> and
//     <allow-subscription-on-location-information>, for any target (a rule without conditions);
//   - "configure": <allow-change-location-configuration-of-users>;
//   - "share_with": <allow-to-share-location-information>, for every user ("*", the default) or for the identities
//     listed (a rule with <identity>);
//
// and "report" (whether the user reports its location at all), which the schema has no element for, goes in the
// document's <anyExt>, in this implementation's namespace.
const (
	locationConfigNS   = "urn:3gpp:mcs:location-user-config:1.0"
	locationConfigMIME = "application/vnd.3gpp.mcs-location-user-config+xml"
	locationConfigAUID = "org.3gpp.mcs.location-user-config"
)

// ------------------------------------------------------------------------------
// TS 24.484 clause 7.4.2.1: the <location-user-configuration-data> root element.
type locationConfigXML struct {
	XMLName    xml.Name           `xml:"urn:3gpp:mcs:location-user-config:1.0 location-user-configuration-data"`
	Domain     string             `xml:"domain,attr"`
	ServiceIDs []string           `xml:"mc-service-id"`
	AnyExt     *locationConfigExt `xml:"anyExt,omitempty"`
	Ruleset    *profileRuleset    `xml:"urn:ietf:params:xml:ns:common-policy ruleset"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 7.4.2.1 item 4: the <anyExt> with this implementation's reporting setting.
type locationConfigExt struct {
	NoReport *struct{} `xml:"urn:openmcx:ns:userProfile:1.0 location-reporting-disabled,omitempty"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 7.4.2.1 item 5: the rules of a user's location record.
func locationRuleset(policy *LocationPolicy) *profileRuleset {
	action := func(name string) profileElement {
		return profileElement{XMLName: xml.Name{Space: locationConfigNS, Local: name}, Text: "true"}
	}
	var any []profileElement
	if policy != nil && policy.Request {
		any = append(any, action("allow-request-location-of-users"), action("allow-request-location-of-groups"),
			action("allow-subscription-on-location-information"))
	}
	if policy != nil && policy.Configure {
		any = append(any, action("allow-change-location-configuration-of-users"))
	}
	shareAll := policy == nil || len(policy.ShareWith) == 0
	var named []string
	if policy != nil {
		for _, id := range policy.ShareWith {
			if id == "*" {
				shareAll = true
			} else {
				named = append(named, id)
			}
		}
	}
	if shareAll {
		any = append(any, action("allow-to-share-location-information"))
	}
	ruleset := &profileRuleset{}
	if len(any) > 0 {
		ruleset.Rules = append(ruleset.Rules, profileRule{ID: "location", Actions: profileElements{Items: any}})
	}
	if !shareAll && len(named) > 0 {
		rule := profileRule{ID: "share", Actions: profileElements{Items: []profileElement{action("allow-to-share-location-information")}}}
		rule.Conditions = &profileConditions{}
		for _, id := range named {
			rule.Conditions.Identity.One = append(rule.Conditions.Identity.One, profileOne{ID: id})
		}
		ruleset.Rules = append(ruleset.Rules, rule)
	}
	return ruleset
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 7.4.2.1: the location user configuration data document of a user.
func (svc *service) locationConfigXML(user User) locationConfigXML {
	doc := locationConfigXML{Domain: svc.cfg.Domain, Ruleset: locationRuleset(user.Location)}
	for _, id := range []string{user.MCPTTID, user.MCVideoID, user.MCDataID} {
		if id != "" {
			doc.ServiceIDs = append(doc.ServiceIDs, id)
		}
	}
	if user.Location != nil && user.Location.Report != nil && !*user.Location.Report {
		doc.AnyExt = &locationConfigExt{NoReport: &struct{}{}}
	}
	return doc
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 7.4.2.8: locationDocumentName is the naming convention.
func locationDocumentName(index int) string {
	return "location-user-config-" + strconv.Itoa(index) + ".xml"
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 7.4.1.2: the XCAP URI of a user's location user configuration data document, by one of the user's
// MC service IDs (the <LocationUserProfileURI> of the user profiles).
func (svc *service) locationDocumentURI(id string, index int) string {
	return svc.cfg.Endpoints.CMS + "/xcap-root/" + locationConfigAUID + "/users/" + url.PathEscape(id) + "/" + locationDocumentName(index)
}

// ------------------------------------------------------------------------------
// Helper: the user one of whose MC service IDs is id.
func (svc *service) userByServiceID(id string) (User, bool) {
	for _, key := range []string{"mcptt_id", "mcvideo_id", "mcdata_id"} {
		if user, ok := svc.siteUser(key, id); ok {
			return user, true
		}
	}
	return User{}, false
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 7.4.1.2 and clause 7.4.2.11: getLocationConfig: an MC service client reads its location user
// configuration data document at CMSXCAPROOTURI/org.3gpp.mcs.location-user-config/users/sip:<MCSERVICEID>/
// location-user-config-<INDEX>.xml; every MC service ID of the user may read it.
func (svc *service) getLocationConfig(writer http.ResponseWriter, request *http.Request) {
	claims, ok := svc.authenticateBearer(writer, request)
	if !ok {
		return
	}
	id := request.PathValue("serviceID")
	user, found := svc.userByServiceID(id)
	own := found && (claims.MCPTTID == user.MCPTTID || (claims.MCDataID != "" && claims.MCDataID == user.MCDataID) ||
		(claims.MCVideoID != "" && claims.MCVideoID == user.MCVideoID))
	if !own && !svc.configManager(claims.MCPTTID) {
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	if !found || request.PathValue("document") != locationDocumentName(user.profileIndex()) {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": http.StatusText(http.StatusNotFound)})
		return
	}
	raw, err := xml.Marshal(svc.locationConfigXML(user))
	if err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	writeDocument(writer, request, append([]byte(xml.Header), raw...), locationConfigMIME)
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 7.4.2.3: checkLocationDocuments validates the location user configuration data documents the CMS
// generates from its configuration.
func (svc *service) checkLocationDocuments() error {
	for _, user := range svc.cfg.Users {
		raw, err := xml.Marshal(svc.locationConfigXML(user))
		if err == nil {
			err = schemaError(locationConfigSchema.validate(raw))
		}
		if err != nil {
			return fmt.Errorf("location user configuration document of %s: %w", user.MCPTTID, err)
		}
	}
	return nil
}
