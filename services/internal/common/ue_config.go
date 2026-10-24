//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The MCPTT UE configuration document the CMS serves (TS 24.484 clause 8.2): the master document of the organisation
// (the "ue_config" record of the configuration) and the document of each MCPTT UE generated from it (clause 8.2.1A).
//
// Specifications: TS 24.484 V19.6.0 (Rel-19), TS 37.579-1 V18.1.0 (Rel-18), TS 24.483 (cited), TS 23.003 (cited),
// RFC 4122.
package common

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const (
	// TS 24.484 clause 8.2.2.2, clause 8.2.2.3 (the schema's target namespace) and clause 8.2.2.5.
	mcpttUEConfigAUID = "org.3gpp.mcptt.ue-config"
	mcpttUEConfigNS   = "urn:3gpp:mcptt:mcpttUEConfig:1.0"
	mcpttUEConfigMIME = "application/vnd.3gpp.mcptt-ue-config+xml"
	// TS 37.579-1 table 5.5.4.2-1 NOTE 5 names the document "mcptt-ue-configuration.xml" where TS 24.484 clause
	// 8.2.1A names it by the UE's instance ID (MCSUEID); the CMS serves it under both names.
	mcpttUEConfigTestName = "mcptt-ue-configuration.xml"
)

// MCPTTUEConfig is the master MCPTT UE configuration document of the organisation (TS 24.484 clause 8.2.1): the
// values of clause 8.2.2.7 that apply to every MCPTT UE. Zero values take the defaults of TS 37.579-1 table
// 5.5.8.2-1 (N10 2, N4 3, N5 5, IPv6 not preferred); no relay service is offered (this system has no ProSe relay).
type MCPTTUEConfig struct {
	// <name> (TS 24.483 clause 4.2.3).
	Name string `json:"name,omitempty"`
	// <Max-Simul-Call-N10>, 1 to 4 (TS 24.483 clause 4.2.7).
	MaxPrivateCallsN10 int `json:"max_private_calls_n10,omitempty"`
	// <Max-Simul-Call-N4> (TS 24.483 clause 4.2.9).
	MaxGroupCallsN4 int `json:"max_group_calls_n4,omitempty"`
	// <Max-Simul-Trans-N5> (TS 24.483 clause 4.2.10).
	MaxTransmissionsN5 int `json:"max_transmissions_n5,omitempty"`
	// <Prioritized-MCPTT-Group> (TS 24.483 clause 4.2.11); empty: the user's groups, the first at the top
	// priority 7 and each further one a step lower.
	PrioritizedGroups []UEGroupPriority `json:"prioritized_groups,omitempty"`
	// <IPv6Preferred> (TS 24.483 clause 4.2.17).
	IPv6Preferred bool `json:"ipv6_preferred,omitempty"`
}

// UEGroupPriority is one <MCPTT-Group-Priority>: an MCPTT group and its <group-priority-hierarchy>, 0 (lowest) to 7.
type UEGroupPriority struct {
	Group    string `json:"group"`
	Priority int    `json:"priority"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.2.2.6: the values of the master document are in range: N10 1 to 4, N4 and N5 at least 1 when
// given, each group priority 0 to 7 with a group.
func (conf *MCPTTUEConfig) validate() error {
	if conf == nil {
		return nil
	}
	if conf.MaxPrivateCallsN10 < 0 || conf.MaxPrivateCallsN10 > 4 || conf.MaxGroupCallsN4 < 0 || conf.MaxTransmissionsN5 < 0 {
		return errors.New("ue_config: max_private_calls_n10 must be 1 to 4, max_group_calls_n4 and max_transmissions_n5 positive")
	}
	for _, entry := range conf.PrioritizedGroups {
		if entry.Group == "" || entry.Priority < 0 || entry.Priority > 7 {
			return errors.New("ue_config: each prioritized group needs a group and a priority 0 to 7")
		}
	}
	return nil
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.2.2.1: the <mcptt-UE-configuration> document.
type mcpttUEConfigXML struct {
	XMLName xml.Name `xml:"urn:3gpp:mcptt:mcpttUEConfig:1.0 mcptt-UE-configuration"`
	Domain  string   `xml:"domain,attr"`
	// The UE's instance ID (TS 24.484 clause 8.2.1A: "the <MCPTT-UE-id> element shall be set to the MCPTT client's
	// UE ID").
	UEID   *mcpttUEIDXML `xml:"mcptt-UE-id,omitempty"`
	Name   string        `xml:"name,omitempty"`
	Common struct {
		PrivateCall struct {
			N10 int `xml:"Max-Simul-Call-N10"`
		} `xml:"private-call"`
		GroupCall struct {
			N4         int                `xml:"Max-Simul-Call-N4"`
			N5         int                `xml:"Max-Simul-Trans-N5"`
			Priorities []mcpttUEGroupPrio `xml:"Prioritized-MCPTT-Group>MCPTT-Group-Priority"`
		} `xml:"MCPTT-Group-Call"`
	} `xml:"common"`
	OnNetwork struct {
		IPv6Preferred bool `xml:"IPv6Preferred"`
		RelayService  bool `xml:"Relay-Service"`
	} `xml:"on-network"`
}

type mcpttUEIDXML struct {
	InstanceIDs []string `xml:"Instance-ID-URN"`
}

type mcpttUEGroupPrio struct {
	Group     string `xml:"MCPTT-Group-ID"`
	Hierarchy int    `xml:"group-priority-hierarchy"`
}

// ------------------------------------------------------------------------------
// Helper: a value of the master document, or its default.
func orDefault(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.2.1A: the CMS generates the MCPTT UE configuration document of a user's UE from the master
// document, its <MCPTT-UE-id> set to the UE's instance ID (none for the TS 37.579-1 document name). A document needs
// at least one prioritized group (clause 8.2.2.3); false when there is none.
func (svc *service) mcpttUEConfigDocument(user User, instanceID string) ([]byte, bool, error) {
	conf := svc.cfg.UEConfig
	if conf == nil {
		conf = &MCPTTUEConfig{}
	}
	doc := mcpttUEConfigXML{Domain: svc.cfg.Domain, Name: conf.Name}
	if instanceID != "" {
		doc.UEID = &mcpttUEIDXML{InstanceIDs: []string{instanceID}}
	}
	doc.Common.PrivateCall.N10 = orDefault(conf.MaxPrivateCallsN10, 2)
	doc.Common.GroupCall.N4 = orDefault(conf.MaxGroupCallsN4, 3)
	doc.Common.GroupCall.N5 = orDefault(conf.MaxTransmissionsN5, 5)
	for _, entry := range conf.PrioritizedGroups {
		doc.Common.GroupCall.Priorities = append(doc.Common.GroupCall.Priorities, mcpttUEGroupPrio{Group: entry.Group, Hierarchy: entry.Priority})
	}
	if len(conf.PrioritizedGroups) == 0 {
		for index, group := range user.Groups {
			doc.Common.GroupCall.Priorities = append(doc.Common.GroupCall.Priorities, mcpttUEGroupPrio{Group: group, Hierarchy: max(7-index, 0)})
		}
	}
	if len(doc.Common.GroupCall.Priorities) == 0 {
		return nil, false, nil
	}
	doc.OnNetwork.IPv6Preferred = conf.IPv6Preferred
	raw, err := xml.Marshal(doc)
	if err != nil {
		return nil, false, err
	}
	return append([]byte(xml.Header), raw...), true, nil
}

// ------------------------------------------------------------------------------
// TS 23.003 clause 13.8 (cited by TS 24.484 clause 8.2.2.6): the forms of an instance ID this CMS names a UE's
// document by: "urn:gsma:imei:" with the IMEI, or "urn:uuid:" with a UUID (RFC 4122) for a UE without an IMEI.
func validInstanceID(id string) bool {
	rest, imei := strings.CutPrefix(id, "urn:gsma:imei:")
	if !imei {
		var uuid bool
		if rest, uuid = strings.CutPrefix(id, "urn:uuid:"); !uuid || len(rest) != 36 {
			return false
		}
	}
	if rest == "" || len(rest) > 64 {
		return false
	}
	for _, symbol := range rest {
		if !((symbol >= '0' && symbol <= '9') || (symbol >= 'a' && symbol <= 'f') || (symbol >= 'A' && symbol <= 'F') || symbol == '-') {
			return false
		}
	}
	return true
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.2.1A: the document a user's request names: the user's provisioned UE (User.UEs) or, the CMS
// generating it from the master document, any UE named by a valid instance ID; or the TS 37.579-1 document name.
// The instance ID set in the document, and false for a name that is neither.
func (user User) ueDocument(name string) (string, bool) {
	if name == mcpttUEConfigTestName {
		return "", true
	}
	for _, id := range user.UEs {
		if id == name {
			return id, true
		}
	}
	return name, validInstanceID(name)
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.2.1A and clause 6.3.3.3: getMCPTTUEConfig: an MCPTT client reads the MCPTT UE configuration
// document of its UE at CMSXCAPROOTURI/org.3gpp.mcptt.ue-config/users/sip:MCPTTID/MCSUEID, under the MCPTT
// configuration management scope (TS 33.180 clause 5.1.3.1); a configuration manager reads any user's.
func (svc *service) getMCPTTUEConfig(writer http.ResponseWriter, request *http.Request) {
	claims, ok := svc.authenticateBearer(writer, request)
	if !ok || !requireScope(writer, claims, scopePTTConfig) {
		return
	}
	id := request.PathValue("mcpttID")
	if id != claims.MCPTTID && !svc.configManager(claims.MCPTTID) {
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	raw, status := svc.mcpttUEConfigFor(id, request.PathValue("document"))
	if status != http.StatusOK {
		writeJSON(writer, status, map[string]string{"error": http.StatusText(status)})
		return
	}
	writeDocument(writer, request, raw, mcpttUEConfigMIME)
}

// ------------------------------------------------------------------------------
// Helper: the MCPTT UE configuration document of a user's UE by the document name, with the HTTP status.
func (svc *service) mcpttUEConfigFor(mcpttID, name string) ([]byte, int) {
	user, found := svc.siteUser("mcptt_id", mcpttID)
	if !found {
		return nil, http.StatusNotFound
	}
	instanceID, ok := user.ueDocument(name)
	if !ok {
		return nil, http.StatusNotFound
	}
	raw, ok, err := svc.mcpttUEConfigDocument(user, instanceID)
	if err != nil {
		return nil, http.StatusInternalServerError
	}
	if !ok {
		return nil, http.StatusNotFound
	}
	return raw, http.StatusOK
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.2.2.3: checkMCPTTUEConfigDocuments validates the MCPTT UE configuration documents the CMS
// generates from its configuration, one per provisioned UE (and the document without a UE ID).
func (svc *service) checkMCPTTUEConfigDocuments() error {
	for _, user := range svc.cfg.Users {
		for _, id := range append([]string{""}, user.UEs...) {
			raw, ok, err := svc.mcpttUEConfigDocument(user, id)
			if err == nil && ok {
				err = schemaError(mcpttUEConfigSchema.validate(raw))
			}
			if err != nil {
				return fmt.Errorf("MCPTT UE configuration document of %s: %w", user.MCPTTID, err)
			}
		}
	}
	return nil
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 6.3.13.3.2.2 step e and RFC 5875: getInternalConfigurationDocument tells the subscription
// function of the CMS (the MCPTT server's xcap-diff notifier, server credentials) the current entity tag of a
// configuration management document named by its AUID, its XUI (none for a global document) and its name: the MCPTT
// UE configuration and user profile documents of a user and the service configuration documents. A user profile is
// reported under its current name (the profile index in use).
func (svc *service) getInternalConfigurationDocument(writer http.ResponseWriter, request *http.Request) {
	if !svc.requireInternal(writer, request) {
		return
	}
	query := request.URL.Query()
	auid, xui, name := query.Get("auid"), query.Get("xui"), query.Get("document")
	var raw []byte
	status := http.StatusNotFound
	switch {
	case auid == mcpttUEConfigAUID && xui != "":
		raw, status = svc.mcpttUEConfigFor(xui, name)
	case auid == "org.3gpp.mcptt.user-profile" && xui != "":
		raw, status = svc.userProfileDocument(xui)
		if user, ok := svc.siteUser("mcptt_id", xui); ok && status == http.StatusOK {
			name = profileDocumentName(user.profileIndex())
		}
	case xui == "" && name == serviceConfigDocument:
		if document, _, _, ok := svc.serviceConfigDocument(auid); ok {
			raw, status = document, http.StatusOK
		}
	}
	if status != http.StatusOK {
		writeJSON(writer, status, map[string]string{"error": http.StatusText(status)})
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"document": name, "document_etag": documentETag(raw)})
}
