//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The MCS group document: rendering a group as the document, reading a document back, the part of it an
// authenticated identity may read, and the GMOP request for the document without its members.
//
// Specifications: TS 24.481 V19.3.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19),
// OMA XDM (Group XDM), OMA PoC list service.
package common

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// ------------------------------------------------------------------------------
// The MCS group document of TS 24.481 clause 7.2: a <group> of the OMA
// list-service namespace holding one <list-service>, with the MCS elements of
// clause 7.2.4.2 in the mcpttGroupInfo namespace.
const (
	groupDocumentMIME = "application/vnd.oma.poc.groups+xml"
	gmopMIME          = "application/vnd.3gpp.GMOP+xml"
	pocNS             = "urn:oma:xml:poc:list-service"
	mcpttgiNS         = "urn:3gpp:ns:mcpttGroupInfo:1.0"
	commonPolicyNS    = "urn:ietf:params:xml:ns:common-policy"
	xdmExtensionsNS   = "urn:oma:xml:xdm:extensions"
	gmopNS            = "urn:3gpp:ns:mcpttGMOP:1.0"
	// Project extension (TS 24.481 clause 7.2.2 NOTE 1 allows elements of any namespace): the
	// rest of the configuration the MCPTT and MCData servers enforce, for which
	// the supplied specifications define no element, carried as JSON.
	groupConfigurationNS = "urn:openmcx:ns:groupConfiguration:1.0"
	mcpttICSI            = "urn:urn-7:3gpp-service.ims.icsi.mcptt"
	mcdataICSI           = "urn:urn-7:3gpp-service.ims.icsi.mcdata"
	mcvideoICSI          = "urn:urn-7:3gpp-service.ims.icsi.mcvideo"
)

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.2: the <group> root element with its <list-service>.
type groupDocXML struct {
	XMLName     xml.Name       `xml:"urn:oma:xml:poc:list-service group"`
	ListService listServiceXML `xml:"list-service"`
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.2 and clause 7.2.4.2: the <list-service> element with the MCS elements this GMS uses.
type listServiceXML struct {
	URI  string        `xml:"uri,attr"`
	List *groupListXML `xml:"list"`
	// <cp:ruleset>: <on-network-allow-getting-member-list> for the members (TS 24.481 clause 7.2.12.1).
	Ruleset              *rulesetXML          `xml:"urn:ietf:params:xml:ns:common-policy ruleset"`
	SupportedServices    supportedServicesXML `xml:"urn:oma:xml:xdm:extensions supported-services"`
	InviteMembers        *bool                `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 on-network-invite-members,omitempty"`
	MaxDuration          string               `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 on-network-maximum-duration,omitempty"`
	MaxParticipants      int                  `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 on-network-max-participant-count,omitempty"`
	PreconfiguredUseOnly bool                 `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 preconfigured-group-use-only,omitempty"`
	Disabled             *struct{}            `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 on-network-disabled,omitempty"`
	ProtectMedia         bool                 `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 protect-media"`
	ProtectFloor         bool                 `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 protect-floor-control-signalling"`
	// MCData group (TS 24.481 clause 7.2.2): the short data service, file distribution and their size limits.
	AllowSDS             *bool                  `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 mcdata-allow-short-data-service,omitempty"`
	AllowFD              *bool                  `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 mcdata-allow-file-distribution,omitempty"`
	AllowEnhancedStatus  bool                   `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 mcdata-allow-enhanced-status,omitempty"`
	EnhancedStatusValues *enhancedStatusListXML `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 mcdata-enhanced-status-operational-values"`
	MaxSDSBytes          int                    `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 mcdata-on-network-max-data-size-for-SDS,omitempty"`
	MaxFDBytes           int                    `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 mcdata-on-network-max-data-size-for-FD,omitempty"`
	MaxAutoRecvBytes     int                    `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 mcdata-on-network-max-data-size-auto-recv,omitempty"`
	OnNetworkTemporary   *temporaryXML          `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 on-network-temporary"`
	OnNetworkRegrouped   []regroupedXML         `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 on-network-regrouped"`
	ForbiddenFAs         *listEntryXML          `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 forbidden-deaffiliation-FAs"`
	ForbiddenIfLastFAs   *listEntryXML          `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 forbidden-deaffiliation-if-last-FAs"`
	Configuration        *groupConfigurationXML `xml:"urn:openmcx:ns:groupConfiguration:1.0 configuration"`
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.4.2: a ListEntryType element, one <entry> with a <uri-entry> per URI.
type listEntryXML struct {
	Entries []listEntryEntryXML `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 entry"`
}

type listEntryEntryXML struct {
	URI string `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 uri-entry"`
}

// ------------------------------------------------------------------------------
// Helper: the ListEntryType element of URIs; nil without any.
func listEntries(uris []string) *listEntryXML {
	if len(uris) == 0 {
		return nil
	}
	list := &listEntryXML{}
	for _, uri := range uris {
		list.Entries = append(list.Entries, listEntryEntryXML{URI: uri})
	}
	return list
}

// ------------------------------------------------------------------------------
// Helper: the URIs of a ListEntryType element; an empty <uri-entry> is an error.
func listEntryURIs(list *listEntryXML) ([]string, error) {
	if list == nil {
		return nil, nil
	}
	var uris []string
	for _, entry := range list.Entries {
		uri := strings.TrimSpace(entry.URI)
		if uri == "" {
			return nil, errors.New("an <entry> without its <uri-entry>")
		}
		uris = append(uris, uri)
	}
	return uris, nil
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.2 and clause 7.2.4.2: <on-network-temporary> and <on-network-regrouped>.
type temporaryXML struct {
	Constituents constituentsXML `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 constituent-MCPTT-group-IDs"`
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.4.2: the <constituent-MCPTT-group-IDs> element.
type constituentsXML struct {
	IDs []string `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 constituent-MCPTT-group-ID"`
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.2 and clause 7.2.4.2: the <on-network-regrouped> element.
type regroupedXML struct {
	XMLName      xml.Name        `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 on-network-regrouped"`
	TGI          string          `xml:"temporary-MCPTT-group-ID,attr"`
	Requestor    string          `xml:"temporary-MCPTT-group-requestor,attr"`
	Constituents constituentsXML `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 constituent-MCPTT-group-IDs"`
	ProtectMedia *bool           `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 protect-media"`
	ProtectFloor *bool           `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 protect-floor-control-signalling"`
}

// ------------------------------------------------------------------------------
// Helper: the regroup mark an <on-network-regrouped> element carries.
func (regrouped regroupedXML) mark() *TemporaryRegroup {
	return &TemporaryRegroup{TGI: regrouped.TGI, Requestor: regrouped.Requestor, Constituents: regrouped.Constituents.IDs,
		ProtectMedia: regrouped.ProtectMedia, ProtectFloor: regrouped.ProtectFloor}
}

// ------------------------------------------------------------------------------
// Helper: the <on-network-regrouped> element of a regroup mark.
func regroupedElement(mark *TemporaryRegroup) regroupedXML {
	return regroupedXML{TGI: mark.TGI, Requestor: mark.Requestor, Constituents: constituentsXML{IDs: mark.Constituents},
		ProtectMedia: mark.ProtectMedia, ProtectFloor: mark.ProtectFloor}
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.2: the <list> of the members.
type groupListXML struct {
	Entries []groupEntryXML `xml:"entry"`
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.2 and clause 7.2.4.2: one member <entry> with its <user-priority>.
type groupEntryXML struct {
	URI          string `xml:"uri,attr"`
	UserPriority int    `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 user-priority,omitempty"`
	// <on-network-recvonly> (TS 24.481 clause 7.2.4.2): the member only receives in the group's calls.
	RecvOnly *struct{} `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 on-network-recvonly,omitempty"`
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.12.1: the <cp:ruleset> of the group document.
type rulesetXML struct {
	Rules []ruleXML `xml:"rule"`
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.12.1: one <rule> with its <conditions> and <actions>.
type ruleXML struct {
	ID         string        `xml:"id,attr"`
	Conditions *conditionXML `xml:"conditions"`
	Actions    actionsXML    `xml:"actions"`
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.4.1: the <is-list-member> condition (every member), or an <identity> condition naming one
// member (RFC 4745 <one>).
type conditionXML struct {
	IsListMember *struct{}    `xml:"urn:oma:xml:poc:list-service is-list-member"`
	Identity     *identityXML `xml:"urn:ietf:params:xml:ns:common-policy identity"`
}

// ------------------------------------------------------------------------------
// RFC 4745 clause 7.1: an <identity> condition with its <one> identities.
type identityXML struct {
	One []oneXML `xml:"urn:ietf:params:xml:ns:common-policy one"`
}

// ------------------------------------------------------------------------------
// RFC 4745 clause 7.1.1: one identity, by its "id" attribute.
type oneXML struct {
	ID string `xml:"id,attr"`
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.4.2: the <actions> of a rule this GMS writes: getting the member list, the MCPTT and MCVideo
// emergency group call, imminent peril call and emergency alert (TS 24.379 clause 6.3.3.1.13 and TS 24.281 clause 6.3.3.1.12), and
// transmitting data in the group (TS 24.282 clause 11.1).
type actionsXML struct {
	JoinHandling               bool `xml:"urn:oma:xml:poc:list-service join-handling,omitempty"`
	AllowGettingMemberList     bool `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 on-network-allow-getting-member-list,omitempty"`
	AllowEmergencyCall         bool `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 allow-MCPTT-emergency-call,omitempty"`
	AllowImminentPeril         bool `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 allow-imminent-peril-call,omitempty"`
	AllowEmergencyAlert        bool `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 allow-MCPTT-emergency-alert,omitempty"`
	VideoAllowEmergencyCall    bool `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 mcvideo-allow-emergency-call,omitempty"`
	VideoAllowEmergencyAlert   bool `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 mcvideo-allow-emergency-alert,omitempty"`
	VideoAllowImminentPeril    bool `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 mcvideo-allow-imminent-peril-call,omitempty"`
	DataAllowTransmitThisGroup bool `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 mcdata-allow-transmit-data-in-this-group,omitempty"`
}

// ------------------------------------------------------------------------------
// Helper: whether a rule grants anything.
func (actions actionsXML) any() bool { return actions != actionsXML{} }

// ------------------------------------------------------------------------------
// Helper: the identities a priority policy lists under a key (MCPTT or MCVideo IDs).
func policyIDs(policy map[string]any, key string) []string {
	var out []string
	list, _ := policy[key].([]any)
	for _, item := range list {
		if id, ok := item.(string); ok {
			out = append(out, id)
		}
	}
	if typed, ok := policy[key].([]string); ok {
		out = append(out, typed...)
	}
	return out
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.12.1: the rules of a group: one for every member (<is-list-member>) with the actions the group
// allows all its members, and one per member listed (<identity>) with the actions the group allows that member: the
// emergency, imminent peril and emergency alert lists of the MCPTT and MCVideo priority policies, and the MCData
// members that may transmit.
func groupRules(group Group) *rulesetXML {
	all := actionsXML{AllowGettingMemberList: group.AllowGettingMemberList, AllowEmergencyCall: group.AllowEmergencyCall,
		AllowImminentPeril: group.AllowImminentPeril, AllowEmergencyAlert: group.AllowEmergencyAlert}
	var order []string
	byID := map[string]*actionsXML{}
	grant := func(ids []string, set func(*actionsXML)) {
		for _, id := range ids {
			if byID[id] == nil {
				byID[id] = &actionsXML{}
				order = append(order, id)
			}
			set(byID[id])
		}
	}
	// <join-handling> (TS 24.379 clause 6.3.5.3): every member may join, unless call_policy join_members names who may.
	if joiners := policyIDs(group.CallPolicy, "join_members"); group.CallPolicy != nil && group.CallPolicy["join_members"] != nil {
		grant(joiners, func(a *actionsXML) { a.JoinHandling = true })
	} else {
		all.JoinHandling = true
	}
	grant(policyIDs(group.PriorityPolicy, "emergency_users"), func(a *actionsXML) { a.AllowEmergencyCall = true })
	grant(policyIDs(group.PriorityPolicy, "imminent_users"), func(a *actionsXML) { a.AllowImminentPeril = true })
	grant(policyIDs(group.PriorityPolicy, "alert_users"), func(a *actionsXML) { a.AllowEmergencyAlert = true })
	if video := group.MCVideo; video != nil {
		all.VideoAllowEmergencyCall, all.VideoAllowImminentPeril = video.AllowEmergencyCall, video.AllowImminentPeril
		all.VideoAllowEmergencyAlert = video.AllowEmergencyAlert
		grant(policyIDs(video.PriorityPolicy, "emergency_users"), func(a *actionsXML) { a.VideoAllowEmergencyCall = true })
		grant(policyIDs(video.PriorityPolicy, "imminent_users"), func(a *actionsXML) { a.VideoAllowImminentPeril = true })
		grant(policyIDs(video.PriorityPolicy, "alert_users"), func(a *actionsXML) { a.VideoAllowEmergencyAlert = true })
	}
	if data := group.MCData; data != nil {
		all.DataAllowTransmitThisGroup = data.TransmitAll
		grant(data.TransmitMembers, func(a *actionsXML) { a.DataAllowTransmitThisGroup = true })
	}
	ruleset := &rulesetXML{}
	if all.any() {
		ruleset.Rules = append(ruleset.Rules, ruleXML{ID: "members", Conditions: &conditionXML{IsListMember: &struct{}{}},
			Actions: all})
	}
	for index, id := range order {
		ruleset.Rules = append(ruleset.Rules, ruleXML{ID: fmt.Sprintf("member-%d", index+1),
			Conditions: &conditionXML{Identity: &identityXML{One: []oneXML{{ID: id}}}}, Actions: *byID[id]})
	}
	if len(ruleset.Rules) == 0 {
		return nil
	}
	return ruleset
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.2: the <supported-services> of the group (OMA Group XDM).
type supportedServicesXML struct {
	Services []serviceXML `xml:"service"`
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.2: one supported <service>, named by its ICSI.
type serviceXML struct {
	Enabler string `xml:"enabler,attr"`
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.4.2: <mcdata-enhanced-status-operational-values>.
type enhancedStatusListXML struct {
	Status []enhancedStatusXML `xml:"status"`
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.4.2: one operational value of the enhanced status.
type enhancedStatusXML struct {
	ID        string            `xml:"id"`
	ShortText languageStringXML `xml:"shortText"`
	// <description> is mandatory in enhancedStatusType; the value is repeated.
	Description languageStringXML `xml:"description"`
}

// ------------------------------------------------------------------------------
// Helper: a text with its language.
type languageStringXML struct {
	LangType string `xml:"langType"`
	LangText string `xml:"langText"`
}

// ------------------------------------------------------------------------------
// Helper: the project extension element, carrying JSON.
type groupConfigurationXML struct {
	JSON string `xml:",chardata"`
}

// ------------------------------------------------------------------------------
// Helper: groupExtension is the part of Group carried in the project extension.
type groupExtension struct {
	Type              string                 `json:"type,omitempty"`
	SubordinateGroups []string               `json:"subordinate_groups,omitempty"`
	Regrouped         bool                   `json:"regrouped,omitempty"`
	CallPolicy        map[string]interface{} `json:"call_policy,omitempty"`
	FloorPriorityCaps map[string]uint8       `json:"floor_priority_caps,omitempty"`
	PriorityPolicy    map[string]interface{} `json:"priority_policy,omitempty"`
	MCData            *GroupMCData           `json:"mcdata,omitempty"`
	// The MCVideo members and settings, which the MCVideo server
	// reads with the group (TS 24.281 clause 6.3.2.1.8 and clause 6.3.5, TS 24.481).
	MCVideo *GroupMCVideo `json:"mcvideo,omitempty"`
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.2: groupDocument renders a group, already reduced to what the requester may
// read, as the group document. withList false leaves out <list> (TS 24.481 clause 6.3.16.3).
func groupDocument(group Group, withList bool) ([]byte, error) {
	ls := listServiceXML{URI: group.ID, ProtectMedia: group.ProtectMedia, ProtectFloor: group.ProtectFloor,
		PreconfiguredUseOnly: group.PreconfiguredUseOnly}
	if group.Disabled {
		ls.Disabled = &struct{}{}
	}
	ls.ForbiddenFAs = listEntries(group.ForbiddenDeaffiliationFAs)
	ls.ForbiddenIfLastFAs = listEntries(group.ForbiddenDeaffiliationIfLastFAs)
	if withList {
		list := &groupListXML{Entries: []groupEntryXML{}}
		receiveOnly := policyIDs(group.PriorityPolicy, "receive_only_users")
		for _, id := range group.Members {
			entry := groupEntryXML{URI: id, UserPriority: group.UserPriorities[id]}
			if slices.Contains(receiveOnly, id) {
				entry.RecvOnly = &struct{}{}
			}
			list.Entries = append(list.Entries, entry)
		}
		ls.List = list
	}
	ls.Ruleset = groupRules(group)
	// <on-network-invite-members> (TS 24.481 clause 7.2.4.2): true for a prearranged group, whose members are invited
	// to its calls; a chat group has none (TS 24.379 clause 10.1.2).
	// <on-network-maximum-duration>, which TS 24.481 clause 7.2.7 requires with it: the duration the MCPTT server
	// enforces (call_policy maximum_duration_ms, by default one hour).
	if group.Type != "chat" {
		invite := true
		ls.InviteMembers = &invite
		durationMs := 3600000.0
		if value, ok := group.CallPolicy["maximum_duration_ms"].(float64); ok && value > 0 {
			durationMs = value
		}
		ls.MaxDuration = fmt.Sprintf("PT%dS", int(durationMs/1000))
	}
	ls.SupportedServices.Services = []serviceXML{{Enabler: mcpttICSI}}
	if group.MCData != nil {
		ls.SupportedServices.Services = append(ls.SupportedServices.Services, serviceXML{Enabler: mcdataICSI})
	}
	if group.MCVideo != nil {
		ls.SupportedServices.Services = append(ls.SupportedServices.Services, serviceXML{Enabler: mcvideoICSI})
	}
	if max, ok := group.CallPolicy["max_participants"].(float64); ok {
		ls.MaxParticipants = int(max)
	}
	if data := group.MCData; data != nil {
		ls.AllowSDS, ls.AllowFD = &data.AllowSDS, &data.AllowFD
		ls.MaxSDSBytes, ls.MaxFDBytes, ls.MaxAutoRecvBytes = data.MaxSDSBytes, data.MaxFDBytes, data.MaxAutoRecvBytes
	}
	if group.MCData != nil && group.MCData.AllowEnhancedStatus {
		ls.AllowEnhancedStatus = true
		values := &enhancedStatusListXML{}
		for _, value := range group.MCData.EnhancedStatusValues {
			text := languageStringXML{LangType: "en", LangText: value.Value}
			values.Status = append(values.Status, enhancedStatusXML{ID: value.ID, ShortText: text, Description: text})
		}
		ls.EnhancedStatusValues = values
	}
	if len(group.TemporaryConstituents) > 0 {
		ls.OnNetworkTemporary = &temporaryXML{Constituents: constituentsXML{IDs: group.TemporaryConstituents}}
	}
	if group.RegroupedBy != nil {
		ls.OnNetworkRegrouped = []regroupedXML{regroupedElement(group.RegroupedBy)}
	}
	extension := groupExtension{Type: group.Type, SubordinateGroups: group.SubordinateGroups, Regrouped: group.Regrouped,
		CallPolicy: group.CallPolicy, FloorPriorityCaps: group.FloorPriorityCaps, PriorityPolicy: group.PriorityPolicy, MCData: group.MCData,
		MCVideo: group.MCVideo}
	raw, err := json.Marshal(extension)
	if err != nil {
		return nil, err
	}
	if string(raw) != "{}" {
		ls.Configuration = &groupConfigurationXML{JSON: string(raw)}
	}
	doc, err := xml.Marshal(groupDocXML{ListService: ls})
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), doc...), nil
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.2: parseGroupDocument reads a group document back into a Group.
func parseGroupDocument(raw []byte) (Group, error) {
	var doc groupDocXML
	if err := xml.Unmarshal(raw, &doc); err != nil {
		return Group{}, err
	}
	ls := doc.ListService
	if ls.URI == "" {
		return Group{}, errors.New("group document without a list-service uri")
	}
	group := Group{ID: ls.URI, ProtectMedia: ls.ProtectMedia, ProtectFloor: ls.ProtectFloor,
		PreconfiguredUseOnly: ls.PreconfiguredUseOnly, Members: []string{}}
	if ls.List != nil {
		for _, entry := range ls.List.Entries {
			if entry.URI == "" || slices.Contains(group.Members, entry.URI) {
				return Group{}, errors.New("empty or repeated group entry")
			}
			group.Members = append(group.Members, entry.URI)
			if entry.UserPriority != 0 {
				if group.UserPriorities == nil {
					group.UserPriorities = map[string]int{}
				}
				group.UserPriorities[entry.URI] = entry.UserPriority
			}
		}
	}
	group.Disabled = ls.Disabled != nil
	var err error
	if group.ForbiddenDeaffiliationFAs, err = listEntryURIs(ls.ForbiddenFAs); err != nil {
		return Group{}, err
	}
	if group.ForbiddenDeaffiliationIfLastFAs, err = listEntryURIs(ls.ForbiddenIfLastFAs); err != nil {
		return Group{}, err
	}
	if ls.InviteMembers != nil && !*ls.InviteMembers && group.Type == "" {
		group.Type = "chat"
	}
	if ls.OnNetworkTemporary != nil {
		group.TemporaryConstituents = ls.OnNetworkTemporary.Constituents.IDs
		if len(group.TemporaryConstituents) == 0 {
			return Group{}, errors.New("a temporary group without constituent groups")
		}
	}
	// One temporary group at a time combines a group (TS 24.379 clause 16.2.4.1 step 2a).
	if len(ls.OnNetworkRegrouped) > 1 {
		return Group{}, errors.New("a group regrouped more than once")
	}
	if len(ls.OnNetworkRegrouped) == 1 {
		group.RegroupedBy = ls.OnNetworkRegrouped[0].mark()
		if group.RegroupedBy.TGI == "" || group.RegroupedBy.Requestor == "" {
			return Group{}, errors.New("<on-network-regrouped> without its attributes")
		}
	}
	if ls.Configuration != nil {
		var extension groupExtension
		if err := json.Unmarshal([]byte(ls.Configuration.JSON), &extension); err != nil {
			return Group{}, err
		}
		group.Type, group.SubordinateGroups, group.Regrouped = extension.Type, extension.SubordinateGroups, extension.Regrouped
		group.CallPolicy, group.FloorPriorityCaps, group.PriorityPolicy = extension.CallPolicy, extension.FloorPriorityCaps, extension.PriorityPolicy
		group.MCData, group.MCVideo = extension.MCData, extension.MCVideo
	}
	if ls.Ruleset != nil {
		readRules(&group, ls.Ruleset.Rules)
	}
	// <on-network-recvonly> members: the priority policy's receive_only_users.
	if ls.List != nil {
		for _, entry := range ls.List.Entries {
			if entry.RecvOnly == nil {
				continue
			}
			if group.PriorityPolicy == nil {
				group.PriorityPolicy = map[string]any{}
			}
			if ids := policyIDs(group.PriorityPolicy, "receive_only_users"); !slices.Contains(ids, entry.URI) {
				group.PriorityPolicy["receive_only_users"] = append(ids, entry.URI)
			}
		}
	}
	if group.CallPolicy == nil && ls.MaxParticipants > 0 {
		group.CallPolicy = map[string]interface{}{"max_participants": float64(ls.MaxParticipants)}
	}
	return group, nil
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.12.1: readableGroup is the part of a group an authenticated identity may read: an authorized MCS
// server reads the whole document; a member reads <list-service> without <list>, except its own <entry>, unless the
// group grants <on-network-allow-getting-member-list>. ok is false when the identity may read nothing.
func readableGroup(group Group, identity string, server bool) (Group, bool) {
	if server {
		return group, true
	}
	if !slices.Contains(group.Members, identity) {
		return Group{}, false
	}
	if group.AllowGettingMemberList {
		return group, true
	}
	return onlyMembers(group, func(id string) bool { return id == identity }), true
}

// ------------------------------------------------------------------------------
// Helper: onlyMembers keeps the entries, priorities and MCData entries a filter allows.
func onlyMembers(group Group, keep func(string) bool) Group {
	out := group
	out.Members = []string{}
	out.UserPriorities = nil
	for _, id := range group.Members {
		if !keep(id) {
			continue
		}
		out.Members = append(out.Members, id)
		if priority, ok := group.UserPriorities[id]; ok {
			if out.UserPriorities == nil {
				out.UserPriorities = map[string]int{}
			}
			out.UserPriorities[id] = priority
		}
	}
	if group.MCData != nil {
		data := *group.MCData
		data.Members = []string{}
		for _, id := range group.MCData.Members {
			if keep(id) {
				data.Members = append(data.Members, id)
			}
		}
		data.TransmitMembers = slices.DeleteFunc(slices.Clone(group.MCData.TransmitMembers), func(id string) bool { return !keep(id) })
		out.MCData = &data
	}
	if group.MCVideo != nil {
		video := *group.MCVideo
		video.Members = slices.DeleteFunc(slices.Clone(group.MCVideo.Members), func(id string) bool { return !keep(id) })
		video.UserPriorities = nil
		for id, priority := range group.MCVideo.UserPriorities {
			if keep(id) {
				if video.UserPriorities == nil {
					video.UserPriorities = map[string]int{}
				}
				video.UserPriorities[id] = priority
			}
		}
		out.MCVideo = &video
	}
	return out
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.3.4.2: gmopGetExcludingMemberList reports whether a GMOP document asks for
// the group document without its members.
func gmopGetExcludingMemberList(raw []byte) (bool, error) {
	var doc struct {
		XMLName xml.Name `xml:"urn:3gpp:ns:mcpttGMOP:1.0 document"`
		Request *struct {
			Get *struct{} `xml:"urn:3gpp:ns:mcpttGMOP:1.0 get-excluding-memberlist"`
		} `xml:"urn:3gpp:ns:mcpttGMOP:1.0 request"`
	}
	if err := xml.Unmarshal(raw, &doc); err != nil {
		return false, err
	}
	return doc.Request != nil && doc.Request.Get != nil, nil
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.12.1: the rules of an uploaded group document read back: the actions of the <is-list-member>
// rule become the group's settings for every member, those of <identity> rules the lists of the members they name.
func readRules(group *Group, rules []ruleXML) {
	add := func(policy *map[string]any, key, id string) {
		if *policy == nil {
			*policy = map[string]any{}
		}
		ids := policyIDs(*policy, key)
		if !slices.Contains(ids, id) {
			(*policy)[key] = append(ids, id)
		}
	}
	for _, rule := range rules {
		actions := rule.Actions
		if rule.Conditions != nil && rule.Conditions.IsListMember != nil {
			group.AllowGettingMemberList = group.AllowGettingMemberList || actions.AllowGettingMemberList
			group.AllowEmergencyCall = group.AllowEmergencyCall || actions.AllowEmergencyCall
			group.AllowImminentPeril = group.AllowImminentPeril || actions.AllowImminentPeril
			group.AllowEmergencyAlert = group.AllowEmergencyAlert || actions.AllowEmergencyAlert
			if group.MCVideo != nil {
				group.MCVideo.AllowEmergencyCall = group.MCVideo.AllowEmergencyCall || actions.VideoAllowEmergencyCall
				group.MCVideo.AllowImminentPeril = group.MCVideo.AllowImminentPeril || actions.VideoAllowImminentPeril
				group.MCVideo.AllowEmergencyAlert = group.MCVideo.AllowEmergencyAlert || actions.VideoAllowEmergencyAlert
			}
			if group.MCData != nil {
				group.MCData.TransmitAll = group.MCData.TransmitAll || actions.DataAllowTransmitThisGroup
			}
			continue
		}
		if rule.Conditions == nil || rule.Conditions.Identity == nil {
			continue
		}
		for _, one := range rule.Conditions.Identity.One {
			if actions.JoinHandling {
				add(&group.CallPolicy, "join_members", one.ID)
			}
			if actions.AllowEmergencyCall {
				add(&group.PriorityPolicy, "emergency_users", one.ID)
			}
			if actions.AllowImminentPeril {
				add(&group.PriorityPolicy, "imminent_users", one.ID)
			}
			if actions.AllowEmergencyAlert {
				add(&group.PriorityPolicy, "alert_users", one.ID)
			}
			if video := group.MCVideo; video != nil {
				if actions.VideoAllowEmergencyCall {
					add(&video.PriorityPolicy, "emergency_users", one.ID)
				}
				if actions.VideoAllowImminentPeril {
					add(&video.PriorityPolicy, "imminent_users", one.ID)
				}
				if actions.VideoAllowEmergencyAlert {
					add(&video.PriorityPolicy, "alert_users", one.ID)
				}
			}
			if data := group.MCData; data != nil && actions.DataAllowTransmitThisGroup &&
				!slices.Contains(data.TransmitMembers, one.ID) {
				data.TransmitMembers = append(data.TransmitMembers, one.ID)
			}
		}
	}
}
