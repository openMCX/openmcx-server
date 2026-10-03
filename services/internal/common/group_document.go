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
	"slices"
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
	Ruleset              *rulesetXML            `xml:"urn:ietf:params:xml:ns:common-policy ruleset"`
	SupportedServices    supportedServicesXML   `xml:"urn:oma:xml:xdm:extensions supported-services"`
	MaxParticipants      int                    `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 on-network-max-participant-count,omitempty"`
	PreconfiguredUseOnly bool                   `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 preconfigured-group-use-only,omitempty"`
	ProtectMedia         bool                   `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 protect-media"`
	ProtectFloor         bool                   `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 protect-floor-control-signalling"`
	AllowEnhancedStatus  bool                   `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 mcdata-allow-enhanced-status,omitempty"`
	EnhancedStatusValues *enhancedStatusListXML `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 mcdata-enhanced-status-operational-values"`
	OnNetworkTemporary   *temporaryXML          `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 on-network-temporary"`
	OnNetworkRegrouped   []regroupedXML         `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 on-network-regrouped"`
	Configuration        *groupConfigurationXML `xml:"urn:openmcx:ns:groupConfiguration:1.0 configuration"`
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
// TS 24.481 clause 7.2.12.1: the <is-list-member> condition.
type conditionXML struct {
	IsListMember *struct{} `xml:"urn:oma:xml:poc:list-service is-list-member"`
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.12.1: the <on-network-allow-getting-member-list> action.
type actionsXML struct {
	AllowGettingMemberList bool `xml:"urn:3gpp:ns:mcpttGroupInfo:1.0 on-network-allow-getting-member-list,omitempty"`
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
	if withList {
		list := &groupListXML{Entries: []groupEntryXML{}}
		for _, id := range group.Members {
			list.Entries = append(list.Entries, groupEntryXML{URI: id, UserPriority: group.UserPriorities[id]})
		}
		ls.List = list
	}
	if group.AllowGettingMemberList {
		ls.Ruleset = &rulesetXML{Rules: []ruleXML{{ID: "members", Conditions: &conditionXML{IsListMember: &struct{}{}},
			Actions: actionsXML{AllowGettingMemberList: true}}}}
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
	if ls.Ruleset != nil {
		for _, rule := range ls.Ruleset.Rules {
			group.AllowGettingMemberList = group.AllowGettingMemberList || rule.Actions.AllowGettingMemberList
		}
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
