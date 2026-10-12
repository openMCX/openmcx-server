// The MCPTT user profile document the CMS serves and accepts: rendering a user's configuration as the document,
// its ruleset of granted rights, and the validation constraints the schema does not express.
//
// Specifications: TS 24.484 V19.6.0 (Rel-19), RFC 4825, RFC 4745.
package common

import (
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
)

// ------------------------------------------------------------------------------
// The MCPTT user profile document of TS 24.484 clause 8.3, which the
// CMS serves and accepts: it conforms to the schema of TS 24.484 clause 8.3.2.3, which the CMS
// checks on every replacement (TS 24.484 clause 8.3.2.6). The configuration a lab user has maps
// to the schema's elements where the schema has one:
//
//   - the identity: the "XUI-URI" attribute and <Common>/<MCPTTUserID>;
//   - the private call targets: <Common>/<PrivateCall>/<PrivateCallList>;
//   - the groups: <OnNetwork>/<MCPTTGroupInfo>; the N2 limit: <MaxAffiliationsN2>;
//   - <IncomingPrivateCallList> in the <anyExt> of <OnNetwork> (TS 24.484 clause 8.3.2.1 item 10 g);
//   - the granted rights: boolean elements of the <cp:ruleset> actions, the
//     Release 13 ones directly and the later ones in its <anyExt> (TS 24.484 clause 8.3.2.1 item
//     11). The MCData rights are the elements of the MCData user profile schema
//     (TS 24.484 clause 10.3.2.3) in its namespace.
//
// What the schema cannot express goes in an element of this implementation's own
// namespace, which TS 24.484 clause 8.3.2.1 item 12 permits: the MC ID, SIP URI and client ID, and
// the emergency private call and private emergency alert recipients. The schema
// has one recipient each, and requires a ProSe user entry beside the emergency
// private call recipient; the lab's users are on-network and may have several.
// Rights of the MCData service that the MCData user profile schema does not
// define carry this namespace too.
const userProfileMIME = "application/vnd.3gpp.mcptt-user-profile+xml"

const profileExtensionNS = "urn:openmcx:ns:userProfile:1.0"

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1: the <mcptt-user-profile> root element.
type profileXML struct {
	XMLName      xml.Name          `xml:"urn:3gpp:mcptt:user-profile:1.0 mcptt-user-profile"`
	XUIURI       string            `xml:"XUI-URI,attr"`
	ProfileIndex int               `xml:"user-profile-index,attr"`
	Status       bool              `xml:"Status"`
	ProfileName  string            `xml:"ProfileName,omitempty"`
	Common       profileCommon     `xml:"Common"`
	OnNetwork    *profileOnNetwork `xml:"OnNetwork,omitempty"`
	Ruleset      *profileRuleset   `xml:"urn:ietf:params:xml:ns:common-policy ruleset,omitempty"`
	Extension    *profileExtension `xml:"urn:openmcx:ns:userProfile:1.0 profile-extension,omitempty"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1 item 8: the <Common> element.
type profileCommon struct {
	Index       string              `xml:"index,attr"`
	MCPTTUserID profileEntry        `xml:"MCPTTUserID"`
	PrivateCall *profilePrivateCall `xml:"PrivateCall,omitempty"`
	GroupCall   profileGroupCall    `xml:"MCPTT-group-call"`
	// TS 24.484 clause 8.3.2.1 item 8g: one <MissionCriticalOrganization>.
	Organization string          `xml:"MissionCriticalOrganization,omitempty"`
	AnyExt       *locationURIExt `xml:"anyExt,omitempty"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1 item 8e: the <MCPTT-group-call> element of <Common>: the N6 limit, the group of an
// emergency group call, of an imminent peril call and of an emergency alert (TS 24.379 clause 6.3.3.1.13 reads
// them), and the user's priority.
type profileGroupCall struct {
	MaxCallsN6 int                    `xml:"MaxSimultaneousCallsN6"`
	Emergency  profileGroupInitiation `xml:"EmergencyCall"`
	Imminent   profileGroupInitiation `xml:"ImminentPerilCall"`
	Alert      profileAlert           `xml:"EmergencyAlert"`
	Priority   int                    `xml:"Priority"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.3: <MCPTTGroupInitiation> with its <entry>.
type profileGroupInitiation struct {
	Entry profileEntry `xml:"MCPTTGroupInitiation>entry"`
}

// ------------------------------------------------------------------------------
// Helper: the <entry> of a group initiation or emergency alert: a dedicated group, or the group the user has
// selected when none is configured.
func groupInitiationEntry(group string) profileEntry {
	if group == "" {
		return profileEntry{EntryInfo: "UseCurrentlySelectedGroup"}
	}
	return profileEntry{EntryInfo: "DedicatedGroup", URI: group}
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.3: profileEntry is the EntryType.
type profileEntry struct {
	EntryInfo string `xml:"entry-info,attr,omitempty"`
	Index     string `xml:"index,attr,omitempty"`
	URI       string `xml:"uri-entry"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1 item 8: the <PrivateCall> element of <Common>.
type profilePrivateCall struct {
	List      privateCallList          `xml:"PrivateCallList"`
	Emergency *profilePrivateEmergency `xml:"EmergencyCall,omitempty"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.3 (EmergencyCallType, MCPTTPrivateRecipientEntryType): the emergency private call's
// recipient, "LocallyDetermined" (the user chooses) or "UsePreConfigured" with its MCPTT ID. <ProSeUserID-entry> is
// mandatory in the type; this system is on-network only, so its <User-Info-ID> is six zero octets (the value must be
// 6 octets, TS 24.484 clause 8.4.2) and names no ProSe user.
type profilePrivateEmergency struct {
	Recipient struct {
		Entry profileEntry `xml:"entry"`
		ProSe struct {
			UserInfoID string `xml:"User-Info-ID"`
		} `xml:"ProSeUserID-entry"`
	} `xml:"MCPTTPrivateRecipient"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.3: privateCallList is the PrivateCallListEntryType, which needs one child: an
// empty <anyExt> stands for an empty list.
type privateCallList struct {
	URIs   []profileEntry `xml:"PrivateCallURI"`
	AnyExt *struct{}      `xml:"anyExt,omitempty"`
}

// ------------------------------------------------------------------------------
// Helper: the <PrivateCallList> of a list of URIs, with an empty <anyExt> when it has none.
func newPrivateCallList(uris []string) privateCallList {
	var list privateCallList
	for _, uri := range uris {
		list.URIs = append(list.URIs, profileEntry{URI: uri})
	}
	if len(list.URIs) == 0 {
		list.AnyExt = &struct{}{}
	}
	return list
}

// ------------------------------------------------------------------------------
// Helper: the URIs of a <PrivateCallList>.
func (list *privateCallList) uris() []string {
	if list == nil {
		return nil
	}
	var out []string
	for _, entry := range list.URIs {
		out = append(out, entry.URI)
	}
	return out
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1 item 10: the <OnNetwork> element.
type profileOnNetwork struct {
	Index             string               `xml:"index,attr"`
	GroupInfo         *profileEntryList    `xml:"MCPTTGroupInfo,omitempty"`
	MaxAffiliationsN2 int                  `xml:"MaxAffiliationsN2,omitempty"`
	EmergencyAlert    *profileAlert        `xml:"PrivateEmergencyAlert,omitempty"`
	AnyExt            *profileOnNetworkExt `xml:"anyExt,omitempty"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1 item 10: a list of <entry> elements (EntryType).
type profileEntryList struct {
	Entries []profileEntry `xml:"entry"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.3: profileAlert is the EmergencyAlertType: one <entry>.
type profileAlert struct {
	Entry profileEntry `xml:"entry"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1 item 10 g: the <anyExt> of <OnNetwork>.
type profileOnNetworkExt struct {
	IncomingList *privateCallList `xml:"IncomingPrivateCallList,omitempty"`
	// Item 10 g ii: <FunctionalAliasList>, the functional aliases the user may activate.
	FunctionalAliasList *profileEntryList `xml:"FunctionalAliasList,omitempty"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1 item 11: the <cp:ruleset> of the profile (RFC 4745).
type profileRuleset struct {
	Rules []profileRule `xml:"rule"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1 item 11: one <rule> with its <actions>.
type profileRule struct {
	ID         string             `xml:"id,attr"`
	Conditions *profileConditions `xml:"conditions,omitempty"`
	Actions    profileElements    `xml:"actions"`
}

// ------------------------------------------------------------------------------
// RFC 4745 section 7.1: the <conditions> of a rule, with the <identity> of the users it applies to.
type profileConditions struct {
	Identity struct {
		One []profileOne `xml:"one"`
	} `xml:"identity"`
}

// ------------------------------------------------------------------------------
// RFC 4745 section 7.1.1: one <one id="..."> of an <identity>.
type profileOne struct {
	ID string `xml:"id,attr"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1 item 11: the children of <actions>.
type profileElements struct {
	Items []profileElement `xml:",any"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1 item 11: profileElement is any element of the ruleset actions: a boolean right, or an
// <anyExt>.
type profileElement struct {
	XMLName  xml.Name
	Text     string           `xml:",chardata"`
	Children []profileElement `xml:",any"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1 item 12: the element of this implementation's own namespace.
type profileExtension struct {
	MCID                string             `xml:"mc-id,omitempty"`
	SIPURI              string             `xml:"sip-uri,omitempty"`
	ClientID            string             `xml:"client-id,omitempty"`
	EmergencyRecipients *profileRecipients `xml:"emergency-private-call-recipients,omitempty"`
	AlertRecipients     *profileRecipients `xml:"private-emergency-alert-recipients,omitempty"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1 item 12 (project extension): profileRecipients: "UsePreConfigured" with the listed users, or
// "LocallyDetermined".
type profileRecipients struct {
	EntryInfo string   `xml:"entry-info,attr"`
	URIs      []string `xml:"uri-entry"`
}

// ------------------------------------------------------------------------------
// Helper: the recipients of an emergency call or alert: locally determined, or the listed users.
func recipients(any bool, uris []string) *profileRecipients {
	if any {
		return &profileRecipients{EntryInfo: "LocallyDetermined"}
	}
	return &profileRecipients{EntryInfo: "UsePreConfigured", URIs: uris}
}

// ------------------------------------------------------------------------------
// The <actions> children of the MCPTT user profile schema that TS 24.484 clause 8.3.2.1 item 11
// lists directly; the others of TS 24.484 clause 8.3.2.3 go in the <anyExt> of <actions>.
var release13Actions = map[string]bool{
	"allow-presence-status": true, "allow-request-presence": true, "allow-query-availability-for-private-calls": true,
	"allow-enable-disable-user": true, "allow-enable-disable-UE": true, "allow-create-delete-user-alias": true,
	"allow-private-call": true, "allow-manual-commencement": true, "allow-automatic-commencement": true,
	"allow-force-auto-answer": true, "allow-failure-restriction": true, "allow-emergency-group-call": true,
	"allow-emergency-private-call": true, "allow-cancel-group-emergency": true, "allow-cancel-private-emergency-call": true,
	"allow-imminent-peril-call": true, "allow-cancel-imminent-peril": true, "allow-activate-emergency-alert": true,
	"allow-cancel-emergency-alert": true, "allow-offnetwork": true, "allow-imminent-peril-change": true,
	"allow-private-call-media-protection": true, "allow-private-call-floor-control-protection": true,
	"allow-request-affiliated-groups": true, "allow-request-to-affiliate-other-users": true,
	"allow-recommend-to-affiliate-other-users": true, "allow-private-call-to-any-user": true, "allow-regroup": true,
	"allow-private-call-participation": true, "allow-override-of-transmission": true, "allow-manual-off-network-switch": true,
	"allow-listen-both-overriding-and-overridden": true, "allow-transmit-during-override": true,
	"allow-off-network-group-call-change-to-emergency": true, "allow-revoke-transmit": true,
	"allow-create-group-broadcast-group": true, "allow-create-user-broadcast-group": true,
}

// ------------------------------------------------------------------------------
// Helper: profileRight is a granted right: an element name in a namespace.
type profileRight struct{ space, name string }

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1 item 11: profileRights lists the rights a user's configuration grants, as elements of
// the MCPTT and MCData user profile schemas.
func profileRights(user User) []profileRight {
	var out []profileRight
	add := func(space string) func(bool, string) {
		return func(ok bool, name string) {
			if ok {
				out = append(out, profileRight{space, name})
			}
		}
	}
	mcptt := add(profileNS)
	// <allow-private-call-participation>: the user may be called, unless the configuration says it may not
	// (callable false); the servers apply the same default (TS 24.379 clause 11.1.1.3.2 step 8).
	mcptt(user.PrivateCall == nil || user.PrivateCall.Callable == nil || *user.PrivateCall.Callable,
		"allow-private-call-participation")
	if private := user.PrivateCall; private != nil {
		mcptt(private.Allow, "allow-private-call")
		mcptt(private.AutomaticCommencement, "allow-automatic-commencement")
		mcptt(private.ManualCommencement, "allow-manual-commencement")
		mcptt(private.ForceAutoAnswer, "allow-force-auto-answer")
		mcptt(private.FirstToAnswer, "allow-request-first-to-answer-call")
		mcptt(private.AnyTarget, "allow-private-call-to-any-user")
		mcptt(private.Emergency, "allow-emergency-private-call")
		mcptt(private.EmergencyCancel, "allow-cancel-private-emergency-call")
		mcptt(private.Callback, "allow-request-private-call-call-back")
		mcptt(private.CallbackCancel, "allow-cancel-private-call-call-back")
		mcptt(private.RemoteInit, "allow-request-remote-init-private-call")
		mcptt(private.Transfer, "allow-call-transfer")
		mcptt(private.ForwardManual, "allow-call-forward-manual-input")
		mcptt(private.IncomingAny, "allow-to-receive-private-call-from-any-user")
		mcptt(private.AmbientRemote, "allow-request-remote-initiated-ambient-listening")
		mcptt(private.AmbientLocal, "allow-request-locally-initiated-ambient-listening")
	}
	if adhoc := user.AdhocCall; adhoc != nil {
		mcptt(adhoc.Allow, "allow-adhoc-group-call")
		mcptt(adhoc.Participation, "allow-adhoc-group-call-participation")
		mcptt(adhoc.Emergency, "allow-emergency-adhoc-group-call")
		mcptt(adhoc.Imminent, "allow-imminent-peril-adhoc-group-call")
		mcptt(adhoc.Modify, "allow-to-modify-adhoc-group-call-participants-info")
		mcptt(adhoc.Alert, "allow-activate-adhoc-group-emergency-alert")
		mcptt(adhoc.AlertCancel, "allow-cancel-adhoc-group-emergency-alert")
	}
	if groupCall := user.GroupCall; groupCall != nil {
		mcptt(groupCall.RemoteInit, "allow-request-remote-init-group-call")
		mcptt(groupCall.Emergency, "allow-emergency-group-call")
		mcptt(groupCall.EmergencyCancel, "allow-cancel-group-emergency")
		mcptt(groupCall.Imminent, "allow-imminent-peril-call")
		mcptt(groupCall.ImminentCancel, "allow-cancel-imminent-peril")
	}
	// One element each for group and private emergency alerts (TS 24.379 clauses 6.3.3.1.13.1 and 6.3.3.1.13.3).
	alert, alertCancel := user.alertRights()
	mcptt(alert, "allow-activate-emergency-alert")
	mcptt(alertCancel, "allow-cancel-emergency-alert")
	mcptt(user.FunctionalAliasTakeover, "allow-takeover-functional-alias-other-user")
	mcptt(user.FunctionalAliasBinding, "allow-functional-alias-binding-with-group")
	if mcdataPolicy := user.MCData; mcdataPolicy != nil {
		mcdata := add(mcdataProfileNS)
		mcdata(mcdataPolicy.TransmitData, "allow-transmit-data")
		mcdata(mcdataPolicy.IncomingAny, "allow-one-to-one-communication-from-any-user")
		mcdata(mcdataPolicy.Adhoc, "allow-adhoc-group-data-comn")
		mcdata(mcdataPolicy.AdhocParticipation, "allow-adhoc-group-data-comn-participation")
		mcdata(mcdataPolicy.FunctionalAliasTakeover, "allow-takeover-functional-alias-other-user")
		mcdata(mcdataPolicy.EmergencyAlert, "allow-activate-emergency-alert")
		mcdata(mcdataPolicy.AlertCancel, "allow-cancel-emergency-alert")
		mcdata(mcdataPolicy.AlertCancelAnyUser, "allow-cancel-emergency-alert-any-user")
		mcdata(mcdataPolicy.EmergencyGroup, "allow-emergency-group-call")
		mcdata(mcdataPolicy.ImminentPeril, "allow-imminent-peril-call")
		mcdata(mcdataPolicy.ImminentPerilCancel, "allow-cancel-imminent-peril")
		// The MCData user profile schema has no group emergency cancellation right.
		add(profileExtensionNS)(mcdataPolicy.EmergencyGroupCancel, "allow-cancel-group-emergency")
	}
	return out
}

// ------------------------------------------------------------------------------
// Helper: the user's <allow-activate-emergency-alert> and <allow-cancel-emergency-alert>: granted by the private call
// or the group call policy.
func (user User) alertRights() (bool, bool) {
	alert, cancel := false, false
	if private := user.PrivateCall; private != nil {
		alert, cancel = private.Alert, private.AlertCancel
	}
	if groupCall := user.GroupCall; groupCall != nil {
		alert, cancel = alert || groupCall.Alert, cancel || groupCall.AlertCancel
	}
	return alert, cancel
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1 item 11: the <cp:ruleset> of a user's MCPTT user profile document.
func profileRulesetOf(user User) *profileRuleset {
	return rulesetOf(profileRights(user), profileNS, release13Actions)
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1 item 11: rulesetOf is the <cp:ruleset> of a profile document whose schema has the
// namespace space: its rights in one rule, those the schema lists directly in
// <actions> and the others in the <anyExt> of <actions>. Rights of other
// namespaces go directly in <actions>.
func rulesetOf(rights []profileRight, space string, direct map[string]bool) *profileRuleset {
	var items, extension []profileElement
	for _, right := range rights {
		element := profileElement{XMLName: xml.Name{Space: right.space, Local: right.name}, Text: "true"}
		if right.space == space && !direct[right.name] {
			extension = append(extension, element)
		} else {
			items = append(items, element)
		}
	}
	if len(extension) > 0 {
		items = append(items, profileElement{XMLName: xml.Name{Space: space, Local: "anyExt"}, Children: extension})
	}
	return &profileRuleset{Rules: []profileRule{{ID: "rights", Actions: profileElements{Items: items}}}}
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1 item 11: grantedRights reads the rights of a profile's ruleset: the elements of a
// namespace set to true, directly in <actions> or in its <anyExt>.
func (doc profileXML) grantedRights(space string) map[string]bool {
	return doc.Ruleset.granted(space, profileNS)
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1 item 11: granted reads the rights of a ruleset: the elements of a namespace set to true,
// directly in <actions> or in the <anyExt> of the profile schema's namespace extNS.
func (rs *profileRuleset) granted(space, extNS string) map[string]bool {
	out := map[string]bool{}
	if rs == nil {
		return out
	}
	var walk func([]profileElement)
	walk = func(items []profileElement) {
		for _, element := range items {
			if element.XMLName.Space == extNS && element.XMLName.Local == "anyExt" {
				walk(element.Children)
				continue
			}
			if value := strings.TrimSpace(element.Text); element.XMLName.Space == space && (value == "true" || value == "1") {
				out[element.XMLName.Local] = true
			}
		}
	}
	for _, rule := range rs.Rules {
		walk(rule.Actions.Items)
	}
	return out
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1: the MCPTT user profile document built from a user's configuration: identity, private
// call lists, groups, N2 limit, emergency recipients and granted rights.
func userProfileXML(user User) profileXML {
	doc := profileXML{XUIURI: user.MCPTTID, ProfileIndex: user.profileIndex(), Status: true,
		ProfileName: profileDocumentName(user.profileIndex()),
		Common: profileCommon{Index: "0", MCPTTUserID: profileEntry{URI: user.MCPTTID},
			GroupCall: profileGroupCall{MaxCallsN6: 1, Emergency: profileGroupInitiation{Entry: groupInitiationEntry("")},
				Imminent: profileGroupInitiation{Entry: groupInitiationEntry("")}, Alert: profileAlert{Entry: groupInitiationEntry("")}}},
		Ruleset:   profileRulesetOf(user),
		Extension: &profileExtension{MCID: user.MCID, SIPURI: user.SIPURI, ClientID: user.ClientID}}
	if groupCall := user.GroupCall; groupCall != nil {
		doc.Common.GroupCall.Emergency.Entry = groupInitiationEntry(groupCall.EmergencyGroup)
		doc.Common.GroupCall.Imminent.Entry = groupInitiationEntry(groupCall.ImminentGroup)
		doc.Common.GroupCall.Alert.Entry = groupInitiationEntry(groupCall.AlertGroup)
	}
	on := &profileOnNetwork{Index: "0", MaxAffiliationsN2: user.MaxAffiliations}
	if len(user.Groups) > 0 {
		on.GroupInfo = &profileEntryList{}
		for _, groupID := range user.Groups {
			on.GroupInfo.Entries = append(on.GroupInfo.Entries, profileEntry{URI: groupID})
		}
	}
	if private := user.PrivateCall; private != nil {
		doc.Common.PrivateCall = &profilePrivateCall{List: newPrivateCallList(private.Targets)}
		if len(private.IncomingFrom) > 0 {
			list := newPrivateCallList(private.IncomingFrom)
			on.AnyExt = &profileOnNetworkExt{IncomingList: &list}
		}
		if private.Emergency {
			doc.Extension.EmergencyRecipients = recipients(private.EmergencyAny, private.EmergencyRecipients)
			emergency := &profilePrivateEmergency{}
			emergency.Recipient.ProSe.UserInfoID = "000000000000"
			emergency.Recipient.Entry = profileEntry{EntryInfo: "LocallyDetermined"}
			if !private.EmergencyAny && len(private.EmergencyRecipients) == 1 {
				emergency.Recipient.Entry = profileEntry{EntryInfo: "UsePreConfigured", URI: private.EmergencyRecipients[0]}
			}
			doc.Common.PrivateCall.Emergency = emergency
		}
		if private.Alert {
			doc.Extension.AlertRecipients = recipients(private.AlertAny, private.AlertRecipients)
			// The schema's single recipient, when the configuration has exactly one.
			if !private.AlertAny && len(private.AlertRecipients) == 1 {
				on.EmergencyAlert = &profileAlert{Entry: profileEntry{EntryInfo: "UsePreConfigured", URI: private.AlertRecipients[0]}}
			}
		}
	}
	if on.GroupInfo != nil || on.MaxAffiliationsN2 > 0 || on.EmergencyAlert != nil || on.AnyExt != nil {
		doc.OnNetwork = on
	}
	return doc
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.8: profileDocumentName is the naming convention, the document name and <ProfileName>.
func profileDocumentName(index int) string {
	return "mcptt-user-profile-" + strconv.Itoa(index) + ".xml"
}

// ------------------------------------------------------------------------------
// Helper: mcpttID is the MCPTT ID a profile document is for.
func (doc profileXML) mcpttID() string {
	if doc.Common.MCPTTUserID.URI != "" {
		return doc.Common.MCPTTUserID.URI
	}
	return doc.XUIURI
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.6: profileConstraints are the validation constraints that the schema does not express,
// checked after it (RFC 4825 section 8.2.5). xui is the XUI of the document URI and name the document name the
// document is stored under, mcptt-user-profile-<profile-index>.xml (this CMS keeps one document per user, so
// <Pre-selected-indication> is optional, clause 8.3.2.6).
func profileConstraints(raw []byte, xui, name string) error {
	root, err := parseXMLTree(raw)
	if err != nil {
		return xcapFail(409, "not-well-formed", err.Error())
	}
	if value, _ := root.attr("XUI-URI"); value != xui {
		return constraintFailure("Wrong User Profile URI")
	}
	if index, _ := root.attr("user-profile-index"); name != "mcptt-user-profile-"+index+".xml" {
		return constraintFailure("The user profile document name does not comply with the format: 'mcptt-user-profile-<profile-index>.xml'")
	}
	var check func(node *xmlNode, parent string) error
	check = func(node *xmlNode, parent string) error {
		if node.Name.Space == profileNS {
			text := strings.TrimSpace(node.Text)
			switch {
			case node.Name.Local == "Priority" && parent == "MCPTT-group-call", node.Name.Local == "RelativePresentationPriority":
				if value, err := strconv.Atoi(strings.TrimPrefix(text, "+")); err != nil || value < 0 || value > 255 {
					return constraintFailure("Priority value out of range")
				}
			case node.Name.Local == "DiscoveryGroupID":
				if octets(text) != 3 {
					return constraintFailure("Invalid Discovery Group ID")
				}
			case node.Name.Local == "User-Info-ID":
				if octets(text) != 6 {
					return constraintFailure("Invalid User Info ID")
				}
			}
		}
		for _, childNode := range node.Children {
			if err := check(childNode, node.Name.Local); err != nil {
				return err
			}
		}
		return nil
	}
	return check(root, "")
}

// ------------------------------------------------------------------------------
// Helper: the number of octets of a hexadecimal text, or -1 when it is not hexadecimal.
func octets(hexText string) int {
	raw, err := hex.DecodeString(hexText)
	if err != nil {
		return -1
	}
	return len(raw)
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1 item 8: the user profile document the CMS serves, with the system's
// <MissionCriticalOrganization> (item 8g) and the <LocationUserProfileURI> of the user's location user configuration
// data document (clause 7.4.1.2).
func (svc *service) servedProfileXML(user User) profileXML {
	doc := userProfileXML(user)
	// Item 10 g ii: the functional aliases whose <mcptt-user-list> names the user (TS 24.379 clause 9A.2.2.2.3 step
	// 4A a).
	if aliases := svc.cfg.functionalAliasList(user.MCPTTID, func(alias FunctionalAlias) []string { return alias.Users }); aliases != nil {
		if doc.OnNetwork == nil {
			doc.OnNetwork = &profileOnNetwork{Index: "0"}
		}
		if doc.OnNetwork.AnyExt == nil {
			doc.OnNetwork.AnyExt = &profileOnNetworkExt{}
		}
		doc.OnNetwork.AnyExt.FunctionalAliasList = aliases
	}
	doc.Common.Organization = svc.cfg.organization()
	doc.Common.AnyExt = &locationURIExt{LocationURI: svc.locationDocumentURI(user.MCPTTID, user.profileIndex())}
	return doc
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.3 and clause 8.3.2.6: checkProfileDocuments validates the user profile documents the CMS
// generates from its configuration.
func (svc *service) checkProfileDocuments() error {
	for _, user := range svc.cfg.Users {
		raw, err := xml.Marshal(svc.servedProfileXML(user))
		if err == nil {
			err = schemaError(userProfileSchema.validate(raw))
		}
		if err == nil {
			err = profileConstraints(raw, user.MCPTTID, profileDocumentName(user.profileIndex()))
		}
		if err != nil {
			return fmt.Errorf("user profile document of %s: %w", user.MCPTTID, err)
		}
	}
	return nil
}
