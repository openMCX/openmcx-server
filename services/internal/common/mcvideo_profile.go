// The MCVideo user profile document the CMS serves: rendering a user's "mcvideo" record as the document, reading
// it back, and the validation constraints the schema does not express.
//
// Specifications: TS 24.484 V19.6.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19),
// TS 23.280 V19.10.1 (Rel-19), TS 33.180 V19.4.0 (Rel-19), RFC 4745.
package common

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// ------------------------------------------------------------------------------
// The MCVideo user profile document of TS 24.484 clause 9.3, which the CMS
// serves from a user's "mcvideo" record (TS 24.281 uses it as TS 24.379 uses the
// MCPTT profile). It conforms to the schema of TS 24.484 clause 9.3.2.3. The record maps to the
// schema's elements where the schema has one:
//
//   - the identity: the "XUI-URI" attribute and <Common>/<MCVideoUserID>;
//   - the private call targets: <Common>/<PrivateCall>/<PrivateCallList>, each
//     <PrivateCallOnNetwork> with the target's KMS in <PrivateCallKMSURI>;
//   - the groups of which the user is an MCVideo member: <OnNetwork>/<MCVideoGroupInfo>;
//     the N2 limit: <MaxAffiliationsN2>; <RemoteGroupSelectionURIList>;
//   - <IncomingPrivateCallList> in the <anyExt> of <OnNetwork> (TS 24.484 clause 9.3.2.1 item 9 h);
//   - the granted rights: boolean elements of the <cp:ruleset> actions, the ones
//     TS 24.484 clause 9.3.2.1 item 11 b lists directly and the later ones in its <anyExt>.
//
// What the schema cannot express goes in this implementation's namespace, as for
// the MCPTT profile: the emergency private call recipients (the schema's single
// <MCVideoPrivateRecipient> requires a ProSe user entry), a user who cannot be
// called, and the rights of TS 24.281 that TS 24.484 has no element for (starting
// a remote transmission, video push to and pull from the server).
const (
	mcvideoProfileNS   = "urn:3gpp:ns:mcvideo:user-profile:1.0"
	mcvideoProfileMIME = "application/vnd.3gpp.mcvideo-user-profile+xml"
)

// ------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.1: the <mcvideo-user-profile> root element.
type mcvideoProfileXML struct {
	XMLName      xml.Name                 `xml:"urn:3gpp:ns:mcvideo:user-profile:1.0 mcvideo-user-profile"`
	XUIURI       string                   `xml:"XUI-URI,attr"`
	ProfileIndex int                      `xml:"user-profile-index,attr"`
	Status       bool                     `xml:"Status"`
	ProfileName  string                   `xml:"ProfileName,omitempty"`
	Common       mcvideoCommon            `xml:"Common"`
	OnNetwork    *mcvideoOnNetwork        `xml:"OnNetwork,omitempty"`
	Ruleset      *profileRuleset          `xml:"urn:ietf:params:xml:ns:common-policy ruleset,omitempty"`
	Extension    *mcvideoProfileExtension `xml:"urn:openmcx:ns:userProfile:1.0 mcvideo-profile-extension,omitempty"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.1 item 8: the <Common> element.
type mcvideoCommon struct {
	Index       string              `xml:"index,attr"`
	UserID      profileEntry        `xml:"MCVideoUserID"`
	PrivateCall *mcvideoPrivateCall `xml:"PrivateCall,omitempty"`
	GroupCall   mcvideoGroupCall    `xml:"MCVideo-group-call"`
	AnyExt      *locationURIExt     `xml:"anyExt,omitempty"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.1 item 8 e: the <MCVideo-group-call> element of <Common>, as <MCPTT-group-call>
// (TS 24.281 clause 6.3.3.1.13 reads its group entries).
type mcvideoGroupCall struct {
	MaxCallsN6 int                    `xml:"MaxSimultaneousCallsN6"`
	Emergency  mcvideoGroupInitiation `xml:"EmergencyCall"`
	Imminent   mcvideoGroupInitiation `xml:"ImminentPerilCall"`
	Alert      profileAlert           `xml:"EmergencyAlert"`
	Priority   int                    `xml:"Priority"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.3: <MCVideoGroupInitiation> with its <entry>.
type mcvideoGroupInitiation struct {
	Entry profileEntry `xml:"MCVideoGroupInitiation>entry"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.1 item 8 d: the <PrivateCall> element of <Common>.
type mcvideoPrivateCall struct {
	List mcvideoPrivateCallList `xml:"PrivateCallList"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.1 item 8 d: the <PrivateCallList> of on-network private call targets.
type mcvideoPrivateCallList struct {
	OnNetwork []mcvideoPrivateCallEntry `xml:"PrivateCallOnNetwork"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.3: mcvideoPrivateCallEntry is the PrivateCallOnNetworkType.
type mcvideoPrivateCallEntry struct {
	URI profileEntry `xml:"PrivateCallURI"`
	KMS struct {
		Entry profileEntry `xml:"PrivateCallKMSURI"`
	} `xml:"PrivateCallKMSURI"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.1 item 9: the <OnNetwork> element.
type mcvideoOnNetwork struct {
	Index             string                  `xml:"index,attr"`
	GroupInfo         []mcvideoGroupInfo      `xml:"MCVideoGroupInfo"`
	MaxAffiliationsN2 int                     `xml:"MaxAffiliationsN2,omitempty"`
	RemoteSelection   *profileEntryList       `xml:"RemoteGroupSelectionURIList,omitempty"`
	AnyExt            *mcvideoOnNetworkExtXML `xml:"anyExt,omitempty"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.1 item 9 b: one <MCVideoGroupInfo> element.
type mcvideoGroupInfo struct {
	GroupID profileEntry `xml:"MCVideo-Group-ID"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.1 item 9 h: the <anyExt> of <OnNetwork>.
type mcvideoOnNetworkExtXML struct {
	IncomingList *privateCallList `xml:"IncomingPrivateCallList,omitempty"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.1 (project extension): the element of this implementation's own namespace.
type mcvideoProfileExtension struct {
	EmergencyRecipients *profileRecipients `xml:"emergency-private-call-recipients,omitempty"`
	NotCallable         bool               `xml:"not-callable,omitempty"`
}

// ------------------------------------------------------------------------------
// Helper: mcvideoRights is the part of a user's "mcvideo" record the profile document
// carries, under the keys the MCVideo server reads.
type mcvideoRights struct {
	PrivateCall              *PrivateCallPolicy `json:"private_call,omitempty"`
	GroupCall                *GroupCallPolicy   `json:"group_call,omitempty"`
	AdhocCall                *AdhocCallPolicy   `json:"adhoc_call,omitempty"`
	Regroup                  bool               `json:"regroup,omitempty"`
	RemoteGroupSelection     []string           `json:"remote_group_selection,omitempty"`
	FunctionalAliasTakeover  bool               `json:"functional_alias_takeover,omitempty"`
	FunctionalAliasBinding   bool               `json:"functional_alias_binding,omitempty"`
	AllowRemoteTransmit      bool               `json:"allow_remote_transmit,omitempty"`
	AllowRevokeTransmit      bool               `json:"allow_revoke_transmit,omitempty"`
	AllowVideoPushToServer   bool               `json:"allow_video_push_to_server,omitempty"`
	AllowVideoPullFromServer bool               `json:"allow_video_pull_from_server,omitempty"`
	MaxAffiliations          int                `json:"max_affiliations,omitempty"`
}

// ------------------------------------------------------------------------------
// Helper: the MCVideo rights of a user's "mcvideo" record.
func mcvideoRightsOf(user User) (mcvideoRights, error) {
	var rights mcvideoRights
	if user.MCVideo == nil {
		return rights, nil
	}
	raw, err := json.Marshal(user.MCVideo)
	if err == nil {
		err = json.Unmarshal(raw, &rights)
	}
	return rights, err
}

// ------------------------------------------------------------------------------
// The <actions> children that TS 24.484 clause 9.3.2.1 item 11 b lists directly; the others go in
// the <anyExt> of <actions>.
var mcvideoDirectActions = map[string]bool{
	"allow-private-call": true, "allow-manual-commencement": true, "allow-automatic-commencement": true,
	"allow-force-auto-answer": true, "allow-emergency-private-call": true, "allow-cancel-private-emergency-call": true,
	"allow-private-call-to-any-user": true, "allow-regroup": true, "allow-revoke-transmit": true,
	"allow-emergency-group-call": true, "allow-cancel-group-emergency": true, "allow-imminent-peril-call": true,
	"allow-cancel-imminent-peril": true, "allow-activate-emergency-alert": true, "allow-cancel-emergency-alert": true,
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.1 item 11 b: mcvideoProfileRights lists the rights of a record as elements of the MCVideo user
// profile schema, or of this implementation's namespace where it has none.
func mcvideoProfileRights(rights mcvideoRights) []profileRight {
	var out []profileRight
	add := func(space string) func(bool, string) {
		return func(ok bool, name string) {
			if ok {
				out = append(out, profileRight{space, name})
			}
		}
	}
	video, own := add(mcvideoProfileNS), add(profileExtensionNS)
	if private := rights.PrivateCall; private != nil {
		video(private.Allow, "allow-private-call")
		video(private.AutomaticCommencement, "allow-automatic-commencement")
		video(private.ManualCommencement, "allow-manual-commencement")
		video(private.ForceAutoAnswer, "allow-force-auto-answer")
		video(private.AnyTarget, "allow-private-call-to-any-user")
		video(private.Emergency, "allow-emergency-private-call")
		video(private.EmergencyCancel, "allow-cancel-private-emergency-call")
		video(private.IncomingAny, "allow-to-receive-private-call-from-any-user")
		video(private.AmbientRemote, "allow-request-remote-initiated-ambient-viewing")
		video(private.AmbientLocal, "allow-request-locally-initiated-ambient-viewing")
	}
	alert, alertCancel := false, false
	if private := rights.PrivateCall; private != nil {
		alert, alertCancel = private.Alert, private.AlertCancel
	}
	if groupCall := rights.GroupCall; groupCall != nil {
		video(groupCall.Emergency, "allow-emergency-group-call")
		video(groupCall.EmergencyCancel, "allow-cancel-group-emergency")
		video(groupCall.Imminent, "allow-imminent-peril-call")
		video(groupCall.ImminentCancel, "allow-cancel-imminent-peril")
		alert, alertCancel = alert || groupCall.Alert, alertCancel || groupCall.AlertCancel
	}
	// One element each for group and private emergency alerts (TS 24.281 clause 6.3.3.1.13).
	video(alert, "allow-activate-emergency-alert")
	video(alertCancel, "allow-cancel-emergency-alert")
	if adhoc := rights.AdhocCall; adhoc != nil {
		video(adhoc.Allow, "allow-adhoc-group-call")
		video(adhoc.Participation, "allow-adhoc-group-call-participation")
		video(adhoc.Emergency, "allow-emergency-adhoc-group-call")
		video(adhoc.Imminent, "allow-imminent-peril-adhoc-group-call")
		video(adhoc.Modify, "allow-to-modify-adhoc-group-call-participants-info")
		video(adhoc.Alert, "allow-activate-adhoc-group-emergency-alert")
		video(adhoc.AlertCancel, "allow-cancel-adhoc-group-emergency-alert")
	}
	video(rights.Regroup, "allow-regroup")
	video(rights.AllowRevokeTransmit, "allow-revoke-transmit")
	video(rights.FunctionalAliasTakeover, "allow-takeover-functional-alias-other-user")
	video(rights.FunctionalAliasBinding, "allow-functional-alias-binding-with-group")
	own(rights.AllowRemoteTransmit, "allow-remote-transmit")
	own(rights.AllowVideoPushToServer, "allow-video-push-to-server")
	own(rights.AllowVideoPullFromServer, "allow-video-pull-from-server")
	return out
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.1: the MCVideo user profile document of a user: identity, private call targets with their
// KMS, groups, N2 limit, remote group selection, emergency recipients and granted rights.
func (svc *service) mcvideoProfileXML(user User) (mcvideoProfileXML, error) {
	rights, err := mcvideoRightsOf(user)
	if err != nil {
		return mcvideoProfileXML{}, err
	}
	doc := mcvideoProfileXML{XUIURI: user.MCVideoID, ProfileIndex: user.profileIndex(), Status: true,
		ProfileName: mcvideoProfileDocumentName(user.profileIndex()),
		Common: mcvideoCommon{Index: "0", UserID: profileEntry{URI: user.MCVideoID},
			GroupCall: mcvideoGroupCall{MaxCallsN6: 1, Emergency: mcvideoGroupInitiation{Entry: groupInitiationEntry("")},
				Imminent: mcvideoGroupInitiation{Entry: groupInitiationEntry("")}, Alert: profileAlert{Entry: groupInitiationEntry("")}}},
		Ruleset: rulesetOf(mcvideoProfileRights(rights), mcvideoProfileNS, mcvideoDirectActions)}
	if groupCall := rights.GroupCall; groupCall != nil {
		doc.Common.GroupCall.Emergency.Entry = groupInitiationEntry(groupCall.EmergencyGroup)
		doc.Common.GroupCall.Imminent.Entry = groupInitiationEntry(groupCall.ImminentGroup)
		doc.Common.GroupCall.Alert.Entry = groupInitiationEntry(groupCall.AlertGroup)
	}
	doc.Common.AnyExt = &locationURIExt{LocationURI: svc.locationDocumentURI(user.MCVideoID, user.profileIndex())}
	ext := &mcvideoProfileExtension{}
	on := &mcvideoOnNetwork{Index: "0", MaxAffiliationsN2: rights.MaxAffiliations}
	if svc.cfg.AdminAccounts != nil {
		// Admin mode: MCX Admin, which writes the GMS's groups, names them (slice D4).
		for _, id := range user.MCVideoGroups {
			on.GroupInfo = append(on.GroupInfo, mcvideoGroupInfo{GroupID: profileEntry{URI: id}})
		}
	} else {
		for _, group := range svc.cfg.Groups {
			if group.MCVideo != nil && slices.Contains(group.MCVideo.Members, user.MCVideoID) {
				on.GroupInfo = append(on.GroupInfo, mcvideoGroupInfo{GroupID: profileEntry{URI: group.ID}})
			}
		}
	}
	if len(rights.RemoteGroupSelection) > 0 {
		on.RemoteSelection = &profileEntryList{}
		for _, id := range rights.RemoteGroupSelection {
			on.RemoteSelection.Entries = append(on.RemoteSelection.Entries, profileEntry{URI: id})
		}
	}
	if private := rights.PrivateCall; private != nil {
		call := &mcvideoPrivateCall{}
		for _, target := range private.Targets {
			entry := mcvideoPrivateCallEntry{URI: profileEntry{URI: target}}
			entry.KMS.Entry = profileEntry{URI: svc.cfg.Endpoints.KMS}
			call.List.OnNetwork = append(call.List.OnNetwork, entry)
		}
		doc.Common.PrivateCall = call
		if len(private.IncomingFrom) > 0 {
			list := newPrivateCallList(private.IncomingFrom)
			on.AnyExt = &mcvideoOnNetworkExtXML{IncomingList: &list}
		}
		if private.Emergency {
			ext.EmergencyRecipients = recipients(private.EmergencyAny, private.EmergencyRecipients)
		}
		ext.NotCallable = private.Callable != nil && !*private.Callable
	}
	if len(on.GroupInfo) > 0 || on.MaxAffiliationsN2 > 0 || on.RemoteSelection != nil || on.AnyExt != nil {
		doc.OnNetwork = on
	}
	if ext.EmergencyRecipients != nil || ext.NotCallable {
		doc.Extension = ext
	}
	return doc, nil
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.8: mcvideoProfileDocumentName is the naming convention.
func mcvideoProfileDocumentName(index int) string {
	return "mcvideo-user-profile-" + strconv.Itoa(index) + ".xml"
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.1: rights reads a profile document back into a record: the inverse of mcvideoProfileXML.
func (doc mcvideoProfileXML) rights() mcvideoRights {
	var rights mcvideoRights
	private := func() *PrivateCallPolicy {
		if rights.PrivateCall == nil {
			rights.PrivateCall = &PrivateCallPolicy{}
		}
		return rights.PrivateCall
	}
	adhoc := func() *AdhocCallPolicy {
		if rights.AdhocCall == nil {
			rights.AdhocCall = &AdhocCallPolicy{}
		}
		return rights.AdhocCall
	}
	setters := map[string]func(){
		"allow-private-call":                                 func() { private().Allow = true },
		"allow-automatic-commencement":                       func() { private().AutomaticCommencement = true },
		"allow-manual-commencement":                          func() { private().ManualCommencement = true },
		"allow-force-auto-answer":                            func() { private().ForceAutoAnswer = true },
		"allow-private-call-to-any-user":                     func() { private().AnyTarget = true },
		"allow-emergency-private-call":                       func() { private().Emergency = true },
		"allow-cancel-private-emergency-call":                func() { private().EmergencyCancel = true },
		"allow-to-receive-private-call-from-any-user":        func() { private().IncomingAny = true },
		"allow-request-remote-initiated-ambient-viewing":     func() { private().AmbientRemote = true },
		"allow-request-locally-initiated-ambient-viewing":    func() { private().AmbientLocal = true },
		"allow-adhoc-group-call":                             func() { adhoc().Allow = true },
		"allow-emergency-adhoc-group-call":                   func() { adhoc().Emergency = true },
		"allow-imminent-peril-adhoc-group-call":              func() { adhoc().Imminent = true },
		"allow-to-modify-adhoc-group-call-participants-info": func() { adhoc().Modify = true },
		"allow-activate-adhoc-group-emergency-alert":         func() { adhoc().Alert = true },
		"allow-cancel-adhoc-group-emergency-alert":           func() { adhoc().AlertCancel = true },
		"allow-regroup":                                      func() { rights.Regroup = true },
		"allow-revoke-transmit":                              func() { rights.AllowRevokeTransmit = true },
		"allow-takeover-functional-alias-other-user":         func() { rights.FunctionalAliasTakeover = true },
		"allow-functional-alias-binding-with-group":          func() { rights.FunctionalAliasBinding = true },
	}
	own := map[string]func(){
		"allow-remote-transmit":        func() { rights.AllowRemoteTransmit = true },
		"allow-video-push-to-server":   func() { rights.AllowVideoPushToServer = true },
		"allow-video-pull-from-server": func() { rights.AllowVideoPullFromServer = true },
	}
	for name := range doc.Ruleset.granted(mcvideoProfileNS, mcvideoProfileNS) {
		if set, ok := setters[name]; ok {
			set()
		}
	}
	for name := range doc.Ruleset.granted(profileExtensionNS, mcvideoProfileNS) {
		if set, ok := own[name]; ok {
			set()
		}
	}
	if call := doc.Common.PrivateCall; call != nil {
		for _, entry := range call.List.OnNetwork {
			private().Targets = append(private().Targets, entry.URI.URI)
		}
	}
	if on := doc.OnNetwork; on != nil {
		rights.MaxAffiliations = on.MaxAffiliationsN2
		if on.RemoteSelection != nil {
			for _, entry := range on.RemoteSelection.Entries {
				rights.RemoteGroupSelection = append(rights.RemoteGroupSelection, entry.URI)
			}
		}
		if on.AnyExt != nil && on.AnyExt.IncomingList != nil {
			private().IncomingFrom = on.AnyExt.IncomingList.uris()
		}
	}
	if ext := doc.Extension; ext != nil {
		if rc := ext.EmergencyRecipients; rc != nil {
			if rc.EntryInfo == "LocallyDetermined" {
				private().EmergencyAny = true
			} else {
				private().EmergencyRecipients = rc.URIs
			}
		}
		if ext.NotCallable {
			no := false
			private().Callable = &no
		}
	}
	return rights
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.6: mcvideoProfileConstraints are the validation constraints
// that the schema does not express. xui is the XUI of the document URI, and name
// its document name.
func mcvideoProfileConstraints(raw []byte, xui, name string) error {
	root, err := parseXMLTree(raw)
	if err != nil {
		return xcapFail(409, "not-well-formed", err.Error())
	}
	if value, _ := root.attr("XUI-URI"); value != xui {
		return constraintFailure("Wrong User Profile URI")
	}
	index, _ := root.attr("user-profile-index")
	if name != "mcvideo-user-profile-"+index+".xml" {
		return constraintFailure("The user profile document name does not comply with the format: 'mcvideo-user-profile-<profile-index>.xml'")
	}
	var check func(node *xmlNode) error
	check = func(node *xmlNode) error {
		if node.Name.Space == mcvideoProfileNS {
			text := strings.TrimSpace(node.Text)
			switch node.Name.Local {
			case "RelativePresentationPriority":
				if value, err := strconv.Atoi(strings.TrimPrefix(text, "+")); err != nil || value < 0 || value > 255 {
					return constraintFailure("Priority value out of range")
				}
			case "User-Info-ID":
				if octets(text) != 6 {
					return constraintFailure("Invalid User Info ID")
				}
			}
		}
		for _, childNode := range node.Children {
			if err := check(childNode); err != nil {
				return err
			}
		}
		return nil
	}
	return check(root)
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 6.3.3.3: mcvideoProfileDocument is the MCVideo user profile document of a user, by MCVideo
// ID, and its profile index.
func (svc *service) mcvideoProfileDocument(id string) ([]byte, int, int) {
	user, ok := svc.siteUser("mcvideo_id", id)
	if !ok {
		return nil, 0, http.StatusNotFound
	}
	doc, err := svc.mcvideoProfileXML(user)
	if err != nil {
		return nil, 0, http.StatusInternalServerError
	}
	raw, err := xml.Marshal(doc)
	if err != nil {
		return nil, 0, http.StatusInternalServerError
	}
	return append([]byte(xml.Header), raw...), doc.ProfileIndex, http.StatusOK
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 9.3.1A and clause 6.3.3.3: getMCVideoProfile: the MCVideo client reads its user profile at
// CMSXCAPROOTURI/org.3gpp.mcvideo.user-profile/users/sip:MCVIDEOID/mcvideo-user-profile-INDEX.xml.
func (svc *service) getMCVideoProfile(writer http.ResponseWriter, request *http.Request) {
	claims, ok := svc.authenticateBearer(writer, request)
	if !ok {
		return
	}
	id := request.PathValue("mcvideoID")
	if id != claims.MCVideoID && !svc.configManager(claims.MCPTTID) {
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	raw, index, status := svc.mcvideoProfileDocument(id)
	if status == http.StatusOK && request.PathValue("document") != mcvideoProfileDocumentName(index) {
		status = http.StatusNotFound
	}
	if status != http.StatusOK {
		writeJSON(writer, status, map[string]string{"error": http.StatusText(status)})
		return
	}
	writeDocument(writer, request, raw, mcvideoProfileMIME)
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.3 and clause 9.3.2.6: checkMCVideoProfileDocuments validates the MCVideo user profile
// documents the CMS generates from its configuration.
func (svc *service) checkMCVideoProfileDocuments() error {
	for _, user := range svc.cfg.Users {
		if user.MCVideoID == "" {
			continue
		}
		doc, err := svc.mcvideoProfileXML(user)
		var raw []byte
		if err == nil {
			raw, err = xml.Marshal(doc)
		}
		if err == nil {
			err = schemaError(mcvideoProfileSchema.validate(raw))
		}
		if err == nil {
			err = mcvideoProfileConstraints(raw, user.MCVideoID, mcvideoProfileDocumentName(user.profileIndex()))
		}
		if err != nil {
			return fmt.Errorf("MCVideo user profile document of %s: %w", user.MCVideoID, err)
		}
	}
	return nil
}
