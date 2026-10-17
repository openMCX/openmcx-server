//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The MCData user profile document the CMS serves: rendering a user's "mcdata" record as the document, and the
// validation constraints the schema does not express.
//
// Specifications: TS 24.484 V19.6.0 (Rel-19), TS 24.282 V19.6.0 (Rel-19), TS 23.282 V19.6.0 (Rel-19), RFC 4745.
package common

import (
	"cmp"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
)

// ------------------------------------------------------------------------------
// The MCData user profile document of TS 24.484 clause 10.3, which the CMS serves from a user's "mcdata" record. It
// conforms to the schema of TS 24.484 clause 10.3.2.3. The record maps to the schema's elements:
//
//   - the identity: the "XUI-URI" attribute and <Common>/<MCDataUserID>; <MissionCriticalOrganization>;
//   - the one-to-one targets: <Common>/<One-to-One-Communication>, each with the KMS in <MCData-ID-KMSURI>;
//   - <TxRxControl> with <MaxData1To1>; <GroupEmergencyAlert> from the alert groups;
//   - the groups of which the user is an MCData member: <OnNetwork>/<MCDataGroupInfo> with the GMS, the IdMS token
//     endpoint and the KMS; <MaxAffiliationsN2>, <ImplicitAffiliations>, <One-To-One-EmergencyAlert>;
//   - in the <anyExt> of <OnNetwork>: <MCDataContentServerURI>, <MessageStoreHostname> and
//     <IncomingOne-to-OneCommunicationList>;
//   - the granted rights: boolean elements of the <cp:ruleset> actions (clause 10.3.2.1 item 11 b).
//
// The MCPTT user profile keeps carrying the MCData rights in its ruleset as well, for the clients that read them
// there.
const (
	mcdataProfileMIME = "application/vnd.3gpp.mcdata-user-profile+xml"
	// <MaxTime1To1>: this system sets no time limit on a one-to-one communication; one day stands for none.
	mcdataMaxTime1To1 = "P1D"
	// <MaxData1To1> is a positiveInteger; the largest value stands for no limit (max_data_1to1 0).
	mcdataNoDataLimit = 4294967295
)

// ------------------------------------------------------------------------------
// TS 24.484 clause 10.3.2.1: the <mcdata-user-profile> root element.
type mcdataProfileXML struct {
	XMLName      xml.Name        `xml:"urn:3gpp:ns:mcdata:user-profile:1.0 mcdata-user-profile"`
	XUIURI       string          `xml:"XUI-URI,attr"`
	ProfileIndex int             `xml:"user-profile-index,attr"`
	Status       bool            `xml:"Status"`
	ProfileName  string          `xml:"ProfileName,omitempty"`
	Common       mcdataCommon    `xml:"Common"`
	OnNetwork    mcdataOnNetwork `xml:"OnNetwork"`
	Ruleset      *profileRuleset `xml:"urn:ietf:params:xml:ns:common-policy ruleset,omitempty"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 10.3.2.1 item 8: the <Common> element.
type mcdataCommon struct {
	Index        string            `xml:"index,attr"`
	UserAlias    struct{}          `xml:"UserAlias"`
	UserID       profileEntry      `xml:"MCDataUserID"`
	Organization string            `xml:"MissionCriticalOrganization"`
	FileDist     struct{}          `xml:"FileDistribution"`
	TxRx         mcdataTxRxControl `xml:"TxRxControl"`
	GroupAlert   profileAlert      `xml:"GroupEmergencyAlert"`
	OneToOne     *mcdataOneToOne   `xml:"One-to-One-Communication,omitempty"`
	AnyExt       *locationURIExt   `xml:"anyExt,omitempty"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 10.3.2.1 item 8 h: the <TxRxControl> element.
type mcdataTxRxControl struct {
	MaxData1To1 int64    `xml:"MaxData1To1"`
	MaxTime1To1 string   `xml:"MaxTime1To1"`
	Release     struct{} `xml:"TxReleaseList"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 10.3.2.3: the One-to-One-CommunicationType, the list of <One-to-One-CommunicationListEntry>.
type mcdataOneToOne struct {
	Entries []mcdataOneToOneEntry `xml:"One-to-One-CommunicationListEntry"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 10.3.2.1 item 8 j i: one <One-to-One-CommunicationListEntry>: the MCData ID and its KMS.
type mcdataOneToOneEntry struct {
	ID  profileEntry `xml:"MCData-ID"`
	KMS profileEntry `xml:"MCData-ID-KMSURI"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 10.3.2.1 item 9: the <OnNetwork> element.
type mcdataOnNetwork struct {
	Index                string             `xml:"index,attr"`
	GroupInfo            []mcdataGroupInfo  `xml:"MCDataGroupInfo"`
	MaxAffiliationsN2    int                `xml:"MaxAffiliationsN2,omitempty"`
	ImplicitAffiliations *profileEntryList  `xml:"ImplicitAffiliations,omitempty"`
	OneToOneAlert        profileAlert       `xml:"One-To-One-EmergencyAlert"`
	AnyExt               mcdataOnNetworkExt `xml:"anyExt"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 10.3.2.1 item 9 b: one <MCDataGroupInfo> element.
type mcdataGroupInfo struct {
	GroupID  profileEntry        `xml:"MCData-Group-ID"`
	GMS      profileEntry        `xml:"GMS-App-Serv-Id"`
	Token    profileEntry        `xml:"IdMS-Token-Endpoint"`
	KMS      profileEntry        `xml:"GroupKMSURI"`
	Priority int                 `xml:"RelativePresentationPriority"`
	AnyExt   *mcdataGroupInfoExt `xml:"anyExt,omitempty"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 10.3.2.1 item 9 b vi: the <anyExt> of <MCDataGroupInfo>.
type mcdataGroupInfoExt struct {
	Store bool `xml:"allow-store-group-comm-in-msgstore"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 10.3.2.1 item 9 i: the <anyExt> of <OnNetwork>.
type mcdataOnNetworkExt struct {
	ContentServer string          `xml:"MCDataContentServerURI"`
	MessageStore  string          `xml:"MessageStoreHostname"`
	IncomingList  *mcdataOneToOne `xml:"IncomingOne-to-OneCommunicationList,omitempty"`
	// <FunctionalAliasList>: the functional aliases the user may activate (TS 24.484 clause 10.3.2.1, TS 24.282
	// clause 22.2.1.2).
	FunctionalAliasList *profileEntryList `xml:"FunctionalAliasList,omitempty"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1 item 8 i, clause 9.3.2.1 and clause 10.3.2.1 item 8 k: the <anyExt> of <Common> with the
// <LocationUserProfileURI> (clause 7.4.1.2).
type locationURIExt struct {
	LocationURI string `xml:"LocationUserProfileURI"`
}

// ------------------------------------------------------------------------------
// The <actions> children that TS 24.484 clause 10.3.2.1 item 11 b lists directly; the others go in the <anyExt> of
// <actions>.
var mcdataDirectActions = map[string]bool{
	"allow-create-delete-user-alias": true, "allow-create-group-broadcast-group": true,
	"allow-create-user-broadcast-group": true, "allow-transmit-data": true, "allow-request-affiliated-groups": true,
	"allow-request-to-affiliate-other-users": true, "allow-recommend-to-affiliate-other-users": true,
	"allow-regroup": true, "allow-presence-status": true, "allow-request-presence": true,
	"allow-activate-emergency-alert": true, "allow-cancel-emergency-alert": true,
	"allow-cancel-emergency-alert-any-user": true, "allow-enable-disable-user": true, "allow-enable-disable-UE": true,
	"allow-off-network-manual-switch": true, "allow-off-network": true, "allow-store-comms-in-msgstore": true,
	"allow-store-private-comms-in-msgstore": true,
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 10.3.2.1 item 11 b: mcdataProfileRights lists the MCData rights of a user's record as elements of
// the MCData user profile schema.
func mcdataProfileRights(user User) []profileRight {
	var out []profileRight
	policy := user.MCData
	if policy == nil {
		return out
	}
	add := func(ok bool, name string) {
		if ok {
			out = append(out, profileRight{mcdataProfileNS, name})
		}
	}
	add(policy.TransmitData, "allow-transmit-data")
	add(user.Regroup, "allow-regroup")
	add(policy.EmergencyAlert, "allow-activate-emergency-alert")
	add(policy.AlertCancel, "allow-cancel-emergency-alert")
	add(policy.AlertCancelAnyUser, "allow-cancel-emergency-alert-any-user")
	add(policy.StoreComms, "allow-store-comms-in-msgstore")
	add(policy.StorePrivateComms, "allow-store-private-comms-in-msgstore")
	add(policy.FunctionalAliasTakeover, "allow-takeover-functional-alias-other-user")
	add(policy.IncomingAny, "allow-one-to-one-communication-from-any-user")
	add(policy.EmergencyGroup, "allow-emergency-group-call")
	add(policy.ImminentPeril, "allow-imminent-peril-call")
	add(policy.ImminentPerilCancel, "allow-cancel-imminent-peril")
	add(policy.EmergencyPrivate, "allow-emergency-private-call")
	add(policy.EmergencyPrivateCancel, "allow-cancel-private-emergency-call")
	add(policy.Adhoc, "allow-adhoc-group-data-comn")
	add(policy.AdhocParticipation, "allow-adhoc-group-data-comn-participation")
	return out
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 10.3.2.1: the MCData user profile document of a user.
func (svc *service) mcdataProfileXML(user User) mcdataProfileXML {
	policy := user.MCData
	if policy == nil {
		policy = &MCDataPolicy{}
	}
	kms := profileEntry{URI: svc.cfg.Endpoints.KMS}
	doc := mcdataProfileXML{XUIURI: user.MCDataID, ProfileIndex: user.profileIndex(), Status: true,
		ProfileName: mcdataProfileDocumentName(user.profileIndex()),
		Common: mcdataCommon{Index: "0", UserID: profileEntry{URI: user.MCDataID}, Organization: cmp.Or(policy.Organization, svc.cfg.organization()),
			TxRx:       mcdataTxRxControl{MaxData1To1: mcdataNoDataLimit, MaxTime1To1: mcdataMaxTime1To1},
			GroupAlert: profileAlert{Entry: groupInitiationEntry("")},
			AnyExt:     &locationURIExt{LocationURI: svc.locationDocumentURI(user.MCDataID, user.profileIndex())}},
		OnNetwork: mcdataOnNetwork{Index: "0", MaxAffiliationsN2: user.MaxAffiliations,
			OneToOneAlert: profileAlert{Entry: profileEntry{EntryInfo: "LocallyDetermined"}},
			AnyExt:        mcdataOnNetworkExt{ContentServer: svc.cfg.Endpoints.Content, MessageStore: hostOf(svc.cfg.Endpoints.MsgStore)}},
		Ruleset: rulesetOf(mcdataProfileRights(user), mcdataProfileNS, mcdataDirectActions)}
	// The functional aliases whose <mcdata-user-list> names the user (TS 24.282 clause 22.2.2.3.3 step 4a).
	doc.OnNetwork.AnyExt.FunctionalAliasList = svc.cfg.functionalAliasList(user.MCDataID,
		func(alias FunctionalAlias) []string { return alias.MCDataUsers })
	if policy.MaxData1To1 > 0 {
		doc.Common.TxRx.MaxData1To1 = int64(policy.MaxData1To1)
	}
	if len(policy.AlertGroups) > 0 {
		doc.Common.GroupAlert.Entry = groupInitiationEntry(policy.AlertGroups[0])
	}
	oneToOne := func(ids []string) *mcdataOneToOne {
		list := &mcdataOneToOne{}
		for _, id := range ids {
			list.Entries = append(list.Entries, mcdataOneToOneEntry{ID: profileEntry{URI: id}, KMS: kms})
		}
		return list
	}
	if len(policy.Targets) > 0 {
		doc.Common.OneToOne = oneToOne(policy.Targets)
	}
	if len(policy.IncomingFrom) > 0 {
		doc.OnNetwork.AnyExt.IncomingList = oneToOne(policy.IncomingFrom)
	}
	if len(policy.ImplicitAffiliations) > 0 {
		doc.OnNetwork.ImplicitAffiliations = &profileEntryList{}
		for _, id := range policy.ImplicitAffiliations {
			doc.OnNetwork.ImplicitAffiliations.Entries = append(doc.OnNetwork.ImplicitAffiliations.Entries, profileEntry{URI: id})
		}
	}
	// The groups of which the user is an MCData member: MCX Admin names them in admin mode, groups[] in file mode.
	groups := user.MCDataGroups
	if svc.cfg.AdminAccounts == nil {
		for _, group := range svc.cfg.Groups {
			if group.MCData != nil && slices.Contains(group.MCData.Members, user.MCDataID) {
				groups = append(groups, group.ID)
			}
		}
	}
	for _, id := range groups {
		info := mcdataGroupInfo{GroupID: profileEntry{URI: id}, GMS: profileEntry{URI: svc.cfg.Endpoints.GMS},
			Token: profileEntry{URI: svc.cfg.Issuer + "/token"}, KMS: kms}
		if slices.Contains(policy.StoreGroupComms, id) {
			info.AnyExt = &mcdataGroupInfoExt{Store: true}
		}
		doc.OnNetwork.GroupInfo = append(doc.OnNetwork.GroupInfo, info)
	}
	return doc
}

// ------------------------------------------------------------------------------
// Helper: the host name of a URL (<MessageStoreHostname>); the text itself when it is not a URL.
func hostOf(raw string) string {
	if parsed, err := url.Parse(raw); err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	return raw
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 10.3.2.8: mcdataProfileDocumentName is the naming convention.
func mcdataProfileDocumentName(index int) string {
	return "mcdata-user-profile-" + strconv.Itoa(index) + ".xml"
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 10.3.2.6: mcdataProfileConstraints are the validation constraints the schema does not express:
// the XUI of the document URI and the document name, and the maximum of simultaneous service authorizations
// (authorizationLimitConstraint).
func mcdataProfileConstraints(raw []byte, xui, name string) error {
	root, err := parseXMLTree(raw)
	if err != nil {
		return xcapFail(409, "not-well-formed", err.Error())
	}
	if value, _ := root.attr("XUI-URI"); value != xui {
		return constraintFailure("Wrong User Profile URI")
	}
	index, _ := root.attr("user-profile-index")
	if name != "mcdata-user-profile-"+index+".xml" {
		return constraintFailure("The user profile document name does not comply with the format: 'mcdata-user-profile-<profile-index>.xml'")
	}
	return authorizationLimitConstraint(root)
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 6.3.3.3: mcdataProfileDocument is the MCData user profile document of a user, by MCData ID, and its
// profile index.
func (svc *service) mcdataProfileDocument(id string) ([]byte, int, int) {
	user, ok := svc.siteUser("mcdata_id", id)
	if !ok || user.MCDataID == "" {
		return nil, 0, http.StatusNotFound
	}
	// With the rights of an uploaded MCPTT user profile document (TS 24.484 clause 6.3.4.3).
	doc := svc.mcdataProfileXML(svc.effectiveUser(user))
	raw, err := xml.Marshal(doc)
	if err != nil {
		return nil, 0, http.StatusInternalServerError
	}
	return append([]byte(xml.Header), raw...), doc.ProfileIndex, http.StatusOK
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 10.3.1 and clause 6.3.3.3: getMCDataProfile: the MCData client reads its user profile at
// CMSXCAPROOTURI/org.3gpp.mcdata.user-profile/users/sip:MCDATAID/mcdata-user-profile-INDEX.xml.
func (svc *service) getMCDataProfile(writer http.ResponseWriter, request *http.Request) {
	claims, ok := svc.authenticateBearer(writer, request)
	if !ok {
		return
	}
	id := request.PathValue("mcdataID")
	if id != claims.MCDataID && !svc.configManager(claims.MCPTTID) {
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	raw, index, status := svc.mcdataProfileDocument(id)
	if status == http.StatusOK && request.PathValue("document") != mcdataProfileDocumentName(index) {
		status = http.StatusNotFound
	}
	if status != http.StatusOK {
		writeJSON(writer, status, map[string]string{"error": http.StatusText(status)})
		return
	}
	writeDocument(writer, request, raw, mcdataProfileMIME)
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 10.3.2.3 and clause 10.3.2.6: checkMCDataProfileDocuments validates the MCData user profile
// documents the CMS generates from its configuration.
func (svc *service) checkMCDataProfileDocuments() error {
	for _, user := range svc.cfg.Users {
		if user.MCDataID == "" {
			continue
		}
		raw, err := xml.Marshal(svc.mcdataProfileXML(user))
		if err == nil {
			err = schemaError(mcdataProfileSchema.validate(raw))
		}
		if err == nil {
			err = mcdataProfileConstraints(raw, user.MCDataID, mcdataProfileDocumentName(user.profileIndex()))
		}
		if err != nil {
			return fmt.Errorf("MCData user profile document of %s: %w", user.MCDataID, err)
		}
	}
	return nil
}
