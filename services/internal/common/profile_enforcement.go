//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The MCPTT user profile document an authorised CMC has uploaded (TS 24.484 clause 6.3.4.3) is the user's profile:
// the CMS serves it, and the MC service servers apply the rights it grants. This file reads such a document back
// into the user record the servers enforce.
//
// Specifications: TS 24.484 V19.6.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.6.0 (Rel-19), RFC 4745.
package common

import (
	"encoding/xml"
	"slices"
)

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1: applyProfile returns the user with the parts the MCPTT user profile document governs
// replaced by what doc says: the private call, ad hoc and group call rights and lists, the emergency entries, the
// groups (<MCPTTGroupInfo>), <MaxAffiliationsN2>, the functional alias rights and the MCData rights of the ruleset.
// An element absent from the document grants nothing (TS 24.379: absent or "false" is not authorised). The parts
// the document has no element for (call forwarding targets and timer, the MCVideo and location records) stay as
// configured.
func applyProfile(user User, doc profileXML) User {
	rights := doc.grantedRights(profileNS)
	own := doc.Ruleset.granted(profileExtensionNS, profileNS)
	data := doc.grantedRights(mcdataProfileNS)

	private := &PrivateCallPolicy{}
	if user.PrivateCall != nil {
		// Kept: what the document cannot express.
		private.ForwardImmediate = user.PrivateCall.ForwardImmediate
		private.ForwardNoAnswer = user.PrivateCall.ForwardNoAnswer
		private.NoAnswerTimeout = user.PrivateCall.NoAnswerTimeout
	}
	private.Allow = rights["allow-private-call"]
	private.AutomaticCommencement = rights["allow-automatic-commencement"]
	private.ManualCommencement = rights["allow-manual-commencement"]
	private.ForceAutoAnswer = rights["allow-force-auto-answer"]
	private.FirstToAnswer = rights["allow-request-first-to-answer-call"]
	private.AnyTarget = rights["allow-private-call-to-any-user"]
	private.Emergency = rights["allow-emergency-private-call"]
	private.EmergencyCancel = rights["allow-cancel-private-emergency-call"]
	private.Callback = rights["allow-request-private-call-call-back"]
	private.CallbackCancel = rights["allow-cancel-private-call-call-back"]
	private.RemoteInit = rights["allow-request-remote-init-private-call"]
	private.Transfer = rights["allow-call-transfer"]
	private.ForwardManual = rights["allow-call-forward-manual-input"]
	private.IncomingAny = rights["allow-to-receive-private-call-from-any-user"]
	private.AmbientRemote = rights["allow-request-remote-initiated-ambient-listening"]
	private.AmbientLocal = rights["allow-request-locally-initiated-ambient-listening"]
	callable := rights["allow-private-call-participation"]
	private.Callable = &callable
	if call := doc.Common.PrivateCall; call != nil {
		private.Targets = call.List.uris()
		if emergency := call.Emergency; emergency != nil {
			entry := emergency.Recipient.Entry
			private.EmergencyAny = entry.EntryInfo == "LocallyDetermined"
			if entry.EntryInfo == "UsePreConfigured" && entry.URI != "" {
				private.EmergencyRecipients = []string{entry.URI}
			}
		}
	}
	// One <allow-activate-emergency-alert> and <allow-cancel-emergency-alert> for private and group alerts
	// (TS 24.379 clauses 6.3.3.1.13.1 and 6.3.3.1.13.3).
	private.Alert = rights["allow-activate-emergency-alert"]
	private.AlertCancel = rights["allow-cancel-emergency-alert"]
	if on := doc.OnNetwork; on != nil {
		if on.AnyExt != nil {
			private.IncomingFrom = on.AnyExt.IncomingList.uris()
		}
		if alert := on.EmergencyAlert; alert != nil && alert.Entry.URI != "" {
			private.AlertRecipients = []string{alert.Entry.URI}
		}
	}
	// This implementation's extension: several recipients, where the schema has one.
	if ext := doc.Extension; ext != nil {
		if rc := ext.EmergencyRecipients; rc != nil {
			private.EmergencyAny = rc.EntryInfo == "LocallyDetermined"
			private.EmergencyRecipients = slices.Clone(rc.URIs)
		}
		if rc := ext.AlertRecipients; rc != nil {
			private.AlertAny = rc.EntryInfo == "LocallyDetermined"
			private.AlertRecipients = slices.Clone(rc.URIs)
		}
	}
	user.PrivateCall = private

	user.AdhocCall = &AdhocCallPolicy{Allow: rights["allow-adhoc-group-call"],
		Participation: rights["allow-adhoc-group-call-participation"], Emergency: rights["allow-emergency-adhoc-group-call"],
		Imminent: rights["allow-imminent-peril-adhoc-group-call"], Modify: rights["allow-to-modify-adhoc-group-call-participants-info"],
		Alert: rights["allow-activate-adhoc-group-emergency-alert"], AlertCancel: rights["allow-cancel-adhoc-group-emergency-alert"]}

	dedicated := func(entry profileEntry) string {
		if entry.EntryInfo == "DedicatedGroup" {
			return entry.URI
		}
		return ""
	}
	groupCall := doc.Common.GroupCall
	user.GroupCall = &GroupCallPolicy{RemoteInit: rights["allow-request-remote-init-group-call"],
		Emergency: rights["allow-emergency-group-call"], EmergencyGroup: dedicated(groupCall.Emergency.Entry),
		EmergencyCancel: rights["allow-cancel-group-emergency"],
		Imminent:        rights["allow-imminent-peril-call"], ImminentGroup: dedicated(groupCall.Imminent.Entry),
		ImminentCancel: rights["allow-cancel-imminent-peril"],
		Alert:          rights["allow-activate-emergency-alert"], AlertGroup: dedicated(groupCall.Alert.Entry),
		AlertCancel: rights["allow-cancel-emergency-alert"]}

	user.FunctionalAliasTakeover = rights["allow-takeover-functional-alias-other-user"]
	user.FunctionalAliasBinding = rights["allow-functional-alias-binding-with-group"]
	user.Groups, user.MaxAffiliations = nil, 0
	if on := doc.OnNetwork; on != nil {
		user.MaxAffiliations = on.MaxAffiliationsN2
		if on.GroupInfo != nil {
			for _, entry := range on.GroupInfo.Entries {
				user.Groups = append(user.Groups, entry.URI)
			}
		}
	}

	// The MCData rights the profile carries in its ruleset (TS 24.484 clause 10.3.2.1 item 11 b); the MCData lists
	// and limits are not in this document and stay as configured.
	if user.MCDataID != "" {
		policy := MCDataPolicy{}
		if user.MCData != nil {
			policy = *user.MCData
		}
		policy.TransmitData = data["allow-transmit-data"]
		policy.IncomingAny = data["allow-one-to-one-communication-from-any-user"]
		policy.Adhoc = data["allow-adhoc-group-data-comn"]
		policy.AdhocParticipation = data["allow-adhoc-group-data-comn-participation"]
		policy.FunctionalAliasTakeover = data["allow-takeover-functional-alias-other-user"]
		policy.EmergencyAlert = data["allow-activate-emergency-alert"]
		policy.AlertCancel = data["allow-cancel-emergency-alert"]
		policy.AlertCancelAnyUser = data["allow-cancel-emergency-alert-any-user"]
		policy.EmergencyGroup = data["allow-emergency-group-call"]
		policy.ImminentPeril = data["allow-imminent-peril-call"]
		policy.ImminentPerilCancel = data["allow-cancel-imminent-peril"]
		policy.EmergencyGroupCancel = own["allow-cancel-group-emergency"]
		user.MCData = &policy
	}
	return user
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 6.3.4.3: uploadedProfile is the MCPTT user profile document an authorised CMC stored for the
// user, while it is the latest change of the user's profile: a change of the user's configuration made afterwards
// (MCX Admin, the configuration file) updates the profile again, and the stored document is then dropped.
func (svc *service) uploadedProfile(user User) ([]byte, bool) {
	generated, err := xml.Marshal(svc.servedProfileXML(user))
	if err != nil {
		return nil, false
	}
	current := documentETag(append([]byte(xml.Header), generated...))
	svc.mu.Lock()
	defer svc.mu.Unlock()
	stored, ok := svc.profileDocs[user.MCPTTID]
	if !ok {
		return nil, false
	}
	if base, known := svc.profileBases[user.MCPTTID]; known && base != current {
		delete(svc.profileDocs, user.MCPTTID)
		delete(svc.profileBases, user.MCPTTID)
		if err := svc.saveProfileDocumentsLocked(); err != nil {
			svc.logEvent("user_profile_save_failed", map[string]any{"user_id": user.MCPTTID, "error": err.Error()})
		}
		svc.logEvent("user_profile_superseded", map[string]any{"user_id": user.MCPTTID})
		return nil, false
	}
	return stored, true
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 6.3.4.3: effectiveUser is the user as the servers enforce it: with the rights of an uploaded MCPTT
// user profile document, when there is one.
func (svc *service) effectiveUser(user User) User {
	raw, ok := svc.uploadedProfile(user)
	if !ok {
		return user
	}
	var doc profileXML
	if err := xml.Unmarshal(raw, &doc); err != nil {
		svc.logEvent("user_profile_unreadable", map[string]any{"user_id": user.MCPTTID, "error": err.Error()})
		return user
	}
	return applyProfile(user, doc)
}
