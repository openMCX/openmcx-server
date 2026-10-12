//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The common services' configuration (site.json): the service roles, the users and groups with the subsets of their
// user profile and group documents the servers use, the endpoints, and the validation of it all.
//
// Specifications: TS 24.484 V19.6.0 (Rel-19), TS 24.481 V19.3.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19),
// TS 24.282 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 23.280 V19.10.1 (Rel-19), TS 23.282 V19.10.0 (Rel-19),
// TS 23.281 V19.10.0 (Rel-19), TS 23.379 V19.11.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19), TS 24.545, RFC 6749.
package common

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"slices"
	"strings"
)

type Role string

const (
	RoleIDMS Role = "idms"
	RoleGMS  Role = "gms"
	RoleCMS  Role = "cms"
	RoleLMS  Role = "lms"
	RoleKMS  Role = "kms"
	// The MCData content server with the media storage function (TS 23.282 clause 6.6.3).
	RoleContent Role = "content"
	// The MCData message store function (TS 24.282 clause 21, MCData-7 and MCData-8)
	// and the MCData notification server (MCData-10 and MCData-11).
	RoleMsgStore     Role = "msgstore"
	RoleNotification Role = "notification"
	// The Credential Service of MCX Admin's managed accounts (credentials.go).
	RoleCredentials Role = "credentials"
)

type SecurityConfig struct {
	KeyParameterProfile map[string]uint8 `json:"key_parameter_profile,omitempty"`
}

type Config struct {
	Security SecurityConfig `json:"security,omitempty"`
	// LogLevel is "info" (the default) or "debug": the HTTP request log (request_log.go); MCX_LOG overrides it.
	LogLevel          string   `json:"log_level,omitempty"`
	Domain            string   `json:"domain"`
	ServiceURI        string   `json:"service_uri"`
	Issuer            string   `json:"issuer"`
	OAuthClientID     string   `json:"oauth_client_id"`
	OAuthRedirectURIs []string `json:"oauth_redirect_uris"`
	ServerClientID    string   `json:"server_client_id"`
	ServerSecret      string   `json:"server_secret"`
	GMSKeyClientID    string   `json:"gms_key_client_id"`
	GMSKeySecret      string   `json:"gms_key_secret"`
	TokenTTLSeconds   int      `json:"token_ttl_seconds"`
	// RefreshTokenTTLSeconds: a refresh token not used for this long lapses (default 7 days).
	RefreshTokenTTLSeconds int     `json:"refresh_token_ttl_seconds,omitempty"`
	Users                  []User  `json:"users"`
	Groups                 []Group `json:"groups"`
	// Functional aliases managed by the CMS (TS 23.280 clause 7.4.2.2.13; TS 24.379 clause 9A).
	FunctionalAliases []FunctionalAlias   `json:"functional_aliases,omitempty"`
	Endpoints         Endpoints           `json:"endpoints"`
	MCDataService     MCDataServiceConfig `json:"mcdata_service,omitempty"`
	// The service configuration documents of the organisation (TS 24.484 clauses 8.4, 9.4 and 10.4).
	ServiceConfig ServiceConfiguration `json:"service_config,omitempty"`
	// The public service identity of the MCVideo server, which the KMS provisions for
	// the CSKs of MCVideo transmission control (TS 33.180 clause 9.4, TS 24.281 clause 4.7).
	MCVideoService MCVideoServiceConfig `json:"mcvideo_service,omitempty"`
	// Accounts managed by MCX Admin (idms_accounts.go); nil keeps IdMS on this file.
	AdminAccounts *AdminAccountsConfig `json:"admin_accounts,omitempty"`
	// The Credential Service's database (credentials.go); only its role reads it.
	Credentials *CredentialsConfig `json:"credentials,omitempty"`
	// The SEAL location management server of the LMS role (TS 24.545); nil without one.
	SealLM *SealLMConfig `json:"seal_lm,omitempty"`
	// The mission critical organisation of this system: <MissionCriticalOrganization> of every user profile (TS 24.484
	// clauses 8.3.2.1, 9.3.2.1 and 10.3.2.1) and <mc-org> of emergency alerts (TS 24.379 clause 6.3.3.1.12); the
	// domain when not set. An MCData user's own organization (MCDataPolicy) takes precedence for MCData.
	Organization string `json:"organization,omitempty"`
}

// FunctionalAlias is the subset of the functional alias configuration used by the
// MCPTT server owning it: <mcptt-user-list>, <max-simultaneous-activations> and
// whether take-over is allowed (<allow-takeover>).
type FunctionalAlias struct {
	ID    string   `json:"id"`
	Users []string `json:"users"`
	// <mcdata-user-list>: MCData IDs allowed to activate the alias (TS 24.282 clause 22.2.2.3.3 step 4a).
	MCDataUsers []string `json:"mcdata_users,omitempty"`
	// <mcvideo-user-list>: MCVideo IDs allowed to activate the alias (TS 24.484 clause 9.4.2,
	// TS 24.281 clause 20.2.2.3.3).
	MCVideoUsers               []string `json:"mcvideo_users,omitempty"`
	MaxSimultaneousActivations int      `json:"max_simultaneous_activations"`
	AllowTakeover              bool     `json:"allow_takeover,omitempty"`
}

type User struct {
	Username    string   `json:"username"`
	Password    string   `json:"password,omitempty"`
	MCID        string   `json:"mc_id"`
	MCPTTID     string   `json:"mcptt_id"`
	SIPURI      string   `json:"sip_uri"`
	SIPPassword string   `json:"sip_password,omitempty"`
	ClientID    string   `json:"client_id"`
	Groups      []string `json:"groups"`
	// Private-call subset of the TS 24.484 user-profile ruleset; nil denies private calls.
	PrivateCall *PrivateCallPolicy `json:"private_call,omitempty"`
	// Ad hoc group call subset of the ruleset (<allow-adhoc-group-call>); nil denies.
	AdhocCall *AdhocCallPolicy `json:"adhoc_call,omitempty"`
	// Group-call subset of the ruleset (<allow-request-remote-init-group-call>); nil denies.
	GroupCall *GroupCallPolicy `json:"group_call,omitempty"`
	// <allow-takeover-functional-alias-other-user>.
	FunctionalAliasTakeover bool `json:"functional_alias_takeover,omitempty"`
	// <allow-functional-alias-binding-with-group> (TS 24.484 clause 8.3.2.7, TS 24.379 clause 9A.4).
	FunctionalAliasBinding bool `json:"functional_alias_binding,omitempty"`
	// <allow-regroup>: create and remove a regroup using a preconfigured group
	// (TS 24.379 clause 16.2.2.2 step 3, warnings 160 and 161).
	Regroup bool `json:"regroup,omitempty"`
	// <MaxAffiliationsN2>: simultaneous group affiliations; 0 means no limit.
	MaxAffiliations int `json:"max_affiliations,omitempty"`
	// MCData ID (TS 23.280 clause 8.1.2): a distinct identity; empty when the user has no
	// MCData service. MCData is the MCData user-profile ruleset subset.
	MCDataID string        `json:"mcdata_id,omitempty"`
	MCData   *MCDataPolicy `json:"mcdata,omitempty"`
	// MCVideo ID (TS 23.280 clause 8.1.2, TS 24.281 clause 4.2): a distinct identity; empty when
	// the user has no MCVideo service.
	MCVideoID string `json:"mcvideo_id,omitempty"`
	// The groups whose MCVideo members name this user, as MCX Admin gives them in admin
	// mode (slice D4); in file mode they come from groups[] and this is empty.
	MCVideoGroups []string `json:"mcvideo_groups,omitempty"`
	// The groups whose MCData members name this user, as MCX Admin gives them in admin mode; in file mode they come
	// from groups[] and this is empty.
	MCDataGroups []string `json:"mcdata_groups,omitempty"`
	// The MCVideo user profile's rulesets (TS 24.484), in the form of the MCPTT ones
	// (private_call, adhoc_call, ...) and naming MCVideo IDs; the MCVideo server
	// reads them in place of the MCPTT rulesets.
	MCVideo map[string]any `json:"mcvideo,omitempty"`
	// Location user profile (TS 23.280 annex A.8, clause 10.9): the rights the participating
	// functions check and this user's location reporting configuration.
	Location *LocationPolicy `json:"location,omitempty"`
	// Group management rights (TS 24.481 clause 6.3.2.3 step b and clause 7.2.12 "subject to MCS
	// service provider policy"): creating groups in the user's own tree, and managing
	// the listed groups ("*" for all).
	GroupManagement *GroupManagementPolicy `json:"group_management,omitempty"`
	// An MC service administrator's right to update other users' configuration
	// management documents (TS 24.484 clause 6.3.4, "authorized" by local policy).
	ConfigManagement bool `json:"config_management,omitempty"`
	// "user-profile-index" of the user's profile (TS 24.484 clause 8.3.2.1); 1 when absent.
	ProfileIndex int `json:"profile_index,omitempty"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1: the "user-profile-index" of the user's profile, 1 when absent.
func (user User) profileIndex() int {
	if user.ProfileIndex == 0 {
		return 1
	}
	return user.ProfileIndex
}

type GroupManagementPolicy struct {
	Create bool `json:"create,omitempty"`
	// Temporary: the user may form and tear down temporary MCS groups (TS 24.481 clause 6.3.14.3.1 step b).
	Temporary bool     `json:"temporary,omitempty"`
	Manage    []string `json:"manage,omitempty"`
}

// LocationPolicy: whether the user may request others' location (TS 24.379
// clause 13.2.3.2 step 5) or change their reporting (clause 13.2.2A step 5), may report its
// own (clause 13.2.4.1, true when absent), whom it shares its location with ("*" for
// any authorised requester; any when absent), and its reporting configuration
// (the servers' JSON form of the annex F.3 <Configuration>).
type LocationPolicy struct {
	Request       bool            `json:"request,omitempty"`
	Configure     bool            `json:"configure,omitempty"`
	Report        *bool           `json:"report,omitempty"`
	ShareWith     []string        `json:"share_with,omitempty"`
	Configuration json.RawMessage `json:"configuration,omitempty"`
}

// MCDataPolicy mirrors the MCData user-profile elements used by TS 24.282
// clauses 11.1 and 9.2.2.3: <allow-transmit-data>, the <One-to-One-Communication>
// target list, <IncomingOne-to-OneCommunicationList> with
// <allow-one-to-one-communication-from-any-user>, and <MaxData1To1> (bytes, 0 = no limit).
type MCDataPolicy struct {
	TransmitData bool     `json:"transmit_data"`
	Targets      []string `json:"targets,omitempty"`
	IncomingFrom []string `json:"incoming_from,omitempty"`
	IncomingAny  bool     `json:"incoming_any,omitempty"`
	MaxData1To1  int      `json:"max_data_1to1,omitempty"`
	// <allow-takeover-functional-alias-other-user> in the MCData user profile.
	FunctionalAliasTakeover bool `json:"functional_alias_takeover,omitempty"`
	// Emergency alert (TS 24.282 clauses 6.3.7.2.1, 6.3.7.2.2 and 16.2.1.2): <allow-activate-emergency-alert>;
	// <EmergencyAlert> "DedicatedGroup" entries (empty = "UseCurrentlySelectedGroup");
	// <allow-cancel-emergency-alert> and <allow-cancel-emergency-alert-any-user>;
	// and <MissionCriticalOrganization> sent as <mc-org>.
	EmergencyAlert     bool     `json:"emergency_alert,omitempty"`
	AlertGroups        []string `json:"alert_groups,omitempty"`
	AlertCancel        bool     `json:"alert_cancel,omitempty"`
	AlertCancelAnyUser bool     `json:"alert_cancel_any_user,omitempty"`
	Organization       string   `json:"organization,omitempty"`
	// Ad hoc group data communication (TS 24.282 clause 24):
	// <allow-adhoc-group-data-comn> and <allow-adhoc-group-data-comn-participation>.
	Adhoc              bool `json:"adhoc,omitempty"`
	AdhocParticipation bool `json:"adhoc_participation,omitempty"`
	// <ImplicitAffiliations> in <OnNetwork> (TS 24.282 clause 8.3.2.15): groups the user is
	// affiliated to after service authorisation.
	ImplicitAffiliations []string `json:"implicit_affiliations,omitempty"`
	// Authorised to release another user's file distribution (TS 24.282 clause 13.2.5).
	ReleaseAnyUser bool `json:"release_any_user,omitempty"`
	// <allow-emergency-private-call> and <allow-cancel-private-emergency-call> for an
	// emergency one-to-one communication on the media plane (TS 24.282 clause 6.2.8.3.1).
	EmergencyPrivate       bool `json:"emergency_private,omitempty"`
	EmergencyPrivateCancel bool `json:"emergency_private_cancel,omitempty"`
	// Priority group communications on a group SDS session (TS 24.282 clause 6.2.8.1.8,
	// clauses 6.3.7.2.3 to 6.3.7.2.6): <allow-emergency-group-call>, <allow-cancel-group-emergency>,
	// <allow-imminent-peril-call> and <allow-cancel-imminent-peril>.
	EmergencyGroup       bool `json:"emergency_group,omitempty"`
	EmergencyGroupCancel bool `json:"emergency_group_cancel,omitempty"`
	ImminentPeril        bool `json:"imminent_peril,omitempty"`
	ImminentPerilCancel  bool `json:"imminent_peril_cancel,omitempty"`
	// Storage of communications in the message store (TS 24.282 clause 21.3):
	// <allow-store-comms-in-msgstore>, <allow-store-private-comms-in-msgstore>, and
	// the groups whose <MCDataGroupInfo> carries <allow-store-group-comm-in-msgstore>.
	StoreComms        bool     `json:"store_comms,omitempty"`
	StorePrivateComms bool     `json:"store_private_comms,omitempty"`
	StoreGroupComms   []string `json:"store_group_comms,omitempty"`
}

// GroupMCData mirrors the MCData group-document membership and elements of TS 24.282
// clause 9.2.2.4.2 step 6 and clause 11.1: <supported-services> naming the SDS enabler,
// <mcdata-allow-short-data-service>, the <mcdata-allow-transmit-data-in-this-group> action (TransmitAll: for every
// member; TransmitMembers: for the members listed; neither: no member may transmit, TS 24.481 clause 7.2.4.2),
// <mcdata-on-network-max-data-size-for-SDS> and
// <mcdata-max-data-in-single-request> (bytes, 0 = no limit).
type GroupMCData struct {
	// <mcdata-mcdata-id> entries of the group list (MCData IDs).
	Members         []string `json:"members"`
	SDSSupported    bool     `json:"sds_supported"`
	AllowSDS        bool     `json:"allow_sds"`
	TransmitMembers []string `json:"transmit_members,omitempty"`
	TransmitAll     bool     `json:"transmit_all,omitempty"`
	MaxSDSBytes     int      `json:"max_sds_bytes,omitempty"`
	MaxRequestBytes int      `json:"max_request_bytes,omitempty"`
	// <mcdata-allow-emergency-alert> (TS 24.282 clause 6.3.7.2.1).
	AllowEmergencyAlert bool `json:"allow_emergency_alert,omitempty"`
	// <allow-MCData-emergency-call> and <allow-imminent-peril-call> of the group
	// document (TS 24.282 clauses 6.3.7.2.6 and 6.3.7.2.4).
	AllowEmergencyCall bool `json:"allow_emergency_call,omitempty"`
	AllowImminentPeril bool `json:"allow_imminent_peril,omitempty"`
	// File distribution (TS 24.282 clause 10.2.1.3.4 step 4): <mcdata-allow-file-distribution>,
	// the FD enabler in <supported-services> and
	// <mcdata-on-network-max-data-size-for-FD>.
	AllowFD     bool `json:"allow_fd,omitempty"`
	FDSupported bool `json:"fd_supported,omitempty"`
	MaxFDBytes  int  `json:"max_fd_bytes,omitempty"`
	// <mcdata-on-network-max-data-size-auto-recv>: a group file up to this size is a mandatory download
	// (TS 24.282 clause 11.2).
	MaxAutoRecvBytes int `json:"max_auto_recv_bytes,omitempty"`
	// Enhanced status (TS 24.282 clause 14.2.1): <mcdata-allow-enhanced-status> and the
	// operational values of <mcdata-enhanced-status-operational-values>, each named
	// by its "id" attribute.
	AllowEnhancedStatus  bool                  `json:"allow_enhanced_status,omitempty"`
	EnhancedStatusValues []EnhancedStatusValue `json:"enhanced_status_values,omitempty"`
}

// EnhancedStatusValue is one operational value of a group's enhanced status.
type EnhancedStatusValue struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

// GroupCallPolicy carries the group-call rights of the user profile (TS 24.484 clause 8.3.2.1, TS 24.379 clauses
// 6.3.3.1.13 and 10.1.5). The emergency, imminent peril and emergency alert rights are the user's; the group document
// must also allow them (Group.AllowEmergencyCall, ...). EmergencyGroup, ImminentGroup and AlertGroup are the
// <entry> of <MCPTT-group-call>'s <EmergencyCall>/<MCPTTGroupInitiation>, <ImminentPerilCall>/<MCPTTGroupInitiation>
// and <EmergencyAlert>: a group names a dedicated group ("DedicatedGroup"), empty the group the user has selected
// ("UseCurrentlySelectedGroup").
type GroupCallPolicy struct {
	RemoteInit      bool   `json:"remote_init,omitempty"`      // <allow-request-remote-init-group-call>
	Emergency       bool   `json:"emergency,omitempty"`        // <allow-emergency-group-call>
	EmergencyGroup  string `json:"emergency_group,omitempty"`  // <EmergencyCall>/<MCPTTGroupInitiation>
	EmergencyCancel bool   `json:"emergency_cancel,omitempty"` // <allow-cancel-group-emergency>
	Imminent        bool   `json:"imminent,omitempty"`         // <allow-imminent-peril-call>
	ImminentGroup   string `json:"imminent_group,omitempty"`   // <ImminentPerilCall>/<MCPTTGroupInitiation>
	ImminentCancel  bool   `json:"imminent_cancel,omitempty"`  // <allow-cancel-imminent-peril>
	// <allow-activate-emergency-alert> and <allow-cancel-emergency-alert>: one right each in the profile for group
	// and private alerts; PrivateCall.Alert and PrivateCall.AlertCancel grant the same elements.
	Alert       bool   `json:"alert,omitempty"`
	AlertGroup  string `json:"alert_group,omitempty"` // <MCPTT-group-call>/<EmergencyAlert>
	AlertCancel bool   `json:"alert_cancel,omitempty"`
}

// AdhocCallPolicy mirrors <allow-adhoc-group-call> (TS 24.379 clause 17.3.2.1.1 step 9),
// <allow-emergency-adhoc-group-call> and <allow-imminent-peril-adhoc-group-call>
// (clauses 6.3.3.1.13.11 and 6.3.3.1.13.12).
type AdhocCallPolicy struct {
	Allow bool `json:"allow"`
	// <allow-adhoc-group-call-participation>: invited to an ad hoc group call, the user may take part (TS 24.379
	// clause 17.4.2.2.1 step 6: absent or false, the invitation is refused with warning 188).
	Participation bool `json:"participation,omitempty"`
	Emergency     bool `json:"emergency,omitempty"`
	Imminent      bool `json:"imminent,omitempty"`
	Modify        bool `json:"modify,omitempty"` // <allow-to-modify-adhoc-group-call-participants-info>
	// <allow-activate-adhoc-group-emergency-alert> and its cancellation counterpart (clause 12.1A).
	Alert       bool `json:"alert,omitempty"`
	AlertCancel bool `json:"alert_cancel,omitempty"`
}

// PrivateCallPolicy mirrors <allow-private-call>, <allow-automatic-commencement>,
// <allow-manual-commencement>, <allow-force-auto-answer> and the <PrivateCall> target list.
// FirstToAnswer mirrors <allow-request-first-to-answer-call>. Callable and the
// <IncomingPrivateCallList> fields govern the terminating side
// (TS 24.379 clause 11.1.1.3.2 steps 8 and 9); a nil Callable leaves the user callable.
type PrivateCallPolicy struct {
	Allow                 bool     `json:"allow"`
	AutomaticCommencement bool     `json:"automatic_commencement"`
	ManualCommencement    bool     `json:"manual_commencement"`
	ForceAutoAnswer       bool     `json:"force_auto_answer"`
	Targets               []string `json:"targets,omitempty"`
	AnyTarget             bool     `json:"any_target"`
	FirstToAnswer         bool     `json:"first_to_answer,omitempty"` // <allow-request-first-to-answer-call>
	Callable              *bool    `json:"callable,omitempty"`
	IncomingFrom          []string `json:"incoming_from,omitempty"`
	IncomingAny           bool     `json:"incoming_any,omitempty"`
	// Emergency private calls (TS 24.379 clause 6.3.3.1.13): <allow-emergency-private-call>
	// with <MCPTTPrivateRecipient> entries or "LocallyDetermined" (EmergencyAny),
	// <allow-cancel-private-emergency-call>, and the <allow-activate-emergency-alert>,
	// <PrivateEmergencyAlert> and <allow-cancel-emergency-alert> equivalents.
	Emergency           bool     `json:"emergency,omitempty"`
	EmergencyRecipients []string `json:"emergency_recipients,omitempty"`
	EmergencyAny        bool     `json:"emergency_any,omitempty"`
	EmergencyCancel     bool     `json:"emergency_cancel,omitempty"`
	Alert               bool     `json:"alert,omitempty"`
	AlertRecipients     []string `json:"alert_recipients,omitempty"`
	AlertAny            bool     `json:"alert_any,omitempty"`
	AlertCancel         bool     `json:"alert_cancel,omitempty"`
	// Private call services (TS 24.379 clauses 11.1.5 to 11.1.9): <allow-request-private-call-call-back>,
	// <allow-cancel-private-call-call-back>, <allow-request-remote-init-private-call>,
	// <allow-call-transfer>, <allow-call-fwd-manual-any>, an immediate forwarding target, and
	// a no-answer forwarding target with its <call-forwarding-no-answer-timeout> (TNP1,
	// TS 24.379 clause 6.3.2.5; 20 s by default).
	Callback         bool   `json:"callback,omitempty"`
	CallbackCancel   bool   `json:"callback_cancel,omitempty"`
	RemoteInit       bool   `json:"remote_init,omitempty"`
	Transfer         bool   `json:"transfer,omitempty"`
	ForwardManual    bool   `json:"forward_manual,omitempty"`
	ForwardImmediate string `json:"forward_immediate,omitempty"`
	ForwardNoAnswer  string `json:"forward_no_answer,omitempty"`
	NoAnswerTimeout  uint   `json:"forward_no_answer_timeout_ms,omitempty"`
	// Ambient listening calls (TS 24.379 clause 11.1.6): <allow-request-remote-initiated-ambient-listening>
	// (listen to another user) and <allow-request-locally-initiated-ambient-listening>
	// (be listened to by another user).
	AmbientRemote bool `json:"ambient_remote,omitempty"`
	AmbientLocal  bool `json:"ambient_local,omitempty"`
}

type Group struct {
	ID string `json:"id"`
	// "prearranged" (default), "chat" (TS 24.379 clause 10.1.2), or a broadcast hierarchy
	// from TS 23.379 clause 10.6.2.5: "group-broadcast" (SubordinateGroups) or
	// "user-broadcast" (Members), which carry broadcast group calls only.
	Type              string   `json:"type,omitempty"`
	SubordinateGroups []string `json:"subordinate_groups,omitempty"`
	// <preconfigured-group-use-only> (warning 167), a regrouped marker set by the
	// regroup administrator (warning 148), and <user-priority> per member for
	// participant preemption at the limit (TS 24.379 clause 10.1.2.4.1 steps 4b, 4c and 12a).
	PreconfiguredUseOnly bool `json:"preconfigured_use_only,omitempty"`
	Regrouped            bool `json:"regrouped,omitempty"`
	// <on-network-disabled> (TS 24.481 clause 7.2.4.2): the group takes no calls (TS 24.379 clause 6.3.5.2 step 5a,
	// warning 115).
	Disabled       bool           `json:"disabled,omitempty"`
	UserPriorities map[string]int `json:"user_priorities,omitempty"`
	Members        []string       `json:"members"`
	// <on-network-allow-getting-member-list> for members (TS 24.481 clause 7.2.12);
	// without it a member reads only its own <entry>.
	AllowGettingMemberList bool                   `json:"allow_getting_member_list,omitempty"`
	ProtectMedia           bool                   `json:"protect_media"`
	ProtectFloor           bool                   `json:"protect_floor"`
	CallPolicy             map[string]interface{} `json:"call_policy,omitempty"`
	// The <actions> of the group document's rule for every member (<is-list-member>, TS 24.481 clause 7.2.12.1):
	// <allow-MCPTT-emergency-call>, <allow-imminent-peril-call> and <allow-MCPTT-emergency-alert>. PriorityPolicy's
	// emergency_users, imminent_users and alert_users grant the same actions to the members they list (rules with an
	// <identity> condition). Neither: the action is not allowed (TS 24.481 clause 7.2.4.2).
	AllowEmergencyCall  bool                   `json:"allow_emergency_call,omitempty"`
	AllowImminentPeril  bool                   `json:"allow_imminent_peril,omitempty"`
	AllowEmergencyAlert bool                   `json:"allow_emergency_alert,omitempty"`
	FloorPriorityCaps   map[string]uint8       `json:"floor_priority_caps,omitempty"`
	PriorityPolicy      map[string]interface{} `json:"priority_policy,omitempty"`
	// MCData settings of the group; nil when the group does not support MCData.
	MCData *GroupMCData `json:"mcdata,omitempty"`
	// TS 24.481 clause 6.3.14: a temporary MCS group formed by the GMS names its
	// constituent groups (<on-network-temporary>), and each constituent group
	// carries the temporary group that combines it (<on-network-regrouped>).
	TemporaryConstituents []string          `json:"temporary_constituents,omitempty"`
	RegroupedBy           *TemporaryRegroup `json:"regrouped_by,omitempty"`
	// MCVideo settings of the group; nil when the group does not support MCVideo.
	MCVideo *GroupMCVideo `json:"mcvideo,omitempty"`
}

// GroupMCVideo is the MCVideo part of a group: its members by MCVideo ID (TS 24.481
// with TS 24.281 clause 8.2.2, which affiliate and call by MCVideo ID).
type GroupMCVideo struct {
	Members []string `json:"members"`
	// The group's call and priority settings for MCVideo, naming MCVideo IDs; the
	// MCVideo server uses them in place of the MCPTT ones.
	CallPolicy        map[string]interface{} `json:"call_policy,omitempty"`
	FloorPriorityCaps map[string]uint8       `json:"floor_priority_caps,omitempty"`
	PriorityPolicy    map[string]interface{} `json:"priority_policy,omitempty"`
	UserPriorities    map[string]int         `json:"user_priorities,omitempty"`
	// <mcvideo-allow-emergency-call>, <mcvideo-allow-imminent-peril-call> and <mcvideo-allow-emergency-alert> for
	// every member (TS 24.481 clause 7.2.12.1), as Group.AllowEmergencyCall and the others for MCPTT.
	AllowEmergencyCall  bool `json:"allow_emergency_call,omitempty"`
	AllowImminentPeril  bool `json:"allow_imminent_peril,omitempty"`
	AllowEmergencyAlert bool `json:"allow_emergency_alert,omitempty"`
	// <preconfigured-group-use-only> for MCVideo (TS 24.481 with TS 24.281): the group's MCVideo part in the
	// site.json form carries it, so provisioning (MCX Admin) must accept it.
	PreconfiguredUseOnly bool `json:"preconfigured_use_only,omitempty"`
}

// TemporaryRegroup is the <on-network-regrouped> element of a constituent group.
type TemporaryRegroup struct {
	TGI          string   `json:"temporary_group_id"`
	Requestor    string   `json:"requestor"`
	Constituents []string `json:"constituents"`
	ProtectMedia *bool    `json:"protect_media,omitempty"`
	ProtectFloor *bool    `json:"protect_floor,omitempty"`
}

type Endpoints struct {
	IDMS string `json:"idms"`
	GMS  string `json:"gms"`
	CMS  string `json:"cms"`
	KMS  string `json:"kms"`
	LMS  string `json:"lms"`
	// <MCDataContentServerURI> of the MCData user profile (TS 24.282 clause 10.2.2.1).
	Content string `json:"content,omitempty"`
	// The MCData message store (TS 24.282 clause 21.1, TS 24.484 clause 10.3) and notification
	// server (clause 10.4), as the clients reach them.
	MsgStore     string `json:"msgstore,omitempty"`
	Notification string `json:"notification,omitempty"`
	// The same two as the servers reach each other directly (MCData-8, MCData-11).
	MsgStoreInternal     string `json:"msgstore_internal,omitempty"`
	ContentInternal      string `json:"content_internal,omitempty"`
	NotificationInternal string `json:"notification_internal,omitempty"`
}

// MCDataServiceConfig carries the MCData service configuration values the content
// server enforces (TS 24.484 is not supplied; the names follow TS 24.282).
type MCDataServiceConfig struct {
	MaxDataSizeFDBytes int `json:"max_data_size_fd_bytes,omitempty"`
	// The public service identity of the MCData server, which the KMS provisions
	// for the CSKs of MCData signalling protection (TS 33.180 clause 9.5.1).
	ServiceURI string `json:"service_uri,omitempty"`
}

type MCVideoServiceConfig struct {
	ServiceURI string `json:"service_uri,omitempty"`
}

// ------------------------------------------------------------------------------
// Helper: reads and validates the configuration file; each group must state protect_media and protect_floor
// explicitly.
func LoadConfig(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	var presence struct {
		Groups []map[string]json.RawMessage `json:"groups"`
	}
	if err := json.Unmarshal(raw, &presence); err != nil {
		return Config{}, err
	}
	for index, group := range presence.Groups {
		if _, ok := group["protect_media"]; !ok {
			return Config{}, fmt.Errorf("groups[%d].protect_media must be explicit", index)
		}
		if _, ok := group["protect_floor"]; !ok {
			return Config{}, fmt.Errorf("groups[%d].protect_floor must be explicit", index)
		}
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// ------------------------------------------------------------------------------
// Helper: checks the configuration: the required values, unique and known identities (MCPTT, MCData and MCVideo
// IDs, functional aliases), the users' rulesets, the groups and their protection.
func (cfg Config) Validate() error {
	if admin := cfg.AdminAccounts; admin != nil && (!strings.HasPrefix(admin.URL, "https://") || !strings.HasPrefix(admin.LinkBaseURL, "https://")) {
		return errors.New("admin_accounts needs an https:// url and link_base_url")
	}
	if cfg.Domain == "" || cfg.ServiceURI == "" || cfg.Issuer == "" || cfg.OAuthClientID == "" || cfg.ServerClientID == "" || cfg.ServerSecret == "" {
		return errors.New("domain, service_uri, issuer, oauth_client_id, server_client_id and server_secret are required")
	}
	if cfg.TokenTTLSeconds <= 0 {
		return errors.New("token_ttl_seconds must be positive")
	}
	if err := cfg.ServiceConfig.Validate(); err != nil {
		return err
	}
	if len(cfg.OAuthRedirectURIs) == 0 {
		return errors.New("oauth_redirect_uris must contain a registered redirect URI")
	}
	for _, redirect := range cfg.OAuthRedirectURIs {
		user, err := url.Parse(redirect)
		if err != nil || user.Scheme == "" || user.Host == "" || user.Fragment != "" {
			return fmt.Errorf("invalid oauth redirect URI %q", redirect)
		}
	}
	users := map[string]bool{}
	mcpttIDs := map[string]bool{}
	for _, user := range cfg.Users {
		if user.Username == "" || user.Password == "" || user.MCID == "" || user.MCPTTID == "" || user.SIPURI == "" || user.ClientID == "" {
			return errors.New("each user requires username, password, mc_id, mcptt_id, sip_uri and client_id")
		}
		if users[user.Username] || mcpttIDs[user.MCPTTID] {
			return errors.New("duplicate username or mcptt_id")
		}
		if user.MaxAffiliations < 0 {
			return fmt.Errorf("user %q has a negative affiliation limit", user.MCPTTID)
		}
		users[user.Username], mcpttIDs[user.MCPTTID] = true, true
	}
	// Identities a group or private-call list may name: the users.
	known := maps.Clone(mcpttIDs)
	mcdataIDs := map[string]bool{}
	for _, user := range cfg.Users {
		if user.MCDataID == "" {
			if user.MCData != nil {
				return fmt.Errorf("user %q has an MCData ruleset but no mcdata_id", user.MCPTTID)
			}
			continue
		}
		if mcdataIDs[user.MCDataID] || mcpttIDs[user.MCDataID] {
			return fmt.Errorf("duplicate or reused mcdata_id %q", user.MCDataID)
		}
		mcdataIDs[user.MCDataID] = true
	}
	mcvideoIDs := map[string]bool{}
	for _, user := range cfg.Users {
		if user.MCVideoID == "" {
			if user.MCVideo != nil {
				return fmt.Errorf("user %q has an MCVideo profile but no mcvideo_id", user.MCPTTID)
			}
			continue
		}
		if !strings.HasPrefix(user.MCVideoID, "sip:") || mcvideoIDs[user.MCVideoID] || mcpttIDs[user.MCVideoID] || mcdataIDs[user.MCVideoID] {
			return fmt.Errorf("invalid, duplicate or reused mcvideo_id %q", user.MCVideoID)
		}
		mcvideoIDs[user.MCVideoID] = true
	}
	// Identities an MCVideo group or an MCData group or one-to-one list may name: the users.
	knownMCVideo := maps.Clone(mcvideoIDs)
	knownMCData := maps.Clone(mcdataIDs)
	for _, user := range cfg.Users {
		if user.MCData == nil {
			continue
		}
		for _, id := range append(append([]string{}, user.MCData.Targets...), user.MCData.IncomingFrom...) {
			if !knownMCData[id] || id == user.MCDataID {
				return fmt.Errorf("user %q has invalid MCData one-to-one entry %q", user.MCDataID, id)
			}
		}
		for _, group := range user.MCData.ImplicitAffiliations {
			if !cfg.knownGroup(group) {
				return fmt.Errorf("user %q has unknown implicit affiliation group %q", user.MCDataID, group)
			}
		}
	}
	for _, user := range cfg.Users {
		if user.PrivateCall == nil {
			continue
		}
		for _, target := range user.PrivateCall.Targets {
			if !known[target] || target == user.MCPTTID {
				return fmt.Errorf("user %q has invalid private call target %q", user.MCPTTID, target)
			}
		}
		for _, recipient := range append(append([]string{}, user.PrivateCall.EmergencyRecipients...), user.PrivateCall.AlertRecipients...) {
			if !known[recipient] || recipient == user.MCPTTID {
				return fmt.Errorf("user %q has invalid emergency private call recipient %q", user.MCPTTID, recipient)
			}
		}
		if forward := user.PrivateCall.ForwardImmediate; forward != "" && (!known[forward] || forward == user.MCPTTID) {
			return fmt.Errorf("user %q has invalid immediate forwarding target %q", user.MCPTTID, forward)
		}
		if forward := user.PrivateCall.ForwardNoAnswer; forward != "" && (!known[forward] || forward == user.MCPTTID) {
			return fmt.Errorf("user %q has invalid no-answer forwarding target %q", user.MCPTTID, forward)
		}
		if timeout := user.PrivateCall.NoAnswerTimeout; timeout != 0 && (user.PrivateCall.ForwardNoAnswer == "" || timeout < 1000 || timeout > 300000) {
			return fmt.Errorf("user %q has an invalid no-answer forwarding timeout", user.MCPTTID)
		}
		for _, caller := range user.PrivateCall.IncomingFrom {
			if !known[caller] || caller == user.MCPTTID {
				return fmt.Errorf("user %q has invalid incoming private call entry %q", user.MCPTTID, caller)
			}
		}
	}
	for _, group := range cfg.Groups {
		if group.ID == "" {
			return errors.New("group id is required")
		}
		if group.MCData != nil {
			for _, id := range append(append([]string{}, group.MCData.Members...), group.MCData.TransmitMembers...) {
				if !knownMCData[id] {
					return fmt.Errorf("group %q has unknown MCData member %q", group.ID, id)
				}
			}
		}
		if group.MCVideo != nil {
			for _, id := range group.MCVideo.Members {
				if !knownMCVideo[id] {
					return fmt.Errorf("group %q has unknown MCVideo member %q", group.ID, id)
				}
			}
		}
		switch group.Type {
		case "", "prearranged", "chat", "group-broadcast", "user-broadcast":
		default:
			return fmt.Errorf("group %q has unsupported type %q", group.ID, group.Type)
		}
		if (group.Type == "group-broadcast") != (len(group.SubordinateGroups) > 0) {
			return fmt.Errorf("group %q: subordinate groups are required for, and only allowed on, a group-broadcast group", group.ID)
		}
		for _, sub := range group.SubordinateGroups {
			target, ok := cfg.groupByID(sub)
			if !ok || sub == group.ID || target.Type == "group-broadcast" || target.Type == "user-broadcast" || target.Type == "chat" {
				return fmt.Errorf("group %q has invalid subordinate group %q", group.ID, sub)
			}
		}
		if group.ProtectMedia || group.ProtectFloor {
			if len(cfg.Security.KeyParameterProfile) != 4 || !strings.HasPrefix(cfg.Endpoints.KMS, "https://") {
				return fmt.Errorf("group %q requests unsupported protected profile: explicit key parameter interoperability profile and HTTPS KMS required", group.ID)
			}
			for _, name := range []string{"message_type", "algorithm", "key_parameters_iei", "encrypted_payload_iei"} {
				if _, ok := cfg.Security.KeyParameterProfile[name]; !ok {
					return errors.New("incomplete key parameter profile")
				}
			}
		}
		for _, member := range group.Members {
			if !known[member] {
				return fmt.Errorf("group %q has unknown member %q", group.ID, member)
			}
		}
		for member, priority := range group.UserPriorities {
			if priority < 0 || priority > 255 || !slices.Contains(group.Members, member) {
				return fmt.Errorf("group %q has invalid user priority for %q", group.ID, member)
			}
		}
	}
	if err := cfg.SealLM.validate(cfg); err != nil {
		return err
	}
	aliases := map[string]bool{}
	for _, fa := range cfg.FunctionalAliases {
		if !strings.HasPrefix(fa.ID, "sip:") || aliases[fa.ID] || mcpttIDs[fa.ID] || mcdataIDs[fa.ID] || mcvideoIDs[fa.ID] || fa.MaxSimultaneousActivations < 1 {
			return fmt.Errorf("invalid functional alias %q", fa.ID)
		}
		aliases[fa.ID] = true
		// In admin mode MCX Admin creates the users after this file is written, so an alias may name users this file
		// does not hold yet (an MC service ID all the same); in file mode every alias user is one of its users.
		known := func(ids map[string]bool, id string) bool {
			return ids[id] || (cfg.AdminAccounts != nil && strings.HasPrefix(id, "sip:"))
		}
		for _, id := range fa.Users {
			if !known(mcpttIDs, id) {
				return fmt.Errorf("functional alias %q has unknown user %q", fa.ID, id)
			}
		}
		for _, id := range fa.MCDataUsers {
			if !known(mcdataIDs, id) {
				return fmt.Errorf("functional alias %q has unknown MCData user %q", fa.ID, id)
			}
		}
		for _, id := range fa.MCVideoUsers {
			if !known(mcvideoIDs, id) {
				return fmt.Errorf("functional alias %q has unknown MCVideo user %q", fa.ID, id)
			}
		}
	}
	if !strings.HasPrefix(cfg.Issuer, "https://") {
		return errors.New("issuer must use https")
	}
	return cfg.validateProfileIndexes()
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1: checks the users' profile indexes.
func (cfg Config) validateProfileIndexes() error {
	for _, user := range cfg.Users {
		if user.ProfileIndex < 0 || user.ProfileIndex > 255 {
			return fmt.Errorf("user %q has an invalid profile_index", user.MCPTTID)
		}
	}
	return nil
}

// ------------------------------------------------------------------------------
// Helper: the user of a user name.
func (cfg Config) userByName(name string) (User, bool) {
	for _, user := range cfg.Users {
		if user.Username == name {
			return user, true
		}
	}
	return User{}, false
}

// ------------------------------------------------------------------------------
// Helper: the user of an MCData ID.
func (cfg Config) userByMCDataID(id string) (User, bool) {
	for _, user := range cfg.Users {
		if id != "" && user.MCDataID == id {
			return user, true
		}
	}
	return User{}, false
}

// ------------------------------------------------------------------------------
// Helper: the user of an MCVideo ID.
func (cfg Config) userByMCVideoID(id string) (User, bool) {
	for _, user := range cfg.Users {
		if id != "" && user.MCVideoID == id {
			return user, true
		}
	}
	return User{}, false
}

// ------------------------------------------------------------------------------
// Helper: the user of an MCPTT ID.
func (cfg Config) userByMCPTTID(id string) (User, bool) {
	for _, user := range cfg.Users {
		if user.MCPTTID == id {
			return user, true
		}
	}
	return User{}, false
}

// ------------------------------------------------------------------------------
// TS 24.484 clauses 8.3.2.1 item 10 g ii, 9.3.2.1 and 10.3.2.1: the <FunctionalAliasList> of a user's profile in one
// service: the aliases whose user list for that service names the user's ID, or nil when none does.
func (cfg Config) functionalAliasList(id string, users func(FunctionalAlias) []string) *profileEntryList {
	if id == "" {
		return nil
	}
	var list *profileEntryList
	for _, alias := range cfg.FunctionalAliases {
		if slices.Contains(users(alias), id) {
			if list == nil {
				list = &profileEntryList{}
			}
			list.Entries = append(list.Entries, profileEntry{URI: alias.ID})
		}
	}
	return list
}

// ------------------------------------------------------------------------------
// Helper: the functional alias of an ID.
func (cfg Config) functionalAliasByID(id string) (FunctionalAlias, bool) {
	for _, fa := range cfg.FunctionalAliases {
		if fa.ID == id {
			return fa, true
		}
	}
	return FunctionalAlias{}, false
}

// ------------------------------------------------------------------------------
// Helper: the group of a group ID.
func (cfg Config) groupByID(id string) (Group, bool) {
	for _, group := range cfg.Groups {
		if group.ID == id {
			return group, true
		}
	}
	return Group{}, false
}

// ------------------------------------------------------------------------------
// TS 33.180 annex B.4.2.2: the redirect URI is one registered for the MC client (annex B.3).
func (cfg Config) redirectAllowed(uri string) bool {
	for _, allowed := range cfg.OAuthRedirectURIs {
		if uri == allowed {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------------------------
// Helper: the mission critical organisation of this system (Config.Organization, else the domain).
func (c *Config) organization() string {
	if c.Organization != "" {
		return c.Organization
	}
	return c.Domain
}
