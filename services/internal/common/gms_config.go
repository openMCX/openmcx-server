// Helpers of the GMS's configuration: SIP identities.
//
// Specifications: TS 24.481 V19.3.0 (Rel-19).
package common

import "strings"

// ------------------------------------------------------------------------------
// Helper: the domain of a SIP URI (the part after "@"), in lower case; empty without one.
func uriDomain(id string) string {
	if index := strings.LastIndexByte(id, '@'); index >= 0 {
		return strings.ToLower(id[index+1:])
	}
	return ""
}

// ------------------------------------------------------------------------------
// Helper: whether an identity is a SIP URI with a domain and without characters that break a header field.
func validSIPIdentity(id string) bool {
	return strings.HasPrefix(id, "sip:") && uriDomain(id) != "" && !strings.ContainsAny(id, " <>\"")
}

// ------------------------------------------------------------------------------
// Helper: knownGroup reports a group defined here.
func (config Config) knownGroup(id string) bool {
	_, ok := config.groupByID(id)
	return ok
}
