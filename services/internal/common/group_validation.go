//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Validation of a group document before it is stored: the schema, then the validation constraints of the OMA
// Group XDM and of TS 24.481, and the check of the documents generated from the configuration at start-up.
//
// Specifications: TS 24.481 V19.3.0 (Rel-19), RFC 4825, OMA XDM (Group XDM), RFC 4826.
package common

import (
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
)

// ------------------------------------------------------------------------------
// RFC 4825 section 8.2.5: validateGroupDocument checks a group document proposed by an XCAP request
// before it is stored: first the schema (TS 24.481 clause 7.2.4), then
// the validation constraints of OMA-TS-XDM_Group-V1_1_1 clause 5.1.6 and TS 24.481 clause 7.2.7.
// owner is the XUI of the document's users tree. The uniqueness of the group URI
// is checked by the caller, which knows the stored documents.
func validateGroupDocument(raw []byte, owner string) error {
	if err := groupDocumentSchema.validate(raw); err != nil {
		return schemaError(err)
	}
	root, err := parseXMLTree(raw)
	if err != nil {
		return xcapFail(409, "not-well-formed", err.Error())
	}
	return groupConstraints(root, owner)
}

// ------------------------------------------------------------------------------
// RFC 4825 section 11: a 409 with the <constraint-failure> error element and its phrase.
func constraintFailure(phrase string) error { return xcapFail(409, "constraint-failure", phrase) }

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.7: the validation constraints of a group document: those of OMA-TS-XDM_Group-V1_1_1 clause
// 5.1.6 on the <list-service>, its entries, external lists and ruleset, then the maximum duration of a group whose
// members are invited.
func groupConstraints(root *xmlNode, owner string) error {
	var services []*xmlNode
	for _, childNode := range root.Children {
		if childNode.Name == (qn(pocNS, "list-service")) {
			services = append(services, childNode)
		}
	}
	// OMA-TS-XDM_Group-V1_1_1 clause 5.1.6: a document in a users directory holds one <list-service>.
	if len(services) != 1 {
		return constraintFailure("No more than one list-service element allowed")
	}
	ls := services[0]
	seen := map[string]bool{}
	pocElement := true
	for _, childNode := range ls.Children {
		// OMA-TS-XDM_Group-V1_1_1 clause 5.1.6: <ruleset> is the first element after those of the
		// list-service namespace.
		if childNode.Name.Space != pocNS {
			if childNode.Name == (qn(commonPolicyNS, "ruleset")) && !pocElement {
				return constraintFailure("The ruleset element must be the first element after the list-service elements")
			}
			pocElement = false
		}
		switch childNode.Name {
		case qn(pocNS, "list"):
			for _, element := range childNode.Children {
				switch element.Name.Local {
				case "entry":
					uri, _ := element.attr("uri")
					if !userAddress(uri) {
						return constraintFailure("URI syntax error")
					}
					if seen[uri] {
						return constraintFailure("Duplicate entry")
					}
					seen[uri] = true
				case "external":
					if err := externalListConstraint(element, owner); err != nil {
						return err
					}
				}
			}
		case qn(commonPolicyNS, "ruleset"):
			if err := rulesetConstraints(childNode, owner); err != nil {
				return err
			}
		case qn(xdmExtensionsNS, "automatic-group-advertisement"):
			if strings.TrimSpace(childNode.Text) == "true" || strings.TrimSpace(childNode.Text) == "1" {
				return constraintFailure("Automatic group advertisement not supported")
			}
		case qn(xdmExtensionsNS, "searchable"):
			return constraintFailure("Search not supported")
		}
	}
	// TS 24.481 clause 7.2.7: members invited to a call need a maximum call duration.
	if invite := child(ls, mcpttgiNS, "on-network-invite-members"); invite != nil {
		if value := strings.TrimSpace(invite.Text); (value == "true" || value == "1") && child(ls, mcpttgiNS, "on-network-maximum-duration") == nil {
			return constraintFailure("on-network-maximum-duration is required when on-network-invite-members is true")
		}
	}
	return nil
}

// ------------------------------------------------------------------------------
// Helper: the first child element of a node with this namespace and local name, or nil.
func child(node *xmlNode, space, local string) *xmlNode {
	for _, childNode := range node.Children {
		if childNode.Name.Space == space && childNode.Name.Local == local {
			return childNode
		}
	}
	return nil
}

// ------------------------------------------------------------------------------
// OMA-TS-XDM_Group-V1_1_1 clause 5.1.6: rulesetConstraints allows one identity-like condition per rule.
func rulesetConstraints(ruleset *xmlNode, owner string) error {
	for _, rule := range ruleset.Children {
		conditions := child(rule, commonPolicyNS, "conditions")
		if conditions == nil {
			continue
		}
		count := 0
		for _, childNode := range conditions.Children {
			switch childNode.Name {
			case qn(commonPolicyNS, "identity"), qn(omaCommonPolicyNS, "external-list"),
				qn(omaCommonPolicyNS, "anonymous-request"), qn(omaCommonPolicyNS, "other-identity"),
				qn(pocNS, "is-list-member"):
				count++
			}
			if childNode.Name == (qn(omaCommonPolicyNS, "external-list")) {
				for _, element := range childNode.Children {
					anc, _ := element.attr("anc")
					if err := listReferenceConstraint(anc, owner); err != nil {
						return err
					}
				}
			}
		}
		if count > 1 {
			return constraintFailure("Complex rules are not allowed")
		}
	}
	return nil
}

// ------------------------------------------------------------------------------
// OMA-TS-XDM_Group-V1_1_1 clause 5.1.6: the "anchor" of an <external> list must be a list of the owner.
func externalListConstraint(element *xmlNode, owner string) error {
	anchor, _ := element.attr("anchor")
	return listReferenceConstraint(anchor, owner)
}

// ------------------------------------------------------------------------------
// OMA-TS-XDM_Group-V1_1_1 clause 5.1.6: listReferenceConstraint: an <external> or <external-list> points to
// a resource-lists document (RFC 4826 section 3) of the owner of the group document.
func listReferenceConstraint(ref, owner string) error {
	uri, err := url.Parse(ref)
	if err != nil {
		return constraintFailure("Wrong type of list")
	}
	path := uri.Path
	at := strings.Index(path, "/resource-lists/")
	if at < 0 {
		return constraintFailure("Wrong type of list")
	}
	rest := strings.TrimPrefix(path[at+len("/resource-lists/"):], "users/")
	xui, _, _ := strings.Cut(rest, "/")
	if unescaped, err := url.PathUnescape(xui); err == nil {
		xui = unescaped
	}
	if owner == "" || xui != owner {
		return constraintFailure("Access denied to list")
	}
	return nil
}

// ------------------------------------------------------------------------------
// OMA-TS-XDM_Group-V1_1_1 clause 5.1.6: userAddress reports whether a group member URI is a user address this GMS
// supports: a SIP, SIPS or TEL URI.
func userAddress(uri string) bool {
	scheme, rest, ok := strings.Cut(uri, ":")
	if !ok || rest == "" || strings.ContainsAny(uri, " <>\"") {
		return false
	}
	switch strings.ToLower(scheme) {
	case "sip", "sips":
		return uriDomain("sip:"+rest) != ""
	case "tel":
		return true
	}
	return false
}

// ------------------------------------------------------------------------------
// Helper: an XML name of a namespace and a local name.
func qn(space, local string) xml.Name { return xml.Name{Space: space, Local: local} }

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.4 and clause 7.2.7: checkGroupDocuments validates the group documents the GMS generates from its
// configuration, so that a configuration whose documents do not conform to the
// schema stops the GMS at start-up instead of being served.
func (svc *service) checkGroupDocuments() error {
	for _, group := range svc.cfg.Groups {
		raw, err := groupDocument(group, true)
		if err == nil {
			err = validateGroupDocument(raw, "")
		}
		if err != nil {
			return fmt.Errorf("group document of %s: %w", group.ID, err)
		}
	}
	return nil
}
