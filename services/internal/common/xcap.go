//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// XCAP on a small namespace-aware XML tree: node selectors, namespace bindings, the fetch, create or replace and
// delete of elements and attributes, and the XCAP error body.
//
// Specifications: RFC 4825, TS 24.481 V19.3.0 (Rel-19).
package common

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// XCAP (RFC 4825) on a small namespace-aware XML tree: the node selectors of RFC 4825 section
// 6.3 (element steps with a position or an attribute predicate, a final attribute or
// namespace selector) and the create, replace, fetch and delete operations of RFC 4825
// sections 7 and 8, as TS 24.481 clause 6.3.2 to clause 6.3.12 use them on group documents.

// ------------------------------------------------------------------------------
// Helper: an element of a parsed XML document, with its attributes, children and leaf text.
type xmlNode struct {
	Name     xml.Name
	Attr     []xml.Attr
	Children []*xmlNode
	Text     string // character data of a leaf
	Parent   *xmlNode
}

// ------------------------------------------------------------------------------
// RFC 4825 section 11: xcapError is an error condition.
type xcapError struct {
	Status  int
	Element string // the <xcap-error> child element
	Detail  string
	Alt     []string // <alt-value> of a <uniqueness-failure>
}

// ------------------------------------------------------------------------------
// Helper: the status, error element and detail of an XCAP error.
func (xcapErr *xcapError) Error() string {
	return fmt.Sprintf("%d %s %s", xcapErr.Status, xcapErr.Element, xcapErr.Detail)
}

// ------------------------------------------------------------------------------
// RFC 4825 section 11: an XCAP error with its status code and error element (none for a plain status).
func xcapFail(status int, element, detail string) error {
	return &xcapError{Status: status, Element: element, Detail: detail}
}

// ------------------------------------------------------------------------------
// RFC 4825 section 8.2.2: parses a well-formed document or fragment into a tree; DTDs and entities are refused and
// namespace declarations dropped.
func parseXMLTree(raw []byte) (*xmlNode, error) {
	if bytes.Contains(raw, []byte("<!DOCTYPE")) || bytes.Contains(raw, []byte("<!ENTITY")) {
		return nil, errors.New("DTD and entities are not accepted")
	}
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	var root, current *xmlNode
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch item := token.(type) {
		case xml.StartElement:
			node := &xmlNode{Name: item.Name, Parent: current}
			for _, attr := range item.Attr {
				if attr.Name.Space == "xmlns" || attr.Name.Local == "xmlns" {
					continue // declarations are regenerated on output
				}
				node.Attr = append(node.Attr, attr)
			}
			if current == nil {
				if root != nil {
					return nil, errors.New("more than one root element")
				}
				root = node
			} else {
				current.Children = append(current.Children, node)
			}
			current = node
		case xml.EndElement:
			if current == nil {
				return nil, errors.New("unbalanced element")
			}
			current = current.Parent
		case xml.CharData:
			if current != nil && len(current.Children) == 0 {
				current.Text += string(item)
			}
		}
	}
	if root == nil || current != nil {
		return nil, errors.New("not a well-formed document")
	}
	trimMixed(root)
	return root, nil
}

// ------------------------------------------------------------------------------
// Helper: text is kept only on leaf elements (the group documents have no mixed content).
func trimMixed(node *xmlNode) {
	if len(node.Children) > 0 {
		node.Text = ""
	}
	for _, childNode := range node.Children {
		trimMixed(childNode)
	}
}

// ------------------------------------------------------------------------------
// Helper: serialize writes the tree with one prefix per namespace, declared on the root.
func (node *xmlNode) serialize() []byte {
	prefixes := map[string]string{node.Name.Space: ""}
	var collect func(*xmlNode)
	collect = func(element *xmlNode) {
		for _, space := range append([]string{element.Name.Space}, attrSpaces(element)...) {
			if _, ok := prefixes[space]; !ok && space != "" {
				prefixes[space] = "ns" + strconv.Itoa(len(prefixes))
			}
		}
		for _, childNode := range element.Children {
			collect(childNode)
		}
	}
	collect(node)
	var buffer bytes.Buffer
	buffer.WriteString(xml.Header)
	var write func(*xmlNode, bool)
	write = func(element *xmlNode, root bool) {
		name := qualified(prefixes, element.Name)
		buffer.WriteString("<" + name)
		if root {
			for _, binding := range sortedPrefixes(prefixes) {
				if binding.prefix == "" {
					buffer.WriteString(` xmlns="` + escapeAttr(binding.space) + `"`)
				} else {
					buffer.WriteString(` xmlns:` + binding.prefix + `="` + escapeAttr(binding.space) + `"`)
				}
			}
		}
		for _, attr := range element.Attr {
			attrName := attr.Name.Local
			if attr.Name.Space != "" {
				attrName = prefixes[attr.Name.Space] + ":" + attr.Name.Local
			}
			buffer.WriteString(" " + attrName + `="` + escapeAttr(attr.Value) + `"`)
		}
		if len(element.Children) == 0 && element.Text == "" {
			buffer.WriteString("/>")
			return
		}
		buffer.WriteString(">")
		if len(element.Children) == 0 {
			_ = xml.EscapeText(&buffer, []byte(element.Text))
		}
		for _, childNode := range element.Children {
			write(childNode, false)
		}
		buffer.WriteString("</" + name + ">")
	}
	write(node, true)
	return buffer.Bytes()
}

// ------------------------------------------------------------------------------
// Helper: a namespace and the prefix bound to it.
type prefixBinding struct{ space, prefix string }

// ------------------------------------------------------------------------------
// Helper: the prefix bindings of the non-empty namespaces, sorted by prefix.
func sortedPrefixes(prefixes map[string]string) []prefixBinding {
	out := make([]prefixBinding, 0, len(prefixes))
	for space, prefix := range prefixes {
		if space != "" {
			out = append(out, prefixBinding{space, prefix})
		}
	}
	for index := range out {
		for later := index + 1; later < len(out); later++ {
			if out[later].prefix < out[index].prefix {
				out[index], out[later] = out[later], out[index]
			}
		}
	}
	return out
}

// ------------------------------------------------------------------------------
// Helper: the namespaces of an element's attributes.
func attrSpaces(node *xmlNode) []string {
	var out []string
	for _, attr := range node.Attr {
		if attr.Name.Space != "" {
			out = append(out, attr.Name.Space)
		}
	}
	return out
}

// ------------------------------------------------------------------------------
// Helper: an element name with the prefix of its namespace.
func qualified(prefixes map[string]string, name xml.Name) string {
	if prefix := prefixes[name.Space]; prefix != "" {
		return prefix + ":" + name.Local
	}
	return name.Local
}

// ------------------------------------------------------------------------------
// Helper: a text escaped for an attribute value in double quotes.
func escapeAttr(text string) string {
	var buffer bytes.Buffer
	_ = xml.EscapeText(&buffer, []byte(text))
	return strings.ReplaceAll(buffer.String(), `"`, "&#34;")
}

// ------------------------------------------------------------------------------
// Helper: the value of an attribute without namespace, and whether it is present.
func (node *xmlNode) attr(local string) (string, bool) {
	for _, attr := range node.Attr {
		if attr.Name.Space == "" && attr.Name.Local == local {
			return attr.Value, true
		}
	}
	return "", false
}

// ---- node selectors (RFC 4825 section 6.3) ----

// ------------------------------------------------------------------------------
// RFC 4825 section 6.3: one location step of a node selector: a name or "*", with a position or an attribute
// predicate.
type selectorStep struct {
	name     xml.Name
	any      bool   // "*"
	position int    // [n], 1-based; 0 when absent
	attrName string // [@name="value"]
	attrVal  string
}

// ------------------------------------------------------------------------------
// RFC 4825 section 6.3: a node selector: its element steps and a final attribute or namespace selector.
type nodeSelector struct {
	steps     []selectorStep
	attribute string // a final "@name"
	namespace bool   // a final "namespace::*"
}

// ------------------------------------------------------------------------------
// RFC 4825 section 6.3 and section 6.4: parseNodeSelector reads a node selector with the namespace bindings of the XCAP
// URI query (xmlns(p=urn)); an unprefixed name is in the default namespace.
func parseNodeSelector(selector string, bindings map[string]string, defaultNS string) (nodeSelector, error) {
	var out nodeSelector
	parts := splitSteps(selector)
	if len(parts) == 0 {
		return out, xcapFail(400, "", "empty node selector")
	}
	for index, part := range parts {
		last := index == len(parts)-1
		if last && strings.HasPrefix(part, "@") {
			out.attribute = part[1:]
			continue
		}
		if last && part == "namespace::*" {
			out.namespace = true
			continue
		}
		step := selectorStep{}
		name := part
		if open := strings.IndexByte(part, '['); open >= 0 {
			if !strings.HasSuffix(part, "]") {
				return out, xcapFail(400, "", "malformed predicate in "+part)
			}
			name = part[:open]
			for _, predicate := range strings.Split(strings.TrimSuffix(part[open+1:], "]"), "][") {
				if count, err := strconv.Atoi(predicate); err == nil && count > 0 {
					step.position = count
					continue
				}
				if !strings.HasPrefix(predicate, "@") || !strings.Contains(predicate, "=") {
					return out, xcapFail(400, "", "unsupported predicate "+predicate)
				}
				eq := strings.IndexByte(predicate, '=')
				step.attrName = predicate[1:eq]
				value := predicate[eq+1:]
				if len(value) < 2 || (value[0] != '"' && value[0] != '\'') || value[len(value)-1] != value[0] {
					return out, xcapFail(400, "", "unquoted predicate value "+value)
				}
				step.attrVal = value[1 : len(value)-1]
			}
		}
		if name == "*" {
			step.any = true
		} else {
			space := defaultNS
			if colon := strings.IndexByte(name, ':'); colon >= 0 {
				bound, ok := bindings[name[:colon]]
				if !ok {
					return out, xcapFail(400, "", "unbound prefix "+name[:colon])
				}
				space, name = bound, name[colon+1:]
			}
			if name == "" {
				return out, xcapFail(400, "", "empty step")
			}
			step.name = xml.Name{Space: space, Local: name}
		}
		out.steps = append(out.steps, step)
	}
	if len(out.steps) == 0 {
		return out, xcapFail(400, "", "node selector without an element step")
	}
	return out, nil
}

// ------------------------------------------------------------------------------
// RFC 4825 section 6.3: splitSteps splits on "/" outside quotes.
func splitSteps(selector string) []string {
	var out []string
	var current strings.Builder
	quote := byte(0)
	for index := 0; index < len(selector); index++ {
		char := selector[index]
		switch {
		case quote != 0:
			if char == quote {
				quote = 0
			}
			current.WriteByte(char)
		case char == '"' || char == '\'':
			quote = char
			current.WriteByte(char)
		case char == '/':
			if current.Len() > 0 {
				out = append(out, current.String())
			}
			current.Reset()
		default:
			current.WriteByte(char)
		}
	}
	if current.Len() > 0 {
		out = append(out, current.String())
	}
	return out
}

// ------------------------------------------------------------------------------
// RFC 4825 section 6.4: parseXMLNSQuery reads the xmlns(prefix=namespace) bindings of an XCAP URI query.
func parseXMLNSQuery(query string) (map[string]string, error) {
	bindings := map[string]string{}
	for query != "" {
		if !strings.HasPrefix(query, "xmlns(") {
			return nil, xcapFail(400, "", "unsupported XCAP query "+query)
		}
		end := strings.IndexByte(query, ')')
		if end < 0 {
			return nil, xcapFail(400, "", "unterminated xmlns() binding")
		}
		binding := query[len("xmlns("):end]
		eq := strings.IndexByte(binding, '=')
		if eq <= 0 {
			return nil, xcapFail(400, "", "malformed xmlns() binding")
		}
		bindings[binding[:eq]] = binding[eq+1:]
		query = query[end+1:]
	}
	return bindings, nil
}

// ------------------------------------------------------------------------------
// RFC 4825 section 6.3: whether an element matches a step's name and attribute predicate.
func (step selectorStep) matches(node *xmlNode) bool {
	if !step.any && node.Name != step.name {
		return false
	}
	if step.attrName != "" {
		value, ok := node.attr(step.attrName)
		return ok && value == step.attrVal
	}
	return true
}

// ------------------------------------------------------------------------------
// RFC 4825 section 6.3: locate finds the elements a selector's steps select: the matches of the last step
// under each match of the previous one. XCAP requires exactly one for the operations.
func (sel nodeSelector) locate(root *xmlNode) []*xmlNode {
	first := sel.steps[0]
	if !first.matches(root) || (first.position > 1) {
		return nil
	}
	current := []*xmlNode{root}
	for _, step := range sel.steps[1:] {
		var next []*xmlNode
		for _, parent := range current {
			var candidates []*xmlNode
			for _, childNode := range parent.Children {
				// Position counts the children with the step's name (RFC 4825 section 6.3).
				if step.any || childNode.Name == step.name {
					candidates = append(candidates, childNode)
				}
			}
			if step.position > 0 {
				if step.position <= len(candidates) && step.matches(candidates[step.position-1]) {
					next = append(next, candidates[step.position-1])
				}
				continue
			}
			for _, childNode := range candidates {
				if step.matches(childNode) {
					next = append(next, childNode)
				}
			}
		}
		current = next
	}
	return current
}

// ---- operations ----

// ------------------------------------------------------------------------------
// RFC 4825 section 8.3 (for RFC 4825 section 7.6, section 7.9 and section 7.10): xcapFetch returns the selected
// element as an XML fragment, an attribute value, or the namespace bindings in scope (RFC 4825 section 10).
func xcapFetch(root *xmlNode, sel nodeSelector) (string, []byte, error) {
	found := sel.locate(root)
	if len(found) != 1 {
		return "", nil, xcapFail(404, "", "no single element selected")
	}
	node := found[0]
	switch {
	case sel.attribute != "":
		value, ok := node.attr(sel.attribute)
		if !ok {
			return "", nil, xcapFail(404, "", "no such attribute")
		}
		return "application/xcap-att+xml", []byte(value), nil
	case sel.namespace:
		var builder strings.Builder
		builder.WriteString(`<` + node.Name.Local + ` xmlns="` + escapeAttr(node.Name.Space) + `"`)
		spaces := map[string]bool{}
		for ancestor := node; ancestor != nil; ancestor = ancestor.Parent {
			spaces[ancestor.Name.Space] = true
		}
		count := 0
		for space := range spaces {
			if space != node.Name.Space && space != "" {
				count++
				builder.WriteString(` xmlns:ns` + strconv.Itoa(count) + `="` + escapeAttr(space) + `"`)
			}
		}
		builder.WriteString("/>")
		return "application/xcap-ns+xml", []byte(builder.String()), nil
	}
	clone := cloneNode(node, nil)
	body := clone.serialize()
	return "application/xcap-el+xml", bytes.TrimPrefix(body, []byte(xml.Header)), nil
}

// ------------------------------------------------------------------------------
// Helper: a deep copy of an element under a new parent.
func cloneNode(node *xmlNode, parent *xmlNode) *xmlNode {
	clone := &xmlNode{Name: node.Name, Attr: append([]xml.Attr{}, node.Attr...), Text: node.Text, Parent: parent}
	for _, childNode := range node.Children {
		clone.Children = append(clone.Children, cloneNode(childNode, clone))
	}
	return clone
}

// ------------------------------------------------------------------------------
// RFC 4825 section 8.2 (for RFC 4825 section 7.4 and section 7.7): xcapPut creates or replaces an element or an
// attribute. created reports whether the node is new.
func xcapPut(root *xmlNode, sel nodeSelector, body []byte) (created bool, err error) {
	if sel.namespace {
		return false, xcapFail(405, "", "namespace bindings cannot be written")
	}
	if sel.attribute != "" {
		found := sel.locate(root)
		if len(found) != 1 {
			return false, xcapFail(409, "no-parent", "the element of the attribute does not exist")
		}
		value := string(body)
		for index, attr := range found[0].Attr {
			if attr.Name.Space == "" && attr.Name.Local == sel.attribute {
				found[0].Attr[index].Value = value
				return false, nil
			}
		}
		found[0].Attr = append(found[0].Attr, xml.Attr{Name: xml.Name{Local: sel.attribute}, Value: value})
		return true, nil
	}
	// The body is one element, in the namespace of the selector's last step (RFC 4825 section 7.4).
	fragment, err := parseXMLTree(body)
	if err != nil {
		return false, xcapFail(409, "not-well-formed", err.Error())
	}
	last := sel.steps[len(sel.steps)-1]
	if (!last.any && fragment.Name != last.name) ||
		(last.attrName != "" && func() bool { value, ok := fragment.attr(last.attrName); return !ok || value != last.attrVal }()) {
		return false, xcapFail(409, "cannot-insert", "the element does not match the node selector")
	}
	if found := sel.locate(root); len(found) == 1 {
		if found[0] == root {
			return false, xcapFail(409, "cannot-delete", "the root element is replaced by a document PUT")
		}
		parent := found[0].Parent
		for index, childNode := range parent.Children {
			if childNode == found[0] {
				fragment.Parent = parent
				parent.Children[index] = fragment
			}
		}
		return false, nil
	} else if len(found) > 1 {
		return false, xcapFail(409, "cannot-insert", "the node selector selects more than one element")
	}
	parentSelector := nodeSelector{steps: sel.steps[:len(sel.steps)-1]}
	if len(parentSelector.steps) == 0 {
		return false, xcapFail(409, "no-parent", "no parent element")
	}
	parents := parentSelector.locate(root)
	if len(parents) != 1 {
		return false, xcapFail(409, "no-parent", "the parent element does not exist")
	}
	fragment.Parent = parents[0]
	// An insert by position lands at that position among the same-named children (RFC 4825 section 8.2.3).
	if last.position > 0 {
		count, index := 0, len(parents[0].Children)
		for childIndex, childNode := range parents[0].Children {
			if childNode.Name == fragment.Name {
				count++
				if count == last.position {
					index = childIndex
				}
			}
		}
		if last.position > count+1 {
			return false, xcapFail(409, "cannot-insert", "position beyond the siblings")
		}
		parents[0].Children = append(parents[0].Children[:index], append([]*xmlNode{fragment}, parents[0].Children[index:]...)...)
		return true, nil
	}
	parents[0].Children = append(parents[0].Children, fragment)
	parents[0].Text = ""
	return true, nil
}

// ------------------------------------------------------------------------------
// RFC 4825 section 8.4 (for RFC 4825 section 7.5 and section 7.8): xcapDelete removes an element or an attribute.
func xcapDelete(root *xmlNode, sel nodeSelector) error {
	if sel.namespace {
		return xcapFail(405, "", "namespace bindings cannot be deleted")
	}
	found := sel.locate(root)
	if len(found) != 1 {
		return xcapFail(404, "", "no single element selected")
	}
	node := found[0]
	if sel.attribute != "" {
		for index, attr := range node.Attr {
			if attr.Name.Space == "" && attr.Name.Local == sel.attribute {
				node.Attr = append(node.Attr[:index], node.Attr[index+1:]...)
				return nil
			}
		}
		return xcapFail(404, "", "no such attribute")
	}
	if node == root {
		return xcapFail(409, "cannot-delete", "the root element is deleted with the document")
	}
	parent := node.Parent
	for index, childNode := range parent.Children {
		if childNode == node {
			parent.Children = append(parent.Children[:index], parent.Children[index+1:]...)
			break
		}
	}
	return nil
}

// ------------------------------------------------------------------------------
// RFC 4825 section 11: xcapErrorBody is the application/xcap-error+xml body.
func xcapErrorBody(xcapErr *xcapError) []byte {
	var builder strings.Builder
	builder.WriteString(`<?xml version="1.0" encoding="UTF-8"?><xcap-error xmlns="urn:ietf:params:xml:ns:xcap-error">`)
	if xcapErr.Element == "uniqueness-failure" {
		builder.WriteString(`<uniqueness-failure><exists field="list-service/@uri">`)
		for _, alt := range xcapErr.Alt {
			builder.WriteString("<alt-value>" + escapeAttr(alt) + "</alt-value>")
		}
		builder.WriteString(`</exists></uniqueness-failure>`)
	} else if xcapErr.Element != "" {
		builder.WriteString("<" + xcapErr.Element + ` phrase="` + escapeAttr(xcapErr.Detail) + `"/>`)
	}
	builder.WriteString("</xcap-error>")
	return []byte(builder.String())
}
