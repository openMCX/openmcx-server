// MCData message store: searching objects (TS 24.282 clauses 21.2.2 and 21.2.17; OMA NMS clause 6.8).
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), OMA RESTful Network API for Network Message Storage
// (OMA-TS-REST_NetAPI_NMS-V1_0-20190528-C).

package common

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// ---- search (OMA NMS clause 6.8, TS 24.282 clauses 21.2.2 and 21.2.17) ----

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.2.2: one search criterion of the OMA NMS SelectionCriteria.
type nmsCriterion struct {
	Type  string `json:"type"`
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.2.2 (OMA NMS clause 6.8.5): the SelectionCriteria of an object search.
type nmsSelection struct {
	MaxEntries     int `json:"maxEntries,omitempty"`
	SearchCriteria *struct {
		Criterion []nmsCriterion `json:"criterion"`
		Operator  string         `json:"operator,omitempty"`
	} `json:"searchCriteria,omitempty"`
	SearchScope *struct {
		ResourceURL string `json:"resourceURL"`
	} `json:"searchScope,omitempty"`
	FromCursor        string `json:"fromCursor,omitempty"`
	NonRecursiveScope *bool  `json:"nonRecursiveScope,omitempty"`
}

// ------------------------------------------------------------------------------
// Helper: the values of the named attribute of an object (case-insensitive name), or nil.
func attributeValues(attributes []nmsAttribute, name string) []string {
	for _, attribute := range attributes {
		if strings.EqualFold(attribute.Name, name) {
			return attribute.Value
		}
	}
	return nil
}

// ------------------------------------------------------------------------------
// Helper: whether a folder lies in the search scope folder: the folder itself or, when recursive, a descendant
// (OMA NMS nonRecursiveScope). An empty scope is the whole box.
func inScope(box *storeBox, folder, scope string, recursive bool) bool {
	if scope == "" {
		return true
	}
	for current := box.Folders[folder]; current != nil; current = box.Folders[current.Parent] {
		if current.ID == scope {
			return true
		}
		if !recursive {
			return false
		}
	}
	return false
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.2.2 (OMA NMS clause 6.8.5) and clause 21.2.17.2 (search-based synchronization): answer the
// objects of the box matching the SelectionCriteria, in creation order and paged by cursor; with a
// VanishedObjects criterion, the references of the objects deleted since a mod-seq instead.
func (svc *service) nmsSearchObjects(writer http.ResponseWriter, request *http.Request, box *storeBox) {
	var sel nmsSelection
	if !readJSON(writer, request, "selectionCriteria", &sel) {
		return
	}
	svc.store.mu.Lock()
	defer svc.store.mu.Unlock()
	scope := ""
	if sel.SearchScope != nil && sel.SearchScope.ResourceURL != "" {
		scope = lastSegment(sel.SearchScope.ResourceURL, "folders")
		if box.Folders[scope] == nil {
			nmsError(writer, http.StatusNotFound, "SVC0004", "No valid addresses provided in message part %1", "searchScope")
			return
		}
	}
	recursive := sel.NonRecursiveScope == nil || !*sel.NonRecursiveScope
	var criteria []nmsCriterion
	and := true
	if sel.SearchCriteria != nil {
		criteria = sel.SearchCriteria.Criterion
		and = !strings.EqualFold(sel.SearchCriteria.Operator, "Or")
	}
	// The criteria that take a cursor or a mod-seq, and fromCursor, are numbers.
	numbers := map[int]int64{}
	for index, criterion := range criteria {
		if criterion.Type != "VanishedObjects" && criterion.Type != "CreatedObjects" && criterion.Type != "ModifiedSince" {
			continue
		}
		number, err := strconv.ParseInt(criterion.Value, 10, 64)
		if err != nil {
			nmsError(writer, http.StatusBadRequest, "SVC0002", "Invalid input value for message part %1", "criterion")
			return
		}
		numbers[index] = number
	}
	start := int64(0)
	if sel.FromCursor != "" {
		var err error
		if start, err = strconv.ParseInt(sel.FromCursor, 10, 64); err != nil {
			nmsError(writer, http.StatusBadRequest, "SVC0002", "Invalid input value for message part %1", "fromCursor")
			return
		}
	}
	base := svc.boxURL(request, box)
	// VanishedObjects: the objects deleted after the given mod-seq (OMA NMS clause 5.1.5.2).
	for index, criterion := range criteria {
		if criterion.Type == "VanishedObjects" {
			since := numbers[index]
			var refs []nmsReference
			var ids []string
			for id, seq := range box.Vanished {
				if seq > since {
					ids = append(ids, id)
				}
			}
			sort.Strings(ids)
			for _, id := range ids {
				refs = append(refs, nmsReference{ResourceURL: base + "/objects/" + id})
			}
			writeJSON(writer, http.StatusOK, map[string]any{"objectReferenceList": map[string]any{"objectReference": refs,
				"lastModSeq": box.ModSeq}})
			return
		}
	}
	matches := func(object *storedObject) bool {
		if !inScope(box, object.Folder, scope, recursive) {
			return false
		}
		if len(criteria) == 0 {
			return true
		}
		result := and
		for index, criterion := range criteria {
			var ok bool
			switch criterion.Type {
			case "Attribute":
				for _, value := range attributeValues(object.Attributes, criterion.Name) {
					if strings.EqualFold(value, criterion.Value) {
						ok = true
					}
				}
			case "Flag":
				for _, flag := range object.Flags {
					ok = ok || flag == criterion.Value
				}
			case "PresentFlag", "NotPresentFlag":
				ok = criterion.Type == "NotPresentFlag"
				for _, flag := range object.Flags {
					if flag == criterion.Value {
						ok = criterion.Type == "PresentFlag"
					}
				}
			case "CreatedObjects":
				ok = object.Created > numbers[index]
			case "ModifiedSince":
				ok = object.ModSeq > numbers[index]
			case "TextContent":
				for _, attribute := range object.Attributes {
					for _, value := range attribute.Value {
						ok = ok || strings.Contains(strings.ToLower(value), strings.ToLower(criterion.Value))
					}
				}
			case "Date":
				for _, value := range attributeValues(object.Attributes, "Date") {
					ok = ok || strings.HasPrefix(value, criterion.Value)
				}
			}
			if and {
				result = result && ok
			} else {
				result = result || ok
			}
		}
		return result
	}
	limit := sel.MaxEntries
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	list := map[string]any{"object": []nmsObject{}}
	var objects []nmsObject
	for _, object := range sortedObjects(box) {
		if object.Created <= start || !matches(object) {
			continue
		}
		if len(objects) == limit {
			list["cursor"] = strconv.FormatInt(object.Created-1, 10)
			break
		}
		objects = append(objects, svc.objectView(request, box, object))
	}
	if objects != nil {
		list["object"] = objects
	}
	for _, criterion := range criteria {
		if criterion.Type == "CreatedObjects" {
			list["creationCursor"] = strconv.FormatInt(box.Creation, 10) // TS 24.282 clause 21.2.17.2 step 1
		}
	}
	list["lastModSeq"] = box.ModSeq
	writeJSON(writer, http.StatusOK, map[string]any{"objectList": list})
}
