//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Location rules for group affiliation at the MCPTT and MCData clients:
//   - the user profile's affiliation rules (TS 24.484 clause 8.3.2.1 item 10 e) and f) and clause 8.3.2.7, the <anyExt>
//     of an <MCPTTGroupInfo> <entry>: <RulesForAffiliation>, <RulesForDeaffiliation> and
//     <manual-deaffiliation-not-allowed-if-affiliation-rules-are-met>; TS 24.379 clauses 9.2.1.7.2 and 9.2.1.2), and
//     those of the MCData user profile (TS 24.484 clause 10.3.2.1 item 9 b vii, the <anyExt> of an <MCDataGroupInfo>;
//     TS 24.282 clauses 8.2.6.2 and 8.2.2);
//   - the group document's <permitted-geographic-area> and <mandatory-geographic-area> (TS 24.481 clauses 7.2.4.2 and
//     7.2.8; TS 24.379 clause 9.2.1.7.3).
//
// Specifications: TS 24.484 V19.6.0, TS 24.481 V19.3.0, TS 24.282 V19.7.0 (Rel-19), TS 23.032.

package common

import (
	"fmt"
	"math"
)

// ------------------------------------------------------------------------------
// The configuration of a user's affiliation rules for one group (site.json "affiliation_rules", by group ID): the
// rule that affiliates and the one that de-affiliates, and whether the user may de-affiliate by hand while a rule
// keeps the group affiliated.
type GroupAffiliationRules struct {
	Affiliate                 *AffiliationRule `json:"affiliate,omitempty"`
	Deaffiliate               *AffiliationRule `json:"deaffiliate,omitempty"`
	ManualDeaffiliationLocked bool             `json:"manual_deaffiliation_locked,omitempty"`
}

// ------------------------------------------------------------------------------
// One rule (RulesForAffiliationManagementType): the areas whose entry or exit meets its location criterion
// (<ListOfLocationCriteria>), and the functional aliases whose activation meets its functional alias criterion
// (<ListOfActiveFunctionalAliasCriteria>).
type AffiliationRule struct {
	Enter   []GeoArea `json:"enter,omitempty"`
	Exit    []GeoArea `json:"exit,omitempty"`
	Aliases []string  `json:"aliases,omitempty"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.3: the RulesForAffiliationManagementType of the profile.
type profileAffiliationRule struct {
	Location *profileAreaChange `xml:"ListOfLocationCriteria,omitempty"`
	Aliases  *profileEntryList  `xml:"ListOfActiveFunctionalAliasCriteria,omitempty"`
}

// ------------------------------------------------------------------------------
// Helper: the profile form of a configured rule; nil without one.
func profileAffiliationRuleOf(rule *AffiliationRule) *profileAffiliationRule {
	if rule == nil {
		return nil
	}
	out := &profileAffiliationRule{Location: profileAreaChangeOf(&AreaCriteria{Enter: rule.Enter, Exit: rule.Exit})}
	if len(rule.Aliases) > 0 {
		out.Aliases = &profileEntryList{}
		for index, alias := range rule.Aliases {
			out.Aliases.Entries = append(out.Aliases.Entries, profileEntry{Index: fmt.Sprint(index + 1), URI: alias})
		}
	}
	return out
}

// ------------------------------------------------------------------------------
// Helper: the <anyExt> of the user's <MCPTTGroupInfo> entry for a group: its affiliation rules; nil without any.
func (rules *GroupAffiliationRules) profileEntryExt() *profileEntryExt {
	if rules == nil {
		return nil
	}
	ext := &profileEntryExt{RulesForAffiliation: profileAffiliationRuleOf(rules.Affiliate),
		RulesForDeaffiliation: profileAffiliationRuleOf(rules.Deaffiliate)}
	if rules.ManualDeaffiliationLocked {
		locked := true
		ext.ManualDeaffiliationLocked = &locked
	}
	if ext.RulesForAffiliation == nil && ext.RulesForDeaffiliation == nil && ext.ManualDeaffiliationLocked == nil {
		return nil
	}
	return ext
}

// ------------------------------------------------------------------------------
// Helper: TS 24.484 clause 10.3.2.1 item 9 b vii: the affiliation rules in the <anyExt> of the user's
// <MCDataGroupInfo> for a group (`ext`, created when nil and a rule is configured); the extension returned.
func (rules *GroupAffiliationRules) mcdataGroupInfoExt(ext *mcdataGroupInfoExt) *mcdataGroupInfoExt {
	rendered := rules.profileEntryExt()
	if rendered == nil {
		return ext
	}
	if ext == nil {
		ext = &mcdataGroupInfoExt{}
	}
	ext.RulesForAffiliation = rendered.RulesForAffiliation
	ext.RulesForDeaffiliation = rendered.RulesForDeaffiliation
	ext.ManualDeaffiliationLocked = rendered.ManualDeaffiliationLocked
	return ext
}

// ------------------------------------------------------------------------------
// Helper: checks an area: a polygon of 3 to 15 corners in range, or an arc with a centre in range.
func checkGeoArea(area GeoArea) error {
	points := area.Polygon
	switch {
	case len(area.Polygon) > 0 && area.Center != nil:
		return fmt.Errorf("an area is a polygon or an arc")
	case len(area.Polygon) > 0 && (len(area.Polygon) < 3 || len(area.Polygon) > 15):
		return fmt.Errorf("a polygon has 3 to 15 corners")
	case area.Center != nil:
		points = [][2]float64{*area.Center}
	case len(area.Polygon) == 0:
		return fmt.Errorf("an area needs a polygon or an arc")
	}
	for _, point := range points {
		if point[0] < -90 || point[0] > 90 || point[1] < -180 || point[1] > 180 {
			return fmt.Errorf("coordinates out of range")
		}
	}
	return nil
}

// ------------------------------------------------------------------------------
// Helper: checks a user's affiliation rules: each for a group of the user, with areas of checkGeoArea and known
// functional aliases, and each rule with a criterion.
func checkAffiliationRules(user User, aliases map[string]bool) error {
	return checkGroupAffiliationRules(user.MCPTTID, user.Groups, user.AffiliationRules, aliases)
}

// ------------------------------------------------------------------------------
// Helper: checks the affiliation rules of one service's user profile (`id`, the user's ID in that service): each
// for one of `groups`, with areas of checkGeoArea and known functional aliases, and each rule with a criterion.
func checkGroupAffiliationRules(id string, groups []string, all map[string]*GroupAffiliationRules,
	aliases map[string]bool) error {
	member := map[string]bool{}
	for _, group := range groups {
		member[group] = true
	}
	for group, rules := range all {
		if !member[group] || rules == nil {
			return fmt.Errorf("user %s: affiliation rules for %q, not one of its groups", id, group)
		}
		for _, rule := range []*AffiliationRule{rules.Affiliate, rules.Deaffiliate} {
			if rule == nil {
				continue
			}
			if len(rule.Enter)+len(rule.Exit)+len(rule.Aliases) == 0 {
				return fmt.Errorf("user %s: an affiliation rule for %s without a criterion", id, group)
			}
			for _, area := range append(append([]GeoArea{}, rule.Enter...), rule.Exit...) {
				if err := checkGeoArea(area); err != nil {
					return fmt.Errorf("user %s: affiliation rule for %s: %w", id, group, err)
				}
			}
			for _, alias := range rule.Aliases {
				if !aliases[alias] {
					return fmt.Errorf("user %s: affiliation rule for %s names unknown functional alias %q",
						id, group, alias)
				}
			}
		}
	}
	return nil
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.4.2: the areaType of <permitted-geographic-area> and <mandatory-geographic-area>, a sequence of
// polygons and ellipsoid arcs in the mcpttGroupInfo namespace (the children take it from the element).
type groupAreaXML struct {
	Polygons []profilePolygon `xml:"PolygonArea"`
	Arcs     []profileArc     `xml:"EllipsoidArcArea"`
}

// ------------------------------------------------------------------------------
// Helper: the group document form of configured areas; nil without any.
func groupAreaOf(areas []GeoArea) *groupAreaXML {
	if len(areas) == 0 {
		return nil
	}
	out := &groupAreaXML{}
	for _, area := range profileAreasOf(areas) {
		if area.Polygon != nil {
			out.Polygons = append(out.Polygons, *area.Polygon)
		} else if area.Arc != nil {
			out.Arcs = append(out.Arcs, *area.Arc)
		}
	}
	return out
}

// ------------------------------------------------------------------------------
// TS 23.032 clause 6.1: the degrees of a coded latitude (sign bit and 23 bits) and longitude (24-bit two's
// complement), at the centre of the coded interval.
func decodeLatitude(code uint32) float64 {
	degrees := (float64(code&0x7fffff) + 0.5) * 90 / 8388608
	if code&0x800000 != 0 {
		degrees = -degrees
	}
	return degrees
}

func decodeLongitude(code uint32) float64 {
	value := int32(code<<8) >> 8
	return (float64(value) + 0.5) * 360 / 16777216
}

// ------------------------------------------------------------------------------
// Helper: configured areas from a group document's area (a group document a client PUTs back keeps them).
func geoAreasOf(area *groupAreaXML) []GeoArea {
	if area == nil {
		return nil
	}
	var out []GeoArea
	point := func(p profilePoint) [2]float64 {
		round := func(value float64) float64 { return math.Round(value*1e7) / 1e7 }
		return [2]float64{round(decodeLatitude(p.Latitude)), round(decodeLongitude(p.Longitude))}
	}
	for _, polygon := range area.Polygons {
		var corners [][2]float64
		for _, corner := range polygon.Corners {
			corners = append(corners, point(corner))
		}
		out = append(out, GeoArea{Polygon: corners})
	}
	for _, arc := range area.Arcs {
		center := point(arc.Center)
		out = append(out, GeoArea{Center: &center, Radius: arc.Radius, OffsetAngle: arc.OffsetAngle,
			IncludedAngle: arc.IncludedAngle})
	}
	return out
}
