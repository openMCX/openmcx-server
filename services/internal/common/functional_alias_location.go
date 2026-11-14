//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Location criteria of functional aliases in the user profile documents (TS 24.484 clauses 8.3.2.1, 9.3.2.1 and
// 10.3.2.1, the <anyExt> of a <FunctionalAliasList> <entry>): the areas whose entry or exit activates or deactivates
// the alias at the client (TS 24.379 clause 9A.2.1.4, TS 24.281 clause 20.2.1.4, TS 24.282 clause 22.2.1.4).
//
// Specifications: TS 24.484 V19.6.0 (Rel-19), TS 23.032.

package common

import (
	"fmt"
	"math"
)

// ------------------------------------------------------------------------------
// The configuration of an area (site.json): a polygon of 3 to 15 [latitude, longitude] corners in degrees, or an
// ellipsoid arc around a [latitude, longitude] centre (TS 23.032 clauses 5.4 and 5.7).
type GeoArea struct {
	Polygon       [][2]float64 `json:"polygon,omitempty"`
	Center        *[2]float64  `json:"center,omitempty"`
	Radius        uint32       `json:"radius,omitempty"`         // metres
	OffsetAngle   uint8        `json:"offset_angle,omitempty"`   // 2N degrees clockwise from north
	IncludedAngle uint8        `json:"included_angle,omitempty"` // 2(N+1) degrees
}

// ------------------------------------------------------------------------------
// The configuration of a <LocationCriteriaForActivation> or <LocationCriteriaForDeactivation>: the areas whose entry
// or exit triggers the change.
type AreaCriteria struct {
	Enter []GeoArea `json:"enter,omitempty"`
	Exit  []GeoArea `json:"exit,omitempty"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.3 (and 9.3.2.3, 10.3.2.3): the <anyExt> of a <FunctionalAliasList> <entry>.
type profileEntryExt struct {
	Activation   *profileAreaChange `xml:"LocationCriteriaForActivation,omitempty"`
	Deactivation *profileAreaChange `xml:"LocationCriteriaForDeactivation,omitempty"`
	ManualLocked *bool              `xml:"manual-deactivation-not-allowed-if-location-criteria-met,omitempty"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.3: the GeographicalAreaChangeType.
type profileAreaChange struct {
	Enter []profileArea `xml:"EnterSpecificArea"`
	Exit  []profileArea `xml:"ExitSpecificArea"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.3: the GeographicalAreaType, a polygon or an ellipsoid arc.
type profileArea struct {
	Polygon *profilePolygon `xml:"PolygonArea,omitempty"`
	Arc     *profileArc     `xml:"EllipsoidArcArea,omitempty"`
}

type profilePolygon struct {
	Corners []profilePoint `xml:"Corner"`
}

type profileArc struct {
	Center        profilePoint `xml:"Center"`
	Radius        uint32       `xml:"Radius"`
	OffsetAngle   uint8        `xml:"OffsetAngle"`
	IncludedAngle uint8        `xml:"IncludedAngle"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.3: the PointCoordinateType, each coordinate coded as in TS 23.032 clause 6.1.
type profilePoint struct {
	Longitude uint32 `xml:"Longitude"`
	Latitude  uint32 `xml:"Latitude"`
}

// ------------------------------------------------------------------------------
// TS 23.032 clause 6.1: a latitude is a sign bit and 23 bits, N <= 2^23 |X| / 90 < N + 1.
func encodeLatitude(degrees float64) uint32 {
	magnitude := math.Min(math.Floor(math.Abs(degrees)*8388608/90), 8388607)
	code := uint32(magnitude)
	if degrees < 0 {
		code |= 0x800000
	}
	return code
}

// ------------------------------------------------------------------------------
// TS 23.032 clause 6.1: a longitude is a 24-bit two's complement number, N <= 2^24 X / 360 < N + 1.
func encodeLongitude(degrees float64) uint32 {
	if degrees == 180 {
		degrees = -180
	}
	return uint32(int32(math.Floor(degrees*16777216/360))) & 0xffffff
}

// ------------------------------------------------------------------------------
// Helper: a configured [latitude, longitude] as a profile point.
func profilePointOf(point [2]float64) profilePoint {
	return profilePoint{Longitude: encodeLongitude(point[1]), Latitude: encodeLatitude(point[0])}
}

// ------------------------------------------------------------------------------
// Helper: the profile form of configured areas.
func profileAreasOf(areas []GeoArea) []profileArea {
	var out []profileArea
	for _, area := range areas {
		if len(area.Polygon) > 0 {
			polygon := &profilePolygon{}
			for _, corner := range area.Polygon {
				polygon.Corners = append(polygon.Corners, profilePointOf(corner))
			}
			out = append(out, profileArea{Polygon: polygon})
		} else if area.Center != nil {
			out = append(out, profileArea{Arc: &profileArc{Center: profilePointOf(*area.Center), Radius: area.Radius,
				OffsetAngle: area.OffsetAngle, IncludedAngle: area.IncludedAngle}})
		}
	}
	return out
}

// ------------------------------------------------------------------------------
// Helper: the profile form of configured criteria; nil without areas.
func profileAreaChangeOf(criteria *AreaCriteria) *profileAreaChange {
	if criteria == nil || len(criteria.Enter)+len(criteria.Exit) == 0 {
		return nil
	}
	return &profileAreaChange{Enter: profileAreasOf(criteria.Enter), Exit: profileAreasOf(criteria.Exit)}
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1 item 10 (9.3.2.1, 10.3.2.1): the <anyExt> of the alias's <FunctionalAliasList> entry; nil
// when the alias has no location criteria.
func (alias FunctionalAlias) profileEntryExt() *profileEntryExt {
	ext := &profileEntryExt{Activation: profileAreaChangeOf(alias.LocationActivation),
		Deactivation: profileAreaChangeOf(alias.LocationDeactivation)}
	if alias.ManualDeactivationLocked {
		locked := true
		ext.ManualLocked = &locked
	}
	if ext.Activation == nil && ext.Deactivation == nil && ext.ManualLocked == nil {
		return nil
	}
	return ext
}

// ------------------------------------------------------------------------------
// Helper: checks the configured location criteria of a functional alias: areas of 3 to 15 corners in range, or arcs
// with a centre in range and a radius.
func (alias FunctionalAlias) checkLocationCriteria() error {
	for _, criteria := range []*AreaCriteria{alias.LocationActivation, alias.LocationDeactivation} {
		if criteria == nil {
			continue
		}
		for _, area := range append(append([]GeoArea{}, criteria.Enter...), criteria.Exit...) {
			points := area.Polygon
			switch {
			case len(area.Polygon) > 0 && area.Center != nil:
				return fmt.Errorf("functional alias %s: an area is a polygon or an arc", alias.ID)
			case len(area.Polygon) > 0 && (len(area.Polygon) < 3 || len(area.Polygon) > 15):
				return fmt.Errorf("functional alias %s: a polygon has 3 to 15 corners", alias.ID)
			case area.Center != nil:
				points = [][2]float64{*area.Center}
			case len(area.Polygon) == 0:
				return fmt.Errorf("functional alias %s: an area needs a polygon or an arc", alias.ID)
			}
			for _, point := range points {
				if point[0] < -90 || point[0] > 90 || point[1] < -180 || point[1] > 180 {
					return fmt.Errorf("functional alias %s: coordinates out of range", alias.ID)
				}
			}
		}
	}
	return nil
}
