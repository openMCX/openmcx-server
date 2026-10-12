//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The service configuration documents the CMS serves: MCPTT (TS 24.484 clause 8.4), MCVideo (clause 9.4) and MCData
// (clause 10.4), one per mission critical organisation, from the site's service_config; and the same values on the
// internal interface for the MC service servers.
//
// Specifications: TS 24.484 V19.6.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.4.0 (Rel-19),
// TS 24.281 V19.6.0 (Rel-19), TS 24.282 V19.6.0 (Rel-19), RFC 8101, RFC 4412.
package common

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// ------------------------------------------------------------------------------
// The three service configuration documents: namespace, AUID and MIME type (TS 24.484 clauses 8.4.2.2 to 8.4.2.5,
// 9.4.2.2 to 9.4.2.5, 10.4.2.2 to 10.4.2.5). The document is global: CMSXCAPROOTURI/<AUID>/global/service-config.xml
// for the one mission critical organisation of this system (clause 8.4.2.8).
const (
	mcpttServiceConfigNS     = "urn:3gpp:ns:mcpttServiceConfig:1.0"
	mcvideoServiceConfigNS   = "urn:3gpp:ns:mcvideoServiceConfig:1.0"
	mcdataServiceConfigNS    = "urn:3gpp:ns:mcdataServiceConfig:1.0"
	serviceConfigDocument    = "service-config.xml"
	defaultFileAvailabilityS = 120
	maxFileAvailabilityS     = 600
)

// ------------------------------------------------------------------------------
// ServiceConfiguration is the site's service_config: what the three service configuration documents carry, per
// service. What is not set takes the defaults of TS 24.380 (floor control) and resourcePriorityDefaults.
type ServiceConfiguration struct {
	MCPTT   *MCPTTServiceConfiguration   `json:"mcptt,omitempty"`
	MCVideo *MCVideoServiceConfiguration `json:"mcvideo,omitempty"`
	MCData  *MCDataServiceConfiguration  `json:"mcdata,omitempty"`
}

// ------------------------------------------------------------------------------
// ResourcePriorities are <emergency-resource-priority>, <imminent-peril-resource-priority> and
// <normal-resource-priority>, each "<namespace>.<priority>" as the Resource-Priority header field carries it (RFC
// 4412): an RFC 8101 namespace (mcpttp, preemption; mcpttq, queuing) and a level 0 to 15.
type ResourcePriorities struct {
	Emergency string `json:"emergency,omitempty"`
	Imminent  string `json:"imminent,omitempty"`
	Normal    string `json:"normal,omitempty"`
}

// ------------------------------------------------------------------------------
// MCPTTServiceConfiguration: the resource priorities and the floor control timers and counters of <on-network>
// (TS 24.484 clause 8.4.2.1), in milliseconds and counts.
type MCPTTServiceConfiguration struct {
	ResourcePriority ResourcePriorities `json:"resource_priority"`
	// <transmit-time>/<time-limit>: T2, the longest a user may hold the floor.
	TransmitTimeLimitMs int `json:"transmit_time_limit_ms,omitempty"`
	// <floor-control-queue>: queueing of floor requests, and its <depth>.
	FloorQueue      bool `json:"floor_queue,omitempty"`
	FloorQueueDepth int  `json:"floor_queue_depth,omitempty"`
	// <fc-timers-counters>, by the timer and counter names of TS 24.380 (t1, t3, ..., c56).
	FloorTimers map[string]int `json:"fc_timers_counters,omitempty"`
}

// ------------------------------------------------------------------------------
// MCVideoServiceConfiguration: the resource priorities of <on-network> (TS 24.484 clause 9.4.2.1).
type MCVideoServiceConfiguration struct {
	ResourcePriority ResourcePriorities `json:"resource_priority"`
}

// ------------------------------------------------------------------------------
// MCDataServiceConfiguration: the resource priorities of the <anyExt> of <on-network> and its <file-availability>
// (TS 24.484 clause 10.4.2.1).
type MCDataServiceConfiguration struct {
	ResourcePriority ResourcePriorities `json:"resource_priority"`
	// <default-file-availability> and <max-file-availability> (TS 24.282 clause 10.2.4.4.2 step 9), in seconds.
	DefaultFileAvailabilityS int `json:"default_file_availability_s,omitempty"`
	MaxFileAvailabilityS     int `json:"max_file_availability_s,omitempty"`
}

// ------------------------------------------------------------------------------
// TS 24.380 tables 11.1.3-1, 11.1.4-1 and 11.2.1-1: the default timers (milliseconds) and counters of
// <fc-timers-counters>. T7 (Floor Idle) has no default: the floor control server repeats Floor Idle once a second.
var floorTimerDefaults = map[string]int{
	"t1": 4000, "t3": 3000, "t7": 1000, "t8": 1000, "t11": 4000, "t12": 30000, "t15": 30000, "t16": 500,
	"t17": 200, "t20": 1000, "t55": 2000, "t56": 2000, "c7": 10, "c17": 3, "c20": 3, "c55": 3, "c56": 3,
}

// ------------------------------------------------------------------------------
// The resource priorities when the site sets none: RFC 8101 preemption, emergency above imminent peril above normal.
var resourcePriorityDefaults = ResourcePriorities{Emergency: "mcpttp.15", Imminent: "mcpttp.10", Normal: "mcpttp.0"}

// ------------------------------------------------------------------------------
// Helper: the resource priorities with the defaults for those not set.
func (rp ResourcePriorities) withDefaults() ResourcePriorities {
	if rp.Emergency == "" {
		rp.Emergency = resourcePriorityDefaults.Emergency
	}
	if rp.Imminent == "" {
		rp.Imminent = resourcePriorityDefaults.Imminent
	}
	if rp.Normal == "" {
		rp.Normal = resourcePriorityDefaults.Normal
	}
	return rp
}

// ------------------------------------------------------------------------------
// RFC 8101 section 3.2: splitResourcePriority gives the namespace (mcpttp or mcpttq) and the level 0 to 15 of a
// "<namespace>.<priority>" value.
func splitResourcePriority(value string) (string, int, error) {
	namespace, level, found := strings.Cut(value, ".")
	priority, err := strconv.Atoi(level)
	if !found || (namespace != "mcpttp" && namespace != "mcpttq") || err != nil || priority < 0 || priority > 15 ||
		strconv.Itoa(priority) != level {
		return "", 0, fmt.Errorf("resource priority %q: not an RFC 8101 value (mcpttp.0 to mcpttp.15, mcpttq.0 to mcpttq.15)", value)
	}
	return namespace, priority, nil
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.4.2.7: each value is an RFC 8101 namespace and level, and the emergency level is at least the
// imminent peril level, which is at least the normal level.
func (rp ResourcePriorities) validate(service string) error {
	rp = rp.withDefaults()
	var levels [3]int
	for index, value := range []string{rp.Emergency, rp.Imminent, rp.Normal} {
		_, level, err := splitResourcePriority(value)
		if err != nil {
			return fmt.Errorf("service_config.%s: %w", service, err)
		}
		levels[index] = level
	}
	if levels[0] < levels[1] || levels[1] < levels[2] {
		return fmt.Errorf("service_config.%s: the emergency resource priority must be at least the imminent peril one, "+
			"which must be at least the normal one", service)
	}
	return nil
}

// ------------------------------------------------------------------------------
// Validate checks the service configuration: the resource priorities of each service and the floor timer names.
func (sc ServiceConfiguration) Validate() error {
	if sc.MCPTT != nil {
		if err := sc.MCPTT.ResourcePriority.validate("mcptt"); err != nil {
			return err
		}
		for name, value := range sc.MCPTT.FloorTimers {
			if _, known := floorTimerDefaults[name]; !known || value < 0 {
				return fmt.Errorf("service_config.mcptt.fc_timers_counters: %s=%d is not a timer or counter of <fc-timers-counters>", name, value)
			}
		}
	}
	if sc.MCVideo != nil {
		if err := sc.MCVideo.ResourcePriority.validate("mcvideo"); err != nil {
			return err
		}
	}
	if sc.MCData != nil {
		if err := sc.MCData.ResourcePriority.validate("mcdata"); err != nil {
			return err
		}
	}
	return nil
}

// ------------------------------------------------------------------------------
// The service configuration of each service, with the defaults filled in.
func (sc ServiceConfiguration) mcptt() MCPTTServiceConfiguration {
	out := MCPTTServiceConfiguration{}
	if sc.MCPTT != nil {
		out = *sc.MCPTT
	}
	out.ResourcePriority = out.ResourcePriority.withDefaults()
	timers := map[string]int{}
	for name, value := range floorTimerDefaults {
		timers[name] = value
	}
	for name, value := range out.FloorTimers {
		timers[name] = value
	}
	out.FloorTimers = timers
	if out.TransmitTimeLimitMs == 0 {
		out.TransmitTimeLimitMs = 30000
	}
	return out
}

func (sc ServiceConfiguration) mcvideo() MCVideoServiceConfiguration {
	out := MCVideoServiceConfiguration{}
	if sc.MCVideo != nil {
		out = *sc.MCVideo
	}
	out.ResourcePriority = out.ResourcePriority.withDefaults()
	return out
}

func (sc ServiceConfiguration) mcdata() MCDataServiceConfiguration {
	out := MCDataServiceConfiguration{}
	if sc.MCData != nil {
		out = *sc.MCData
	}
	out.ResourcePriority = out.ResourcePriority.withDefaults()
	if out.DefaultFileAvailabilityS == 0 {
		out.DefaultFileAvailabilityS = defaultFileAvailabilityS
	}
	if out.MaxFileAvailabilityS == 0 {
		out.MaxFileAvailabilityS = maxFileAvailabilityS
	}
	return out
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.4.2.3: resource-priorityType.
type resourcePriorityXML struct {
	Namespace string `xml:"resource-priority-namespace"`
	Priority  string `xml:"resource-priority-priority"`
}

// ------------------------------------------------------------------------------
// Helper: the element of a "<namespace>.<priority>" value (validated with the configuration).
func resourcePriorityElement(value string) resourcePriorityXML {
	namespace, level, _ := splitResourcePriority(value)
	return resourcePriorityXML{Namespace: namespace, Priority: strconv.Itoa(level)}
}

// ------------------------------------------------------------------------------
// Helper: an xs:duration of milliseconds (PT<seconds>S, with a fraction when needed).
func durationOf(ms int) string {
	if ms%1000 == 0 {
		return "PT" + strconv.Itoa(ms/1000) + "S"
	}
	return "PT" + strconv.FormatFloat(float64(ms)/1000, 'f', -1, 64) + "S"
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.4.2.1: the MCPTT service configuration document.
type mcpttServiceConfigXML struct {
	XMLName xml.Name `xml:"urn:3gpp:ns:mcpttServiceConfig:1.0 service-configuration-info"`
	Params  struct {
		Domain    string `xml:"domain,attr"`
		OnNetwork struct {
			TransmitTime struct {
				TimeLimit string `xml:"time-limit"`
			} `xml:"transmit-time"`
			Queue *struct {
				Depth int `xml:"depth"`
			} `xml:"floor-control-queue,omitempty"`
			Timers struct {
				T1  string `xml:"T1-end-of-rtp-media"`
				T3  string `xml:"T3-stop-talking-grace"`
				T7  string `xml:"T7-floor-idle"`
				T8  string `xml:"T8-floor-revoke"`
				T11 string `xml:"T11-end-of-RTP-dual"`
				T12 string `xml:"T12-stop-talking-dual"`
				T15 string `xml:"T15-conversation"`
				T16 string `xml:"T16-map-group-to-bearer"`
				T17 string `xml:"T17-unmap-group-to-bearer"`
				T20 string `xml:"T20-floor-granted"`
				T55 string `xml:"T55-connect"`
				T56 string `xml:"T56-disconnect"`
				C7  int    `xml:"C7-floor-idle"`
				C17 int    `xml:"C17-unmap-group-to-bearer"`
				C20 int    `xml:"C20-floor-granted"`
				C55 int    `xml:"C55-connect"`
				C56 int    `xml:"C56-disconnect"`
			} `xml:"fc-timers-counters"`
			Emergency resourcePriorityXML `xml:"emergency-resource-priority"`
			Imminent  resourcePriorityXML `xml:"imminent-peril-resource-priority"`
			Normal    resourcePriorityXML `xml:"normal-resource-priority"`
		} `xml:"on-network"`
	} `xml:"service-configuration-params"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 9.4.2.1: the MCVideo service configuration document.
type mcvideoServiceConfigXML struct {
	XMLName xml.Name `xml:"urn:3gpp:ns:mcvideoServiceConfig:1.0 service-configuration-info"`
	Params  struct {
		Domain    string `xml:"domain,attr"`
		OnNetwork struct {
			Emergency resourcePriorityXML `xml:"emergency-resource-priority"`
			Imminent  resourcePriorityXML `xml:"imminent-peril-resource-priority"`
			Normal    resourcePriorityXML `xml:"normal-resource-priority"`
		} `xml:"on-network"`
	} `xml:"service-configuration-params"`
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 10.4.2.1: the MCData service configuration document; the resource priorities are in the <anyExt>
// of <on-network> (item 4).
type mcdataServiceConfigXML struct {
	XMLName xml.Name `xml:"urn:3gpp:ns:mcdataServiceConfig:1.0 service-configuration-info"`
	Params  struct {
		Domain    string `xml:"domain,attr"`
		OnNetwork struct {
			FileAvailability struct {
				Default int `xml:"default-file-availability"`
				Max     int `xml:"max-file-availability"`
			} `xml:"file-availability"`
			AnyExt struct {
				Emergency resourcePriorityXML `xml:"emergency-resource-priority"`
				Imminent  resourcePriorityXML `xml:"imminent-peril-resource-priority"`
				Normal    resourcePriorityXML `xml:"normal-resource-priority"`
			} `xml:"anyExt"`
		} `xml:"on-network"`
	} `xml:"service-configuration-params"`
}

// ------------------------------------------------------------------------------
// The service configuration documents by AUID: the document, its MIME type and its schema.
func (svc *service) serviceConfigDocument(auid string) ([]byte, string, *documentSchema, bool) {
	var doc any
	var mime string
	var schema *documentSchema
	sc := svc.cfg.ServiceConfig
	switch auid {
	case "org.3gpp.mcptt.service-config":
		conf := sc.mcptt()
		var out mcpttServiceConfigXML
		out.Params.Domain = svc.cfg.Domain
		on := &out.Params.OnNetwork
		on.TransmitTime.TimeLimit = durationOf(conf.TransmitTimeLimitMs)
		if conf.FloorQueue {
			on.Queue = &struct {
				Depth int `xml:"depth"`
			}{Depth: max(conf.FloorQueueDepth, 1)}
		}
		t := conf.FloorTimers
		timers := &on.Timers
		timers.T1, timers.T3, timers.T7, timers.T8 = durationOf(t["t1"]), durationOf(t["t3"]), durationOf(t["t7"]), durationOf(t["t8"])
		timers.T11, timers.T12, timers.T15, timers.T16 = durationOf(t["t11"]), durationOf(t["t12"]), durationOf(t["t15"]), durationOf(t["t16"])
		timers.T17, timers.T20, timers.T55, timers.T56 = durationOf(t["t17"]), durationOf(t["t20"]), durationOf(t["t55"]), durationOf(t["t56"])
		timers.C7, timers.C17, timers.C20, timers.C55, timers.C56 = t["c7"], t["c17"], t["c20"], t["c55"], t["c56"]
		rp := conf.ResourcePriority
		on.Emergency, on.Imminent, on.Normal = resourcePriorityElement(rp.Emergency), resourcePriorityElement(rp.Imminent), resourcePriorityElement(rp.Normal)
		doc, mime, schema = out, "application/vnd.3gpp.mcptt-service-config+xml", mcpttServiceConfigSchema
	case "org.3gpp.mcvideo.service-config":
		rp := sc.mcvideo().ResourcePriority
		var out mcvideoServiceConfigXML
		out.Params.Domain = svc.cfg.Domain
		on := &out.Params.OnNetwork
		on.Emergency, on.Imminent, on.Normal = resourcePriorityElement(rp.Emergency), resourcePriorityElement(rp.Imminent), resourcePriorityElement(rp.Normal)
		doc, mime, schema = out, "application/vnd.3gpp.mcvideo-service-config+xml", mcvideoServiceConfigSchema
	case "org.3gpp.mcdata.service-config":
		conf := sc.mcdata()
		var out mcdataServiceConfigXML
		out.Params.Domain = svc.cfg.Domain
		on := &out.Params.OnNetwork
		on.FileAvailability.Default, on.FileAvailability.Max = conf.DefaultFileAvailabilityS, conf.MaxFileAvailabilityS
		rp := conf.ResourcePriority
		on.AnyExt.Emergency, on.AnyExt.Imminent, on.AnyExt.Normal = resourcePriorityElement(rp.Emergency), resourcePriorityElement(rp.Imminent), resourcePriorityElement(rp.Normal)
		doc, mime, schema = out, "application/vnd.3gpp.mcdata-service-config+xml", mcdataServiceConfigSchema
	default:
		return nil, "", nil, false
	}
	raw, err := xml.Marshal(doc)
	if err != nil {
		return nil, "", nil, false
	}
	return append([]byte(xml.Header), raw...), mime, schema, true
}

// ------------------------------------------------------------------------------
// TS 24.484 clauses 8.4.2.8, 8.4.2.9 and 6.3.3.3: getServiceConfig: every authenticated MC service user reads the
// service configuration document (read-only) at CMSXCAPROOTURI/<AUID>/global/service-config.xml.
func (svc *service) getServiceConfig(writer http.ResponseWriter, request *http.Request) {
	if _, ok := svc.authenticateBearer(writer, request); !ok {
		return
	}
	raw, mime, _, ok := svc.serviceConfigDocument(request.PathValue("auid"))
	if !ok || request.PathValue("document") != serviceConfigDocument {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": http.StatusText(http.StatusNotFound)})
		return
	}
	writeDocument(writer, request, raw, mime)
}

// ------------------------------------------------------------------------------
// TS 24.379 clause 6.3.3.1.19 (TS 24.281, TS 24.282 likewise) and TS 24.380 clause 11: getInternalServiceConfig
// gives an MC service server the values of its service configuration document: the Resource-Priority header field
// values by priority, and for MCPTT the floor control timers.
func (svc *service) getInternalServiceConfig(writer http.ResponseWriter, request *http.Request) {
	if !svc.requireInternal(writer, request) {
		return
	}
	sc := svc.cfg.ServiceConfig
	values := func(rp ResourcePriorities) map[string]string {
		return map[string]string{"emergency": rp.Emergency, "imminent": rp.Imminent, "imminent_peril": rp.Imminent, "normal": rp.Normal}
	}
	switch request.URL.Query().Get("service") {
	case "mcptt":
		conf := sc.mcptt()
		// <floor-control-queue>/<depth> as the CMS publishes it to the clients (TS 24.484 clause 8.4.2.7 step 10).
		writeJSON(writer, http.StatusOK, map[string]any{"resource_priority": values(conf.ResourcePriority),
			"transmit_time_limit_ms": conf.TransmitTimeLimitMs, "floor_queue": conf.FloorQueue,
			"floor_queue_depth": max(conf.FloorQueueDepth, 1), "fc_timers_counters": conf.FloorTimers,
			"organization": svc.cfg.organization()})
	case "mcvideo":
		writeJSON(writer, http.StatusOK, map[string]any{"resource_priority": values(sc.mcvideo().ResourcePriority),
			"organization": svc.cfg.organization()})
	case "mcdata":
		conf := sc.mcdata()
		writeJSON(writer, http.StatusOK, map[string]any{"resource_priority": values(conf.ResourcePriority),
			"default_file_availability_s": conf.DefaultFileAvailabilityS, "max_file_availability_s": conf.MaxFileAvailabilityS})
	default:
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": "unknown service"})
	}
}

// ------------------------------------------------------------------------------
// TS 24.484 clauses 8.4.2.3, 9.4.2.3 and 10.4.2.3: checkServiceConfigDocuments validates the service configuration
// documents the CMS generates against their schemas.
func (svc *service) checkServiceConfigDocuments() error {
	if err := svc.cfg.ServiceConfig.Validate(); err != nil {
		return err
	}
	for _, auid := range []string{"org.3gpp.mcptt.service-config", "org.3gpp.mcvideo.service-config", "org.3gpp.mcdata.service-config"} {
		raw, _, schema, _ := svc.serviceConfigDocument(auid)
		if err := schemaError(schema.validate(raw)); err != nil {
			return fmt.Errorf("%s service configuration document: %w", auid, err)
		}
	}
	return nil
}
