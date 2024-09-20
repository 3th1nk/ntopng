package ntopng

import (
	"github.com/antchfx/htmlquery"
	"regexp"
	"strings"
	"time"
)

const (
	urlFlowsData  = "/lua/get_flows_data.lua"
	urlFlowStats  = "/lua/flow_stats.lua"
	urlFlowActive = "/lua/rest/v2/get/flow/active.lua"
)

type FlowReq struct {
	BasePageReq
	IfId              int64             `json:"ifid"`
	FlowHostsType     FlowHostType      `json:"flowhosts_type,omitempty"`
	AlertType         AlertType         `json:"alert_type,omitempty"`
	AlertTypeSeverity AlertTypeSeverity `json:"alert_type_severity,omitempty"`
	TrafficType       TrafficType       `json:"traffic_type,omitempty"`
	Host              string            `json:"host,omitempty"`         // 主机IP
	Application       string            `json:"application,omitempty"`  // 应用程序
	Category          string            `json:"category,omitempty"`     // 应用程序类别
	DSCP              *int              `json:"dscp,omitempty"`         // DSCP有效值0-63
	HostPoolId        *int              `json:"host_pool_id,omitempty"` // 主机池ID
	Network           *int              `json:"network,omitempty"`      // 网络ID
	Version           IPVersion         `json:"version,omitempty"`      // IP版本
	L4Proto           L4Proto           `json:"l4_proto,omitempty"`     // 协议
}

func (r *FlowReq) defaultIfEmpty() {
	r.BasePageReq.defaultIfEmpty()
	if r.SortColumn == "" {
		r.SortColumn = "column_ndpi"
	}
}

type FlowResp struct {
	BasePageResp
	Data []*Flow `json:"data"`
}

type Flow struct {
	KeyAndHash      string  `json:"key_and_hash"`
	Key             string  `json:"key"`
	HashId          string  `json:"hash_id"`
	ColumnKey       string  `json:"column_key"`
	ColumnNdpi      string  `json:"column_ndpi"`
	ColumnProtoL4   string  `json:"column_proto_l4"`
	ColumnClient    string  `json:"column_client"`
	ColumnServer    string  `json:"column_server"`
	ColumnBreakdown string  `json:"column_breakdown"`
	ColumnDuration  string  `json:"column_duration"`
	ColumnThpt      float64 `json:"column_thpt"`  // 当前流量，单位:bps
	ColumnBytes     int64   `json:"column_bytes"` // 总字节数，单位:byte
	ColumnInfo      string  `json:"column_info"`
	ColumnFirstSeen string  `json:"column_first_seen"`
	ColumnLastSeen  string  `json:"column_last_seen"`
}

func (f Flow) Id() string {
	return f.HashId
}

func (f Flow) Application() string {
	return getFirstHtmlInnerText(f.ColumnNdpi, "//a")
}

func (f Flow) Protocol() string {
	// 原始返回数据有可能带后缀：
	//	TCP
	//	UDP
	//	TCP <i class='fa-fw fas fa-info-circle text-info' title='TLS（可能）不携带 HTTPS'></i>
	// 	TCP <i class='fa-fw fas fa-exclamation-triangle text-warning' title='在非标准端口上的应用程序'></i>
	return trimRightTag(f.ColumnProtoL4, "<i")
}

func (f Flow) parseAddr(htmlStr string) string {
	doc, err := htmlquery.Parse(strings.NewReader(htmlStr))
	if err != nil {
		return ""
	}

	hostNode := htmlquery.FindOne(doc, "//a[contains(@href, 'host_details.lua')]")
	portNode := htmlquery.FindOne(doc, "//a[contains(@href, 'flows_stats.lua')]")

	var portProtoStr, portHref string
	if portNode != nil {
		portProtoStr = htmlquery.InnerText(portNode)
		portHref = htmlquery.SelectAttr(portNode, "href")
	}

	re := regexp.MustCompile(`port=(\d+)`)
	if match := re.FindStringSubmatch(portHref); len(match) > 1 && match[1] != portProtoStr {
		return htmlquery.InnerText(hostNode) + ":" + match[1] + "|" + portProtoStr
	}
	return htmlquery.InnerText(hostNode) + ":" + portProtoStr
}

func (f Flow) Client() string {
	return f.parseAddr(f.ColumnClient)
}

func (f Flow) Server() string {
	return f.parseAddr(f.ColumnServer)
}

func (f Flow) Duration() string {
	return f.ColumnDuration
}

// Breakdown client和server流量占比
func (f Flow) Breakdown() []float64 {
	return getProgressBarDivWidth(f.ColumnBreakdown)
}

func (f Flow) Thpt() float64 {
	return f.ColumnThpt
}

func (f Flow) Traffic() int64 {
	return f.ColumnBytes
}

func (f Flow) Info() string {
	return f.ColumnInfo
}

func (f Flow) FirstSeenTime() time.Time {
	t, _ := time.ParseInLocation("01/02/2006 15:04:05", f.ColumnFirstSeen, time.Local)
	return t
}

func (f Flow) LastSeenTime() time.Time {
	t, _ := time.ParseInLocation("01/02/2006 15:04:05", f.ColumnLastSeen, time.Local)
	return t
}

// GetFlowList 活动流列表
func (this *Ntopng) GetFlowList(req *FlowReq) (*FlowResp, error) {
	req.defaultIfEmpty()
	query := map[string]interface{}{
		"ifid":        req.IfId,
		"currentPage": req.CurrentPage,
		"perPage":     req.PerPage,
		"sortColumn":  req.SortColumn,
		"sortOrder":   req.SortOrder,
	}
	if req.FlowHostsType != FlowHostTypeAll {
		query["flowhosts_type"] = req.FlowHostsType
	}
	if req.AlertType != AlertTypeAll {
		query["alert_type"] = req.AlertType
	}
	if req.AlertTypeSeverity != AlertTypeSeverityAll {
		query["alert_type_severity"] = req.AlertTypeSeverity
	}
	if req.TrafficType != TrafficTypeAll {
		query["traffic_type"] = req.TrafficType
	}
	if req.Host != "" {
		query["host"] = req.Host
	}
	if req.Application != "" {
		query["application"] = req.Application
	}
	if req.Category != "" {
		query["category"] = req.Category
	}
	if req.DSCP != nil {
		query["dscp"] = *req.DSCP
	}
	if req.HostPoolId != nil {
		query["host_pool_id"] = *req.HostPoolId
	}
	if req.Network != nil {
		query["network"] = *req.Network
	}
	if req.Version != IPVersionAll {
		query["version"] = req.Version
	}
	if req.L4Proto != L4ProtoAll {
		query["l4_proto"] = req.L4Proto
	}
	bs, err := this.Get(urlFlowsData, nil, query)
	if err != nil {
		return nil, err
	}

	var resp FlowResp
	if err = UnmarshalRaw(bs, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

type FlowStatsReq struct {
	IfId   int64  `json:"ifid"`
	Key    string `json:"key"`
	HashId string `json:"hash_id"`
}

type FlowStatsResp struct {
	SeenLast             string  `json:"seen.last"`
	SeenFirst            string  `json:"seen.first"`
	SeenDuration         string  `json:"seen.duration"`
	Bytes                int64   `json:"bytes"`
	GoodputBytes         int64   `json:"goodput_bytes"`
	Cli2SrvPackets       int64   `json:"cli2srv.packets"`
	Srv2CliPackets       int64   `json:"srv2cli.packets"`
	Cli2SrvBytes         int64   `json:"cli2srv.bytes"`
	Srv2CliBytes         int64   `json:"srv2cli.bytes"`
	Throughput           string  `json:"throughput"`
	TopThroughputDisplay string  `json:"top_throughput_display"`
	ThroughputRaw        float64 `json:"throughput_raw"`
	C2SOOO               int64   `json:"c2sOOO"`
	C2Slost              int64   `json:"c2slost"`
	C2SkeepAlive         int64   `json:"c2skeep_alive"`
	C2Sretr              int64   `json:"c2sretr"`
	S2COOO               int64   `json:"s2cOOO"`
	S2Clost              int64   `json:"s2clost"`
	S2CkeepAlive         int64   `json:"s2ckeep_alive"`
	S2Cretr              int64   `json:"s2cretr"`
}

func (this *Ntopng) GetFlowStats(req *FlowStatsReq) (*FlowStatsResp, error) {
	bs, err := this.Get(urlFlowStats, nil, map[string]interface{}{
		"ifid":         req.IfId,
		"flow_key":     req.Key,
		"flow_hash_id": req.HashId,
	})
	if err != nil {
		return nil, err
	}

	var resp FlowStatsResp
	if err = UnmarshalRaw(bs, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

type ActiveFlowResp struct {
	BasePageResp
	Data []*ActiveFlow `json:"data"`
}

type ActiveFlow struct {
	Key       string  `json:"key"`
	HashId    string  `json:"hash_id"`
	FirstSeen int64   `json:"first_seen"`
	LastSeen  int64   `json:"last_seen"`
	Bytes     float64 `json:"bytes"`
	Duration  int64   `json:"duration"`
	Vlan      int     `json:"vlan"`

	Client struct {
		Ip                string `json:"ip,omitempty"`
		IsBlacklisted     bool   `json:"is_blacklisted,omitempty"`
		IsBroadcastDomain bool   `json:"is_broadcast_domain,omitempty"`
		Port              int    `json:"port,omitempty"`
		IsDhcp            bool   `json:"is_dhcp,omitempty"`
		Name              string `json:"name,omitempty"`
	} `json:"client,omitempty"`

	Server struct {
		Ip            string `json:"ip"`
		IsBlacklisted bool   `json:"is_blacklisted"`
		IsDhcp        bool   `json:"is_dhcp"`
		Port          int    `json:"port"`
		Name          string `json:"name"`
		IsBroadcast   bool   `json:"is_broadcast"`
	}

	Breakdown struct {
		Srv2Cli float64 `json:"srv2cli"`
		Cli2Srv float64 `json:"cli2srv"`
	} `json:"breakdown"`

	Thpt struct {
		Pps float64 `json:"pps"`
		Bps float64 `json:"bps"`
	} `json:"thpt"`

	Protocol struct {
		L4 string `json:"l4"`
		L7 string `json:"l7"`
	} `json:"protocol"`
}

func (this *Ntopng) GetActiveFlows(req *FlowReq) (*ActiveFlowResp, error) {
	req.defaultIfEmpty()
	query := map[string]interface{}{
		"ifid":        req.IfId,
		"currentPage": req.CurrentPage,
		"perPage":     req.PerPage,
		"sortColumn":  req.SortColumn,
		"sortOrder":   req.SortOrder,
	}
	if req.FlowHostsType != FlowHostTypeAll {
		query["flowhosts_type"] = req.FlowHostsType
	}
	if req.AlertType != AlertTypeAll {
		query["alert_type"] = req.AlertType
	}
	if req.AlertTypeSeverity != AlertTypeSeverityAll {
		query["alert_type_severity"] = req.AlertTypeSeverity
	}
	if req.TrafficType != TrafficTypeAll {
		query["traffic_type"] = req.TrafficType
	}
	if req.Host != "" {
		query["host"] = req.Host
	}
	if req.Application != "" {
		query["application"] = req.Application
	}
	if req.Category != "" {
		query["category"] = req.Category
	}
	if req.DSCP != nil {
		query["dscp"] = *req.DSCP
	}
	if req.HostPoolId != nil {
		query["host_pool_id"] = *req.HostPoolId
	}
	if req.Network != nil {
		query["network"] = *req.Network
	}
	if req.Version != IPVersionAll {
		query["version"] = req.Version
	}
	if req.L4Proto != L4ProtoAll {
		query["l4proto"] = req.L4Proto
	}

	bs, err := this.Get(urlFlowActive, nil, query)
	if err != nil {
		return nil, err
	}

	var resp ActiveFlowResp
	if err = UnmarshalRsp(bs, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}
