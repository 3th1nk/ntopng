package ntopng

import (
	"fmt"
	"strings"
	"time"
)

const (
	urlTsTypeConst = "/lua/rest/v2/get/timeseries/type/consts.lua" // 查询指标列表
	urlTsData      = "/lua/rest/v2/get/timeseries/ts.lua"          // 查询时序数据
)

type TsTypeConstReq struct {
	IfId  int64  `json:"ifid"`
	Query string `json:"query"` // 查询类型：iface, host, mac, subnet, asn, country, os, vlan, host_pool, pod, container, ht, system, profile, redis, influxdb, am, snmp_interface, snmp_device, obs_point, sflowdev_port, flowdev, flowdev_port
	Host  string `json:"host,omitempty"`
	Pool  int64  `json:"pool,omitempty"`
	VLAN  int64  `json:"vlan,omitempty"`
	ASN   int64  `json:"asn,omitempty"`
	Mac   string `json:"mac,omitempty"`
}

type TsTypeConst struct {
	Id             string                 `json:"id"`
	Group          string                 `json:"group,omitempty"` // 分组
	Scale          string                 `json:"scale"`
	Query          string                 `json:"query,omitempty"`
	Schema         string                 `json:"schema"`
	Label          string                 `json:"label"`        // 名称
	MeasureUnit    string                 `json:"measure_unit"` // 单位
	Priority       int                    `json:"priority"`     // 顺序
	DefaultVisible bool                   `json:"default_visible,omitempty"`
	AlwaysVisible  bool                   `json:"alwais_visibile,omitempty"` // 注：接口原始返回字段拼写错误
	Timeseries     map[string]interface{} `json:"timeseries"`
}

func (this *Ntopng) GetTsTypeConst(req *TsTypeConstReq) ([]*TsTypeConst, error) {
	query := map[string]interface{}{
		"ifid":  req.IfId,
		"query": req.Query,
	}
	if req.Host != "" {
		query["host"] = req.Host
	}
	if req.Pool > 0 {
		query["pool"] = req.Pool
	}
	if req.VLAN > 0 {
		query["vlan"] = req.VLAN
	}
	if req.ASN > 0 {
		query["asn"] = req.ASN
	}
	if req.Mac != "" {
		query["mac"] = req.Mac
	}
	bs, err := this.Get(urlTsTypeConst, nil, query)
	if err != nil {
		return nil, err
	}

	var arr []*TsTypeConst
	if err = UnmarshalRsp(bs, &arr); err != nil {
		return nil, err
	}
	return arr, err
}

type TsDataReq struct {
	Schema    string                 `json:"schema"` // 查询类型
	Query     map[string]interface{} `json:"query"`  // 查询条件
	TsKey     interface{}            `json:"tskey"`  // 查询对象唯一标识，比如接口ID、主机IP
	BeginTime time.Time              `json:"begin_time,omitempty"`
	EndTime   time.Time              `json:"end_time,omitempty"`
	Limit     int                    `json:"limit,omitempty"`
	Zoom      string                 `json:"zoom,omitempty"`
	TsCompare string                 `json:"ts_compare,omitempty"`
	Version   IPVersion              `json:"version,omitempty"`
}

func (r *TsDataReq) defaultIfEmpty() {
	if r.BeginTime.IsZero() && r.EndTime.IsZero() {
		nowUnix := time.Now()
		r.BeginTime = nowUnix.Add(-30 * time.Minute)
		r.EndTime = nowUnix
	}
	if r.Limit == 0 {
		r.Limit = 180
	}
	if r.Zoom == "" {
		r.Zoom = "30m"
	}
	if r.TsCompare == "" {
		r.TsCompare = "30m"
	}
	if r.Version == 0 {
		r.Version = IPVersion4
	}
}

type TsDataResp struct {
	Metadata struct {
		Query      map[string]interface{} `json:"query"`
		Schema     string                 `json:"schema"`
		NumPoint   int64                  `json:"num_point"`
		EpochBegin int64                  `json:"epoch_begin"`
		EpochEnd   int64                  `json:"epoch_end"`
		EpochStep  int64                  `json:"epoch_step"`
	} `json:"metadata"`
	Series           []*Series              `json:"series"`
	AdditionalSeries map[string]interface{} `json:"additional_series"`
}

type Series struct {
	Id         string    `json:"id"`
	Data       []float64 `json:"data"`
	Statistics struct {
		Total     float64 `json:"total"`
		P95       float64 `json:"95th_percentile"`
		Average   float64 `json:"average"`
		MaxVal    float64 `json:"max_val"`
		MaxValIdx int     `json:"max_val_idx"`
		MinVal    float64 `json:"min_val"`
		MinValIdx int     `json:"min_val_idx"`
	} `json:"statistics"`
}

func (this *Ntopng) GetTsData(req *TsDataReq) (*TsDataResp, error) {
	req.defaultIfEmpty()
	var queryArgs []string
	for k, v := range req.Query {
		queryArgs = append(queryArgs, fmt.Sprintf("%s:%v", k, v))
	}
	query := map[string]interface{}{
		"ts_schema":   req.Schema,
		"ts_query":    strings.Join(queryArgs, ","),
		"tskey":       req.TsKey,
		"epoch_begin": req.BeginTime.Unix(),
		"epoch_end":   req.EndTime.Unix(),
		"limit":       req.Limit,
		"zoom":        req.Zoom,
		"ts_compare":  req.TsCompare,
		"version":     req.Version,
	}
	bs, err := this.Get(urlTsData, nil, query)
	if err != nil {
		return nil, err
	}

	var resp TsDataResp
	if err = UnmarshalRsp(bs, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
