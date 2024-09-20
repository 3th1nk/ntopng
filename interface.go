package ntopng

import (
	"fmt"
	"time"
)

const (
	urlInterfaceList              = "/lua/rest/v2/get/ntopng/interfaces.lua"
	urlInterfaceData              = "/lua/rest/v2/get/interface/data.lua"
	urlInterfaceAddress           = "/lua/rest/v2/get/interface/address.lua"
	urlInterfacePktDistro         = "/lua/if_pkt_distro.lua"
	urlInterfacePktTcpFlagsDistro = "/lua/if_tcpflags_pkt_distro.lua"
	urlInterfaceTcpStats          = "/lua/iface_tcp_stats.lua"
	urlInterfaceDSCPStats         = "/lua/rest/v2/get/interface/dscp/stats.lua"
	urlInterfaceL7Stats           = "/lua/rest/v2/get/interface/l7/stats.lua"
	urlInterfaceTopHosts          = "/lua/rest/v2/get/interface/top/hosts.lua" // Top主机(本地)
	urlInterfaceFind              = "/lua/rest/v2/get/host/find.lua"           // 查找对象
)

type Interface struct {
	ActiveDiscoveryActive bool  `json:"active_discovery_active,omitempty"`
	AlertedFlows          int64 `json:"alerted_flows,omitempty"`
	AlertedFlowsError     int64 `json:"alerted_flows_error,omitempty"`
	AlertedFlowsNotice    int64 `json:"alerted_flows_notice,omitempty"`
	AlertedFlowsWarning   int64 `json:"alerted_flows_warning,omitempty"`
	Bytes                 int64 `json:"bytes,omitempty"`
	BytesDownload         int64 `json:"bytes_download,omitempty"`
	BytesUpload           int64 `json:"bytes_upload,omitempty"`
	DownloadUploadChart   struct {
		Download []int64 `json:"download"`
		Upload   []int64 `json:"upload"`
	} `json:"download_upload_chart,omitempty"`
	DroppedAlerts                    int64       `json:"dropped_alerts,omitempty"`
	Drops                            int64       `json:"drops,omitempty"`
	EngagedAlerts                    int64       `json:"engaged_alerts,omitempty"`
	EngagedAlertsError               int64       `json:"engaged_alerts_error,omitempty"`
	EngagedAlertsNotice              int64       `json:"engaged_alerts_notice,omitempty"`
	EngagedAlertsWarning             int64       `json:"engaged_alerts_warning,omitempty"`
	Epoch                            int64       `json:"epoch,omitempty"`
	FlowDroppedAlerts                int64       `json:"flow_dropped_alerts,omitempty"`
	FlowsPctg                        int64       `json:"flows_pctg,omitempty"`
	HostDroppedAlerts                int64       `json:"host_dropped_alerts,omitempty"`
	HostsPctg                        int64       `json:"hosts_pctg,omitempty"`
	Ifid                             int64       `json:"ifid"`
	Ifname                           string      `json:"ifname"`
	IsView                           bool        `json:"is_view,omitempty"`
	Local2Remote                     int64       `json:"local2remote,omitempty"`
	Localtime                        string      `json:"localtime,omitempty"`
	MacsPctg                         int64       `json:"macs_pctg,omitempty"`
	NumDevices                       int64       `json:"num_devices,omitempty"`
	NumFlows                         int64       `json:"num_flows,omitempty"`
	NumHosts                         int64       `json:"num_hosts,omitempty"`
	NumLiveCaptures                  int64       `json:"num_live_captures,omitempty"`
	NumLocalHosts                    int64       `json:"num_local_hosts,omitempty"`
	NumLocalHostsAnomalies           int64       `json:"num_local_hosts_anomalies,omitempty"`
	NumLocalRcvdOnlyHosts            int64       `json:"num_local_rcvd_only_hosts,omitempty"`
	NumRcvdOnlyHosts                 int64       `json:"num_rcvd_only_hosts,omitempty"`
	NumRemoteHostsAnomalies          int64       `json:"num_remote_hosts_anomalies,omitempty"`
	OtherDroppedAlerts               int64       `json:"other_dropped_alerts,omitempty"`
	Packets                          int64       `json:"packets,omitempty"`
	PacketsDownload                  int64       `json:"packets_download,omitempty"`
	PacketsUpload                    int64       `json:"packets_upload,omitempty"`
	PeriodicStatsUpdateFrequencySecs int64       `json:"periodic_stats_update_frequency_secs,omitempty"`
	Profiles                         interface{} `json:"profiles,omitempty"`
	Remote2Local                     int64       `json:"remote2local,omitempty"`
	RemoteBps                        float64     `json:"remote_bps,omitempty"`
	RemotePps                        float64     `json:"remote_pps,omitempty"`
	Speed                            int64       `json:"speed,omitempty"` // Mbps
	SystemHostStats                  struct {
		AlertsQueries int64 `json:"alerts_queries,omitempty"`
		AlertsStats   struct {
			AlertQueues struct {
				InternalAlertsQueue struct {
					PctNotEnqueued int64 `json:"pct_not_enqueued,omitempty"`
				} `json:"internal_alerts_queue,omitempty"`
			} `json:"alert_queues,omitempty"`
		} `json:"alerts_stats,omitempty"`
		CpuLoad   float64 `json:"cpu_load,omitempty"`
		CpuStates struct {
			Guest     float64 `json:"guest,omitempty"`
			GuestNice float64 `json:"guest_nice,omitempty"`
			Idle      float64 `json:"idle,omitempty"`
			Iowait    float64 `json:"iowait,omitempty"`
			Irq       float64 `json:"irq,omitempty"`
			Nice      float64 `json:"nice,omitempty"`
			Softirq   float64 `json:"softirq,omitempty"`
			Steal     float64 `json:"steal,omitempty"`
			System    float64 `json:"system,omitempty"`
			User      float64 `json:"user,omitempty"`
		} `json:"cpu_states,omitempty"`
		DroppedAlerts     int64 `json:"dropped_alerts,omitempty"`
		MemBuffers        int64 `json:"mem_buffers,omitempty"`
		MemCached         int64 `json:"mem_cached,omitempty"`
		MemFree           int64 `json:"mem_free,omitempty"`
		MemNtopngResident int64 `json:"mem_ntopng_resident,omitempty"`
		MemNtopngVirtual  int64 `json:"mem_ntopng_virtual,omitempty"`
		MemShmem          int64 `json:"mem_shmem,omitempty"`
		MemSreclaimable   int64 `json:"mem_sreclaimable,omitempty"`
		MemTotal          int64 `json:"mem_total,omitempty"`
		MemUsed           int64 `json:"mem_used,omitempty"`
		WrittenAlerts     int64 `json:"written_alerts,omitempty"`
	} `json:"system_host_stats,omitempty"`
	TcpPacketStats struct {
		Lost            int64 `json:"lost,omitempty"`            // 丢失包数量
		OutOfOrder      int64 `json:"out_of_order,omitempty"`    // 乱序包数量
		Retransmissions int64 `json:"retransmissions,omitempty"` // 重传包数量
	} `json:"tcpPacketStats,omitempty"` // TCP数据包分析
	Throughput struct {
		Download struct {
			Bps float64 `json:"bps,omitempty"`
			Pps float64 `json:"pps,omitempty"`
		} `json:"download,omitempty"`
		Upload struct {
			Bps float64 `json:"bps,omitempty"`
			Pps float64 `json:"pps,omitempty"`
		} `json:"upload,omitempty"`
	} `json:"throughput,omitempty"`
	ThroughputBps             float64 `json:"throughput_bps,omitempty"`
	ThroughputPps             float64 `json:"throughput_pps,omitempty"`
	TrafficExtractionNumTasks int64   `json:"traffic_extraction_num_tasks,omitempty"`
	TrafficRecording          string  `json:"traffic_recording,omitempty"`
	Uptime                    string  `json:"uptime,omitempty"`
}

func (this *Ntopng) GetInterfaceList() ([]*Interface, error) {
	bs, err := this.Get(urlInterfaceList, nil, nil)
	if err != nil {
		return nil, err
	}

	var arr []*Interface
	if err = UnmarshalRsp(bs, &arr); err != nil {
		return nil, err
	}
	return arr, nil
}

func (this *Ntopng) GetInterface(ifId int64) (*Interface, error) {
	bs, err := this.Get(urlInterfaceData, nil, map[string]interface{}{
		"ifid": ifId,
	})
	if err != nil {
		return nil, err
	}
	fmt.Println(string(bs))

	var result Interface
	if err = UnmarshalRsp(bs, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

type InterfaceSummary struct {
	ActiveDiscoveryActive bool   `json:"active_discovery_active,omitempty"`
	AlertedFlows          int64  `json:"alerted_flows,omitempty"`
	AlertedFlowsError     int64  `json:"alerted_flows_error,omitempty"`
	AlertedFlowsWarning   int64  `json:"alerted_flows_warning,omitempty"`
	Drops                 int64  `json:"drops,omitempty"`
	EngagedAlerts         int64  `json:"engaged_alerts,omitempty"`
	EngagedAlertsError    int64  `json:"engaged_alerts_error,omitempty"`
	EngagedAlertsWarning  int64  `json:"engaged_alerts_warning,omitempty"`
	FlowsPctg             int64  `json:"flows_pctg,omitempty"`
	HostsPctg             int64  `json:"hosts_pctg,omitempty"`
	Ifid                  int64  `json:"ifid"`
	Ifname                string `json:"ifname"`
	Localtime             string `json:"localtime,omitempty"`
	MacsPctg              int64  `json:"macs_pctg,omitempty"`
	NumDevices            int64  `json:"num_devices,omitempty"`
	NumFlows              int64  `json:"num_flows,omitempty"`
	NumHosts              int64  `json:"num_hosts,omitempty"`
	NumLiveCaptures       int64  `json:"num_live_captures,omitempty"`
	NumLocalHosts         int64  `json:"num_local_hosts,omitempty"`
	NumLocalRcvdOnlyHosts int64  `json:"num_local_rcvd_only_hosts,omitempty"`
	NumRcvdOnlyHosts      int64  `json:"num_rcvd_only_hosts,omitempty"`
	Throughput            struct {
		Download float64 `json:"download,omitempty"`
		Upload   float64 `json:"upload,omitempty"`
	} `json:"throughput,omitempty"`
	ThroughputBps             float64 `json:"throughput_bps,omitempty"`
	TrafficExtractionNumTasks int64   `json:"traffic_extraction_num_tasks,omitempty"`
	TrafficRecording          string  `json:"traffic_recording,omitempty"`
	Uptime                    string  `json:"uptime,omitempty"`
}

func (this *Ntopng) GetInterfaceSummary(ifId int64) (*InterfaceSummary, error) {
	bs, err := this.Get(urlInterfaceData, nil, map[string]interface{}{
		"ifid": ifId,
		"type": "summary",
	})
	if err != nil {
		return nil, err
	}

	var result InterfaceSummary
	if err = UnmarshalRsp(bs, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (this *Ntopng) GetInterfaceAddress(ifId int64) ([]string, error) {
	bs, err := this.Get(urlInterfaceAddress, nil, map[string]interface{}{
		"ifid": ifId,
	})
	if err != nil {
		return nil, err
	}

	var result struct {
		Addresses []string `json:"addresses"`
	}
	if err = UnmarshalRsp(bs, &result); err != nil {
		return nil, err
	}
	return result.Addresses, nil
}

type LabelValue struct {
	Label string  `json:"label"`
	Value float64 `json:"value"`
	Color string  `json:"color,omitempty"`
}

type IfDistroReq struct {
	IfId int64 `json:"ifid"`
	Type IfDistroType
}

// GetInterfaceDistro 接口数据分布情况
func (this *Ntopng) GetInterfaceDistro(req *IfDistroReq) ([]*LabelValue, error) {
	var path string
	var isUnmarshalRsp bool
	query := map[string]interface{}{"ifid": req.IfId}
	switch req.Type {
	default:
		return nil, fmt.Errorf("unsupported interface distro type: %s", req.Type)

	case IfDistroTypePktSize, IfDistroTypePktIpVer:
		path = urlInterfacePktDistro
		query["distr"] = string(req.Type)

	case IfDistroTypePktTcpFlags:
		path = urlInterfacePktTcpFlagsDistro

	case IfDistroTypeDSCP:
		path = urlInterfaceDSCPStats
		isUnmarshalRsp = true

	case IfDistroTypeL7SinceStartup:
		path = urlInterfaceL7Stats
		query["ndpistats_mode"] = "sinceStartup"
		isUnmarshalRsp = true

	case IfDistroTypeL7BreedSinceStartup:
		path = urlInterfaceL7Stats
		query["ndpistats_mode"] = "sinceStartup"
		query["breed"] = true
		isUnmarshalRsp = true

	case IfDistroTypeL7BreedCount:
		path = urlInterfaceL7Stats
		query["ndpistats_mode"] = "count"
		query["breed"] = true
		isUnmarshalRsp = true

	case IfDistroTypeL7Category:
		path = urlInterfaceL7Stats
		query["ndpistats_mode"] = "sinceStartup"
		query["ndpi_category"] = true
		isUnmarshalRsp = true

	case IfDistroTypeTcpStats:
		path = urlInterfaceTcpStats

	case IfDistroTypeTopHosts:
		path = urlInterfaceTopHosts
		nowUnix := time.Now().Unix()
		query["epoch_begin"] = nowUnix - 300
		query["epoch_end"] = nowUnix
		isUnmarshalRsp = true
	}

	bs, err := this.Get(path, nil, query)
	if err != nil {
		return nil, err
	}

	var arr []*LabelValue
	if isUnmarshalRsp {
		err = UnmarshalRsp(bs, &arr)
	} else {
		err = UnmarshalRaw(bs, &arr)
	}
	if err != nil {
		return nil, err
	}

	return arr, nil
}

type FindReq struct {
	IfId  int64  `json:"ifid"`
	Query string `json:"query"`
}

type FindResp struct {
	Interface string    `json:"interface"` // 接口名称
	Results   []*Object `json:"results"`   // 搜索结果
}

type Object struct {
	Type    string `json:"type"`              // 对象类型 network、mac、asn、ip等
	Name    string `json:"name"`              // 显示名称
	Network int    `json:"network,omitempty"` // 网络ID
	Mac     string `json:"mac,omitempty"`     // MAC地址
	ASN     int    `json:"asn,omitempty"`     // ASN
	IP      string `json:"ip,omitempty"`      // 主机IP
}

func (this *Ntopng) Find(req *FindReq) (*FindResp, error) {
	bs, err := this.Get(urlInterfaceFind, nil, map[string]interface{}{
		"ifid":  req.IfId,
		"query": req.Query,
	})
	if err != nil {
		return nil, err
	}

	var resp FindResp
	if err = UnmarshalRsp(bs, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
