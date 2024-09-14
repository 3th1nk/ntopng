package ntopng

import "fmt"

const (
	urlHostsData                 = "/lua/get_hosts_data.lua"                           // 所有主机
	urlHostStats                 = "/lua/host_stats.lua"                               // 主机状态
	urlHostL4TrafficDistro       = "/lua/rest/v2/get/host/l4/traffic_data.lua"         // 主机统计数据-L4发送、接收流量
	urlHostL4ProtoDistro         = "/lua/rest/v2/get/host/l4/proto_data.lua"           // 主机统计数据-L4协议流量
	urlHostL4ConnectedHostDistro = "/lua/rest/v2/get/host/l4/contacted_hosts_data.lua" // 主机统计数据-L4连接
	urlHostL4Data                = "/lua/rest/v2/get/host/l4/data.lua"                 // 主机L4流量列表
	urlHostL7ProtoDistro         = "/lua/rest/v2/get/host/l7/proto_data.lua"           // 主机统计数据-L7协议流量
	urlHostL7BreedDistro         = "/lua/rest/v2/get/host/l7/breed_data.lua"           // 主机统计数据-L7应用流量
	urlHostL7Data                = "/lua/rest/v2/get/host/l7/data.lua"                 // 主机L7流量列表
	urlHostPktSendSizeDistro     = "/lua/rest/v2/get/host/packets/sent_data.lua"       // 主机统计数据-发送数据包大小
	urlHostPktRcvdSizeDistro     = "/lua/rest/v2/get/host/packets/rcvd_data.lua"       // 主机统计数据-接收数据包大小
	urlHostPktTcpFlagsDistro     = "/lua/rest/v2/get/host/packets/tcp_flags_data.lua"  // 主机统计数据-TCP标志
	urlHostPktArpDistro          = "/lua/rest/v2/get/host/packets/arp_data.lua"        // 主机统计数据-ARP数据包
	urlHostPortTrafficDistro     = "/lua/iface_ports_list.lua"                         // 主机统计数据-端口统计
	urlHostTopPeersProtocols     = "/lua/host_top_peers_protocols.lua"                 // 主机统计数据- Top peers
	urlHostDnsBreakdown          = "/lua/host_dns_breakdown.lua"                       // 主机统计数据-DNS查询发送、接收分布
	urlHostHttpBreakdown         = "/lua/host_http_breakdown.lua"                      // 主机统计数据-HTTP发送查询、接收响应分布
	urlHostFingerprintData       = "/lua/rest/v2/get/host/fingerprint/data.lua"        // TLS JA3客户端指纹
	urlMacsData                  = "/lua/get_macs_data.lua"                            // 按MAC地址划分主机
	urlNetworksData              = "/lua/get_networks_data.lua"                        // 按网络划分主机
	urlHostPoolsData             = "/lua/get_pools_data.lua"                           // 按主机池划分主机
	urlASesData                  = "/lua/get_ases_data.lua"                            // 按自治系统划分主机
	urlCountriesData             = "/lua/get_countries_data.lua"                       // 按国家划分主机
	urlOSesData                  = "/lua/get_oses_data.lua"                            // 按操作系统划分主机
)

type HostReq struct {
	BasePageReq
	Version     IPVersion   `json:"version,omitempty"`      // IP版本
	TrafficType TrafficType `json:"traffic_type,omitempty"` // 流量方向
	HostMode    HostMode    `json:"mode,omitempty"`         // 过滤主机
}

func (r *HostReq) defaultIfEmpty() {
	r.BasePageReq.defaultIfEmpty()
	if r.SortColumn == "" {
		r.SortColumn = "column_traffic_sent"
	}
}

type HostResp struct {
	BasePageResp
	Data []*Host `json:"data"`
}

type Host struct {
	ColumnBreakdown   string `json:"column_breakdown"`
	ColumnUrl         string `json:"column_url"`
	ColumnIp          string `json:"column_ip"`
	ColumnScore       string `json:"column_score"`
	ColumnNumFlows    string `json:"column_num_flows"`
	ColumnTrafficSent string `json:"column_traffic_sent"`
	Key               string `json:"key"`
	ColumnName        string `json:"column_name"`
	ColumnAlerts      string `json:"column_alerts"`
	ColumnTraffic     string `json:"column_traffic"`
	ColumnLast        string `json:"column_last"`
	ColumnThpt        string `json:"column_thpt"`
	ColumnInfo        string `json:"column_info"`
	ColumnSince       string `json:"column_since"`
}

func (h Host) IP() string {
	return getFirstHtmlInnerText(h.ColumnIp, "//a")
}

func (h Host) NumFlows() int {
	return strNumToInt(h.ColumnNumFlows)
}

// TrafficSent 发送的总字节数，带单位的字符串
func (h Host) TrafficSent() string {
	return h.ColumnTrafficSent
}

// Traffic 总字节数，带单位的字符串
func (h Host) Traffic() string {
	return h.ColumnTraffic
}

func (h Host) Name() string {
	return h.ColumnName
}

func (h Host) Since() string {
	return h.ColumnSince
}

func (h Host) Alerts() int {
	return strNumToInt(h.ColumnAlerts)
}

func (h Host) Score() int {
	return strNumToInt(h.ColumnScore)
}

// Breakdown sent和rcvd流量占比
func (h Host) Breakdown() []float64 {
	return getProgressBarDivWidth(h.ColumnBreakdown)
}

// Thpt 吞吐量，带单位的字符串
func (h Host) Thpt() string {
	return trimRightTag(h.ColumnThpt, "<i")
}

func (this *Ntopng) GetHostList(req *HostReq) (*HostResp, error) {
	req.defaultIfEmpty()
	query := map[string]interface{}{
		"currentPage": req.CurrentPage,
		"perPage":     req.PerPage,
		"sortColumn":  req.SortColumn,
		"sortOrder":   req.SortOrder,
	}
	if req.Version != IPVersionAll {
		query["version"] = req.Version
	}
	if req.TrafficType != TrafficTypeAll {
		query["traffic_type"] = req.TrafficType
	}
	if req.HostMode != HostModeAll {
		query["mode"] = req.HostMode
	}
	bs, err := this.Get(urlHostsData, nil, query)
	if err != nil {
		return nil, err
	}

	var resp HostResp
	if err = UnmarshalRaw(bs, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

type HostStats struct {
	Systemhost                   bool        `json:"systemhost"`
	ThroughputTrendBps           int64       `json:"throughput_trend_bps"`
	Asn                          int64       `json:"asn"`
	UdpBytesSent                 int64       `json:"udp.bytes.sent"`
	Os                           int64       `json:"os"`
	UdpBytesRcvd                 int64       `json:"udp.bytes.rcvd"`
	ContactsAsClient             int64       `json:"contacts.as_client"`
	Name                         string      `json:"name"`
	HostUnreachableFlowsAsServer int64       `json:"host_unreachable_flows.as_server"`
	AlertedFlowsAsServer         int64       `json:"alerted_flows.as_server"`
	IcmpBytesRcvdAnomalyIndex    int64       `json:"icmp.bytes.rcvd.anomaly_index"`
	ThroughputBps                float64     `json:"throughput_bps"`
	HasshFingerprint             interface{} `json:"hassh_fingerprint"`
	Ifid                         int         `json:"ifid"`
	Ja3Fingerprint               interface{} `json:"ja3_fingerprint"`
	FlowsAsServer                int64       `json:"flows.as_server"`
	ActiveFlowsAsServer          int64       `json:"active_flows.as_server"`
	OtherIpPacketsRcvd           int64       `json:"other_ip.packets.rcvd"`
	Localhost                    bool        `json:"localhost"`
	Duration                     int64       `json:"duration"`
	City                         string      `json:"city"`
	Ipkey                        int64       `json:"ipkey"`
	SeenLast                     int64       `json:"seen.last"`
	BytesSent                    int64       `json:"bytes.sent"`
	SeenFirst                    int64       `json:"seen.first"`
	TcpPacketStatsSent           struct {
		Lost            int64 `json:"lost"`
		KeepAlive       int64 `json:"keep_alive"`
		OutOfOrder      int64 `json:"out_of_order"`
		Retransmissions int64 `json:"retransmissions"`
	} `json:"tcpPacketStats.sent"`
	OtherIpBytesRcvd int64 `json:"other_ip.bytes.rcvd"`
	Privatehost      bool  `json:"privatehost"`
	NdpiCategories   map[string]struct {
		Duration  int64 `json:"duration"`
		Category  int64 `json:"category"`
		Bytes     int64 `json:"bytes"`
		BytesRcvd int64 `json:"bytes.rcvd"`
		BytesSent int64 `json:"bytes.sent"`
	} `json:"ndpi_categories"`
	Names                        interface{} `json:"names"`
	HostUnreachableFlowsAsClient int64       `json:"host_unreachable_flows.as_client"`
	ThroughputPps                float64     `json:"throughput_pps"`
	ScoreAsClient                int64       `json:"score.as_client"`
	TcpPacketStatsRcvd           struct {
		Lost            int64 `json:"lost"`
		KeepAlive       int64 `json:"keep_alive"`
		OutOfOrder      int64 `json:"out_of_order"`
		Retransmissions int64 `json:"retransmissions"`
	} `json:"tcpPacketStats.rcvd"`
	UnreachableFlowsAsServer int `json:"unreachable_flows.as_server"`
	ScorePct                 struct {
		ScoreBreakdownServer map[string]interface{} `json:"score_breakdown_server"`
		ScoreBreakdownClient map[string]interface{} `json:"score_breakdown_client"`
	} `json:"score_pct"`
	IcmpBytesSent             int64  `json:"icmp.bytes.sent"`
	OsDetail                  string `json:"os_detail"`
	NumUnidirectionalTcpFlows struct {
		NumEgress  int64 `json:"num_egress"`
		NumIngress int64 `json:"num_ingress"`
	} `json:"num_unidirectional_tcp_flows"`
	TcpBytesSentAnomalyIndex                      int64   `json:"tcp.bytes.sent.anomaly_index"`
	TcpPacketsSent                                int64   `json:"tcp.packets.sent"`
	IcmpBytesRcvd                                 int64   `json:"icmp.bytes.rcvd"`
	TcpBytesRcvdAnomalyIndex                      int64   `json:"tcp.bytes.rcvd.anomaly_index"`
	NumIncomingPeersThatSentTcpUdpFlowsNoResponse int64   `json:"num_incoming_peers_that_sent_tcp_udp_flows_no_response"`
	Latitude                                      float64 `json:"latitude"`
	ActiveAlertedFlows                            int64   `json:"active_alerted_flows"`
	Dscp                                          map[string]struct {
		PacketsRcvd int64 `json:"packets.rcvd"`
		PacketsSent int64 `json:"packets.sent"`
		BytesRcvd   int64 `json:"bytes.rcvd"`
		BytesSent   int64 `json:"bytes.sent"`
	} `json:"dscp"`
	BytesNdpiUnknown                           int64   `json:"bytes.ndpi.unknown"`
	ContactsAsServer                           int64   `json:"contacts.as_server"`
	NumContactedPeersWithTcpUdpFlowsNoResponse int64   `json:"num_contacted_peers_with_tcp_udp_flows_no_response"`
	ThroughputTrendPps                         int64   `json:"throughput_trend_pps"`
	BytesRatio                                 float64 `json:"bytes_ratio"`
	Score                                      int64   `json:"score"`
	ScoreAsServer                              int64   `json:"score.as_server"`
	Mac                                        string  `json:"mac"`
	Ndpi                                       map[string]struct {
		Breed       string `json:"breed"`
		PacketsSent int64  `json:"packets.sent"`
		PacketsRcvd int64  `json:"packets.rcvd"`
		BytesRcvd   int64  `json:"bytes.rcvd"`
		Duration    int64  `json:"duration"`
		NumFlows    int64  `json:"num_flows"`
		BytesSent   int64  `json:"bytes.sent"`
	} `json:"ndpi"`
	ActiveFlowsAsClient       int64     `json:"active_flows.as_client"`
	ActiveFlowsBehaviour      Behaviour `json:"active_flows_behaviour"`
	HostServicesBitmap        int64     `json:"host_services_bitmap"`
	Longitude                 float64   `json:"longitude"`
	Devtype                   int64     `json:"devtype"`
	TcpPacketsSeqProblems     bool      `json:"tcp.packets.seq_problems"`
	UnreachableFlowsAsClient  int64     `json:"unreachable_flows.as_client"`
	Iphex                     string    `json:"iphex"`
	PktsRatio                 float64   `json:"pkts_ratio"`
	UdpBytesSentNonUnicast    int64     `json:"udpBytesSent.non_unicast"`
	BytesRcvd                 int64     `json:"bytes.rcvd"`
	AlertedFlowsAsClient      int64     `json:"alerted_flows.as_client"`
	OtherIpBytesSent          int64     `json:"other_ip.bytes.sent"`
	Tskey                     string    `json:"tskey"`
	PacketsRcvd               int64     `json:"packets.rcvd"`
	IcmpPacketsRcvd           int64     `json:"icmp.packets.rcvd"`
	UdpPacketsSent            int64     `json:"udp.packets.sent"`
	IcmpPacketsSent           int64     `json:"icmp.packets.sent"`
	UdpPacketsRcvd            int64     `json:"udp.packets.rcvd"`
	BytesSentAnomalyIndex     int64     `json:"bytes.sent.anomaly_index"`
	TcpBytesRcvd              int64     `json:"tcp.bytes.rcvd"`
	BytesRcvdAnomalyIndex     int64     `json:"bytes.rcvd.anomaly_index"`
	IpVersion                 IPVersion `json:"ip_version"`
	IcmpBytesSentAnomalyIndex int64     `json:"icmp.bytes.sent.anomaly_index"`
	TcpPacketsRcvd            int64     `json:"tcp.packets.rcvd"`
	NumFlowAlerts             int64     `json:"num_flow_alerts"`
	NumBlacklistedFlows       struct {
		TotAsServer int64 `json:"tot_as_server"`
		TotAsClient int64 `json:"tot_as_client"`
		AsClient    int64 `json:"as_client"`
		AsServer    int64 `json:"as_server"`
	} `json:"num_blacklisted_flows"`
	UdpBytesSentUnicast          int64            `json:"udpBytesSent.unicast"`
	TotalFlowsAsServer           int64            `json:"total_flows.as_server"`
	TotalFlowsAsClient           int64            `json:"total_flows.as_client"`
	ObservationPointId           int64            `json:"observation_point_id"`
	FlowsAsClient                int64            `json:"flows.as_client"`
	OtherIpPacketsSent           int64            `json:"other_ip.packets.sent"`
	PktStatsRecv                 PktStats         `json:"pktStats.recv"`
	IsRxOnly                     bool             `json:"is_rx_only"`
	TcpBytesSent                 int64            `json:"tcp.bytes.sent"`
	Continent                    string           `json:"continent"`
	OtherIpBytesRcvdAnomalyIndex int64            `json:"other_ip.bytes.rcvd.anomaly_index"`
	IsMulticast                  bool             `json:"is_multicast"`
	Ip                           string           `json:"ip"`
	PktStatsSent                 PktStats         `json:"pktStats.sent"`
	DhcpHost                     bool             `json:"dhcpHost"`
	CrawlerBotScannerHost        bool             `json:"crawlerBotScannerHost"`
	BroadcastDomainHost          bool             `json:"broadcast_domain_host"`
	IsBlacklisted                bool             `json:"is_blacklisted"`
	UdpBytesSentAnomalyIndex     int64            `json:"udp.bytes.sent.anomaly_index"`
	TotalActivityTime            int64            `json:"total_activity_time"`
	ActiveHttpHosts              int64            `json:"active_http_hosts"`
	Vlan                         int64            `json:"vlan"`
	PacketsSent                  int64            `json:"packets.sent"`
	PacketsRcvdAnomalyIndex      int64            `json:"packets.rcvd.anomaly_index"`
	TotalAlerts                  int64            `json:"total_alerts"`
	HostPoolId                   int64            `json:"host_pool_id"`
	PacketsSentAnomalyIndex      int64            `json:"packets.sent.anomaly_index"`
	Country                      string           `json:"country"`
	OtherIpBytesSentAnomalyIndex int64            `json:"other_ip.bytes.sent.anomaly_index"`
	NumAlerts                    int64            `json:"num_alerts"`
	UdpBytesRcvdAnomalyIndex     int64            `json:"udp.bytes.rcvd.anomaly_index"`
	SerializeByMac               bool             `json:"serialize_by_mac"`
	IsBroadcast                  bool             `json:"is_broadcast"`
	ScoreBehaviour               Behaviour        `json:"score_behaviour"`
	Asname                       string           `json:"asname"`
	ServerContacts               map[string]int64 `json:"server_contacts,omitempty"`
	UsedPorts                    struct {
		LocalServerPorts     map[string]string `json:"local_server_ports"`
		RemoteContactedPorts map[string]string `json:"remote_contacted_ports"`
	} `json:"used_ports,omitempty"`
	Cardinality struct {
		NumHostContactsAsServer      int64 `json:"num_host_contacts_as_server"`
		NumContactedHostsAsClient    int64 `json:"num_contacted_hosts_as_client"`
		NumContactedServicesAsClient int64 `json:"num_contacted_services_as_client"`
	} `json:"cardinality,omitempty"`
	HTTP struct {
		Receiver     HttpBreakdown `json:"receiver"`
		Sender       HttpBreakdown `json:"sender"`
		VirtualHosts interface{}   `json:"virtual_hosts"`
	} `json:"http,omitempty"`
}

type PktStats struct {
	TcpFlags struct {
		Rst    int64 `json:"rst"`
		Synack int64 `json:"synack"`
		Finack int64 `json:"finack"`
		Syn    int64 `json:"syn"`
	} `json:"tcp_flags"`
	Size map[string]int64 `json:"size"`
}

type Behaviour struct {
	AsServer struct {
		Value      int64 `json:"value"`
		UpperBound int64 `json:"upper_bound"`
		LowerBound int64 `json:"lower_bound"`
		Anomaly    bool  `json:"anomaly"`
	} `json:"as_server"`
	AsClient struct {
		Value      int64 `json:"value"`
		UpperBound int64 `json:"upper_bound"`
		LowerBound int64 `json:"lower_bound"`
		Anomaly    bool  `json:"anomaly"`
	} `json:"as_client"`
	TotNumAnomalies int64 `json:"tot_num_anomalies"`
}

type HttpBreakdown struct {
	Query struct {
		Total    int64 `json:"total"`
		NumGet   int64 `json:"num_get"`
		NumOther int64 `json:"num_other"`
		NumHead  int64 `json:"num_head"`
		NumPut   int64 `json:"num_put"`
		NumPost  int64 `json:"num_post"`
	} `json:"query"`
	Rate struct {
		Query struct {
			Get   int64 `json:"get"`
			Put   int64 `json:"put"`
			Post  int64 `json:"post"`
			Head  int64 `json:"head"`
			Other int64 `json:"other"`
		} `json:"query"`
		Response struct {
			Num1XX int64 `json:"1xx"`
			Num2XX int64 `json:"2xx"`
			Num3XX int64 `json:"3xx"`
			Num4XX int64 `json:"4xx"`
			Num5XX int64 `json:"5xx"`
		} `json:"response"`
	} `json:"rate"`
	Response struct {
		Total  int64 `json:"total"`
		Num3XX int64 `json:"num_3xx"`
		Num4XX int64 `json:"num_4xx"`
		Num2XX int64 `json:"num_2xx"`
		Num5XX int64 `json:"num_5xx"`
		Num1XX int64 `json:"num_1xx"`
	} `json:"response"`
}

func (this *Ntopng) GetHostStats(host string) (*HostStats, error) {
	bs, err := this.Get(urlHostStats, nil, map[string]interface{}{"host": host})
	if err != nil {
		return nil, err
	}

	// 接口可能返回空值`"{}"`，特殊处理一下
	if bs == nil || len(bs) == 0 || string(bs) == `"{}"` {
		return &HostStats{}, nil
	}

	var resp HostStats
	if err = UnmarshalRaw(bs, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

type HostDistroReq struct {
	Host     string
	Type     HostDistroType
	CliSrv   CliSrvType `json:"cli_srv,omitempty"`   // 仅HostDistroTypePortTraffic需要指定值
	HttpMode HttpMode   `json:"http_mode,omitempty"` // 仅HostDistroTypeHttpBreakdown需要指定值
}

func (this *Ntopng) GetHostDistro(req *HostDistroReq) ([]*LabelValue, error) {
	var path string
	var isUnmarshalRaw bool
	query := map[string]interface{}{"host": req.Host}
	switch req.Type {
	default:
		return nil, fmt.Errorf("unsupported host distro type: %s", req.Type)
	case HostDistroTypeL4Proto:
		path = urlHostL4ProtoDistro
		query["page"] = "traffic"

	case HostDistroTypeL4ConnectedHost:
		path = urlHostL4ConnectedHostDistro
		query["page"] = "traffic"

	case HostDistroTypeL4Traffic:
		path = urlHostL4TrafficDistro
		query["page"] = "traffic"

	case HostDistroTypeL7Proto:
		path = urlHostL7ProtoDistro
		query["page"] = "ndpi"

	case HostDistroTypeL7Breed:
		path = urlHostL7BreedDistro
		query["page"] = "ndpi"

	case HostDistroTypePktSendSize:
		path = urlHostPktSendSizeDistro
		query["page"] = "traffic"

	case HostDistroTypePktRcvdSize:
		path = urlHostPktRcvdSizeDistro
		query["page"] = "traffic"

	case HostDistroTypePktTcpFlags:
		path = urlHostPktTcpFlagsDistro
		query["page"] = "traffic"

	case HostDistroTypePktArp:
		path = urlHostPktArpDistro
		query["page"] = "traffic"

	case HostDistroTypePortTraffic:
		path = urlHostPortTrafficDistro
		query["clisrv"] = req.CliSrv
		isUnmarshalRaw = true

	case HostDistroTypeDnsBreakdown:
		path = urlHostDnsBreakdown
		query["direction"] = "sent"
		isUnmarshalRaw = true

	case HostDistroTypeHttpBreakdown:
		path = urlHostHttpBreakdown
		query["http_mode"] = req.HttpMode
		isUnmarshalRaw = true
	}

	bs, err := this.Get(path, nil, query)
	if err != nil {
		return nil, err
	}

	if isUnmarshalRaw {
		var arr []*LabelValue
		if err = UnmarshalRaw(bs, &arr); err != nil {
			return nil, err
		}
		return arr, nil
	}

	var resp struct {
		Colors []string  `json:"colors"`
		Series []float64 `json:"series"`
		Labels []string  `json:"labels"`
	}
	if err = UnmarshalRsp(bs, &resp); err != nil {
		return nil, err
	}

	arr := make([]*LabelValue, 0, len(resp.Labels))
	for i := range resp.Labels {
		arr = append(arr, &LabelValue{
			Label: resp.Labels[i],
			Value: resp.Series[i],
			Color: resp.Colors[i],
		})
	}
	return arr, nil
}

type HostL4Data struct {
	Protocol        string  `json:"protocol"`
	BytesSent       int64   `json:"bytes_sent"`
	BytesRcvd       int64   `json:"bytes_rcvd"`
	TotalBytes      int64   `json:"total_bytes"`
	TotalPercentage float64 `json:"total_percentage"`
}

func (this *Ntopng) GetHostL4Data(host string) ([]*HostL4Data, error) {
	bs, err := this.Get(urlHostL4Data, nil, map[string]interface{}{"host": host})
	if err != nil {
		return nil, err
	}
	var arr []*HostL4Data
	if err = UnmarshalRsp(bs, &arr); err != nil {
		return nil, err
	}
	return arr, nil
}

type HostL7Data struct {
	Application struct {
		Id    int64  `json:"id"`
		Label string `json:"label"`
	} `json:"application"`
	Duration   int64   `json:"duration"`
	BytesSent  int64   `json:"bytes_sent"`
	BytesRcvd  int64   `json:"bytes_rcvd"`
	TotBytes   int64   `json:"tot_bytes"`
	Percentage float64 `json:"percentage"`
}

func (this *Ntopng) GetHostL7Data(host string) ([]*HostL7Data, error) {
	bs, err := this.Get(urlHostL7Data, nil, map[string]interface{}{
		"host": host,
		"view": "applications",
	})
	if err != nil {
		return nil, err
	}
	var arr []*HostL7Data
	if err = UnmarshalRsp(bs, &arr); err != nil {
		return nil, err
	}
	return arr, nil
}

type HostTopPeer struct {
	Host       string `json:"host"`
	Name       string `json:"name"`
	Url        string `json:"url"`
	Traffic    int64  `json:"traffic"`
	L7Proto    string `json:"l7proto"`
	L7ProtoUrl string `json:"l7proto_url"`
}

func (this *Ntopng) GetHostTopPeersProtocols(host string) ([]*HostTopPeer, error) {
	bs, err := this.Get(urlHostTopPeersProtocols, nil, map[string]interface{}{"host": host})
	if err != nil {
		return nil, err
	}
	var arr []*HostTopPeer
	if err = UnmarshalRaw(bs, &arr); err != nil {
		return nil, err
	}
	return arr, nil
}

type HostFingerprint struct {
	Ja3         string `json:"ja3"`
	IsMalicious bool   `json:"is_malicious"`
	AppName     string `json:"app_name"`
	NumUses     int64  `json:"num_uses"`
}

func (this *Ntopng) GetHostFingerprint(host string) ([]*HostFingerprint, error) {
	bs, err := this.Get(urlHostFingerprintData, nil, map[string]interface{}{
		"host":             host,
		"fingerprint_type": "ja3",
	})
	if err != nil {
		return nil, err
	}
	var arr []*HostFingerprint
	if err = UnmarshalRsp(bs, &arr); err != nil {
		return nil, err
	}
	return arr, nil
}

type MacReq struct {
	BasePageReq
	MacMode      *MacMode    // 过滤MAC
	Manufacturer string      // 供应商
	DeviceType   *DeviceType // 设备类型
}

func (r *MacReq) defaultIfEmpty() {
	r.BasePageReq.defaultIfEmpty()
	if r.SortColumn == "" {
		r.SortColumn = "column_"
	}
}

type MacResp struct {
	BasePageResp
	Data []*Mac `json:"data"`
}

type Mac struct {
	ColumnArpTotal     string `json:"column_arp_total"`
	ColumnDeviceType   string `json:"column_device_type"`
	Key                string `json:"key"`
	ColumnSince        string `json:"column_since"`
	ColumnBreakdown    string `json:"column_breakdown"`
	ColumnMac          string `json:"column_mac"`
	ColumnName         string `json:"column_name"`
	ColumnTraffic      string `json:"column_traffic"`
	ColumnHosts        string `json:"column_hosts"`
	ColumnThpt         string `json:"column_thpt"`
	ColumnManufacturer string `json:"column_manufacturer"`
}

func (m Mac) MAC() string {
	return getFirstHtmlInnerText(m.ColumnMac, "//a")
}

func (m Mac) Manufacturer() string {
	return m.ColumnManufacturer
}

func (m Mac) DeviceType() string {
	return trimRightTag(m.ColumnDeviceType, "<i")
}

func (m Mac) ArpTotal() int {
	return strNumToInt(m.ColumnArpTotal)
}

func (m Mac) Hosts() int {
	return strNumToInt(m.ColumnHosts)
}

func (m Mac) Breakdown() []float64 {
	return getProgressBarDivWidth(m.ColumnBreakdown)
}

// GetMacList 获取MAC地址列表
func (this *Ntopng) GetMacList(req *MacReq) (*MacResp, error) {
	req.defaultIfEmpty()
	query := map[string]interface{}{
		"currentPage": req.CurrentPage,
		"perPage":     req.PerPage,
		"sortColumn":  req.SortColumn,
		"sortOrder":   req.SortOrder,
	}
	if req.MacMode != nil {
		query["version"] = *req.MacMode
	}
	if req.Manufacturer != "" {
		query["manufacturer"] = req.Manufacturer
	}
	if req.DeviceType != nil {
		query["device_type"] = *req.DeviceType
	}
	bs, err := this.Get(urlMacsData, nil, query)
	if err != nil {
		return nil, err
	}

	var resp MacResp
	if err = UnmarshalRaw(bs, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

type NetworksReq struct {
	BasePageReq
}

type NetworkResp struct {
	BasePageResp
	Data []*Network `json:"data"`
}

type Network struct {
	Key                  string `json:"key"`
	ColumnId             string `json:"column_id"`
	ColumnHostScoreRatio string `json:"column_host_score_ratio"`
	ColumnAlertedFlows   string `json:"column_alerted_flows"`
	ColumnBreakdown      string `json:"column_breakdown"`
	ColumnHosts          string `json:"column_hosts"`
	ColumnChart          string `json:"column_chart"`
	ColumnScore          string `json:"column_score"`
	ColumnThpt           string `json:"column_thpt"`
	ColumnTraffic        string `json:"column_traffic"`
}

func (n Network) Name() string {
	return getFirstHtmlInnerText(n.ColumnId, "//a")
}

func (n Network) AlertedFlows() int {
	return strNumToInt(n.ColumnAlertedFlows)
}

func (n Network) Hosts() int {
	return strNumToInt(n.ColumnHosts)
}

func (n Network) Score() int {
	return strNumToInt(n.ColumnScore)
}

func (n Network) Breakdown() []float64 {
	return getProgressBarDivWidth(n.ColumnBreakdown)
}

func (n Network) Traffic() string {
	return n.ColumnTraffic
}

func (n Network) Thpt() string {
	return n.ColumnThpt
}

// GetNetworkList 获取网络列表
func (this *Ntopng) GetNetworkList(req *NetworksReq) (*NetworkResp, error) {
	req.defaultIfEmpty()
	query := map[string]interface{}{
		"currentPage": req.CurrentPage,
		"perPage":     req.PerPage,
	}
	bs, err := this.Get(urlNetworksData, nil, query)
	if err != nil {
		return nil, err
	}
	var resp NetworkResp
	if err = UnmarshalRaw(bs, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

type HostPoolReq struct {
	BasePageReq
}

func (r *HostPoolReq) defaultIfEmpty() {
	r.BasePageReq.defaultIfEmpty()
	if r.SortColumn == "" {
		r.SortColumn = "column_"
	}
}

type HostPool struct {
	ColumnHosts           string `json:"column_hosts"`
	ColumnId              string `json:"column_id"`
	ColumnSince           string `json:"column_since"`
	ColumnThpt            string `json:"column_thpt"`
	Key                   string `json:"key"`
	ColumnChart           string `json:"column_chart"`
	ColumnBreakdown       string `json:"column_breakdown"`
	ColumnNumDroppedFlows string `json:"column_num_dropped_flows"`
	ColumnTraffic         string `json:"column_traffic"`
}

func (h HostPool) Id() string {
	return getFirstHtmlInnerText(h.ColumnId, "//a")
}

func (h HostPool) NumHosts() int {
	return strNumToInt(h.ColumnHosts)
}

func (h HostPool) NumDroppedFlows() int {
	return strNumToInt(h.ColumnNumDroppedFlows)
}

func (h HostPool) Thpt() string {
	return h.ColumnThpt
}

func (h HostPool) Traffic() string {
	return h.ColumnTraffic
}

func (h HostPool) Breakdown() []float64 {
	return getProgressBarDivWidth(h.ColumnBreakdown)
}

func (h HostPool) Since() string {
	return h.ColumnSince
}

// GetHostPoolList 获取主机池列表
func (this *Ntopng) GetHostPoolList(req *HostPoolReq) ([]*HostPool, error) {
	req.defaultIfEmpty()
	bs, err := this.Get(urlHostPoolsData, nil, map[string]interface{}{
		"currentPage": req.CurrentPage,
		"perPage":     req.PerPage,
		"sortColumn":  req.SortColumn,
		"sortOrder":   req.SortOrder,
	})
	if err != nil {
		return nil, err
	}
	var arr []*HostPool
	if err = UnmarshalRaw(bs, &arr); err != nil {
		return nil, err
	}
	return arr, nil
}

type ASReq struct {
	BasePageReq
}

func (r *ASReq) defaultIfEmpty() {
	r.BasePageReq.defaultIfEmpty()
	if r.SortColumn == "" {
		r.SortColumn = "column_"
	}
}

type ASResp struct {
	BasePageResp
	Data []*AS `json:"data"`
}

type AS struct {
	Key                  string `json:"key"`
	ColumnHosts          string `json:"column_hosts"`
	ColumnThpt           string `json:"column_thpt"`
	ColumnAsname         string `json:"column_asname"`
	ColumnAsn            string `json:"column_asn"`
	ColumnHostScoreRatio string `json:"column_host_score_ratio"`
	ColumnAlertedFlows   string `json:"column_alerted_flows"`
	ColumnChart          string `json:"column_chart"`
	ColumnScore          string `json:"column_score"`
	ColumnSince          string `json:"column_since"`
	ColumnTraffic        string `json:"column_traffic"`
	ColumnBreakdown      string `json:"column_breakdown"`
}

func (a AS) ASN() int {
	return strNumToInt(getFirstHtmlInnerText(a.ColumnAsn, "//a"))
}

func (a AS) ASName() string {
	return getFirstHtmlInnerText(a.ColumnAsname, "//a")
}

func (a AS) NumHosts() int {
	return strNumToInt(a.ColumnHosts)
}

func (a AS) Score() int {
	return strNumToInt(a.ColumnScore)
}

func (a AS) HostScoreRatio() float64 {
	return strNumToFloat(a.ColumnHostScoreRatio)
}

func (a AS) AlertedFlows() int {
	return strNumToInt(a.ColumnAlertedFlows)
}

func (a AS) Thpt() string {
	return a.ColumnThpt
}

func (a AS) Traffic() string {
	return a.ColumnTraffic
}

func (a AS) Breakdown() []float64 {
	return getProgressBarDivWidth(a.ColumnBreakdown)
}

func (a AS) Since() string {
	return a.ColumnSince
}

func (this *Ntopng) GetASList(req *ASReq) (*ASResp, error) {
	req.defaultIfEmpty()
	bs, err := this.Get(urlASesData, nil, map[string]interface{}{
		"currentPage": req.CurrentPage,
		"perPage":     req.PerPage,
		"sortColumn":  req.SortColumn,
		"sortOrder":   req.SortOrder,
	})
	if err != nil {
		return nil, err
	}

	var resp ASResp
	if err = UnmarshalRaw(bs, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

type CountryReq struct {
	BasePageReq
}

func (r *CountryReq) defaultIfEmpty() {
	r.BasePageReq.defaultIfEmpty()
	if r.SortColumn == "" {
		r.SortColumn = "column_"
	}
}

type CountryResp struct {
	BasePageResp
	Data []*Country `json:"data"`
}

type Country struct {
	ColumnChart     string `json:"column_chart"`
	ColumnTraffic   string `json:"column_traffic"`
	ColumnId        string `json:"column_id"`
	ColumnBreakdown string `json:"column_breakdown"`
	Key             string `json:"key"`
	ColumnSince     string `json:"column_since"`
	ColumnHosts     string `json:"column_hosts"`
	ColumnScore     string `json:"column_score"`
	ColumnThpt      string `json:"column_thpt"`
}

func (c Country) Name() string {
	return c.Key
}

func (c Country) NumHosts() int {
	return strNumToInt(c.ColumnHosts)
}

func (c Country) Score() int {
	return strNumToInt(c.ColumnScore)
}

func (c Country) Thpt() string {
	return c.ColumnThpt
}

func (c Country) Traffic() string {
	return c.ColumnTraffic
}

func (c Country) Breakdown() []float64 {
	return getProgressBarDivWidth(c.ColumnBreakdown)
}

func (c Country) Since() string {
	return c.ColumnSince
}

func (this *Ntopng) GetCountryList(req *CountryReq) (*CountryResp, error) {
	req.defaultIfEmpty()
	bs, err := this.Get(urlCountriesData, nil, map[string]interface{}{
		"currentPage": req.CurrentPage,
		"perPage":     req.PerPage,
		"sortColumn":  req.SortColumn,
		"sortOrder":   req.SortOrder,
	})
	if err != nil {
		return nil, err
	}
	var resp CountryResp
	if err = UnmarshalRaw(bs, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

type OsReq struct {
	BasePageReq
}

type OsResp struct {
	BasePageResp
	Data []*OS `json:"data"`
}

type OS struct {
	ColumnId        string `json:"column_id"`
	Key             string `json:"key"`
	ColumnHosts     string `json:"column_hosts"`
	ColumnBreakdown string `json:"column_breakdown"`
	ColumnAlerts    string `json:"column_alerts"`
	ColumnThpt      string `json:"column_thpt"`
	ColumnTraffic   string `json:"column_traffic"`
	ColumnChart     string `json:"column_chart"`
	ColumnSince     string `json:"column_since"`
}

func (o OS) Name() string {
	return getFirstHtmlInnerText(o.ColumnId, "//a")
}

func (o OS) NumHosts() int {
	return strNumToInt(o.ColumnHosts)
}

func (o OS) Alerts() int {
	return strNumToInt(o.ColumnAlerts)
}

func (o OS) Thpt() string {
	return o.ColumnThpt
}

func (o OS) Traffic() string {
	return o.ColumnTraffic
}

func (o OS) Breakdown() []float64 {
	return getProgressBarDivWidth(o.ColumnBreakdown)
}

func (o OS) Since() string {
	return o.ColumnSince
}

func (this *Ntopng) GetOsList(req *OsReq) (*OsResp, error) {
	req.defaultIfEmpty()
	bs, err := this.Get(urlOSesData, nil, map[string]interface{}{
		"currentPage": req.CurrentPage,
		"perPage":     req.PerPage,
		"sortColumn":  req.SortColumn,
		"sortOrder":   req.SortOrder,
	})
	if err != nil {
		return nil, err
	}
	var resp OsResp
	if err = UnmarshalRaw(bs, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
