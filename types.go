package ntopng

// IfDistroType 接口统计类型
type IfDistroType string

const (
	IfDistroTypePktSize             IfDistroType = "size"           // 数据包 - 大小分布
	IfDistroTypePktIpVer            IfDistroType = "ipver"          // 数据包 - IP版本分布
	IfDistroTypePktTcpFlags         IfDistroType = "tcp_flags"      // 数据包 - TCP标志分布
	IfDistroTypeDSCP                IfDistroType = "dscp"           // DSCP - 优先级分布
	IfDistroTypeL7SinceStartup      IfDistroType = "l7"             // 应用程序概述 - 协议分布
	IfDistroTypeL7BreedSinceStartup IfDistroType = "l7_breed"       // 应用程序概述 - 协议类型分布
	IfDistroTypeL7BreedCount        IfDistroType = "l7_breed_count" // 应用程序实时流计数 - 协议类型分布
	IfDistroTypeTcpStats            IfDistroType = "tcp_stats"      // 应用程序实时流计数 - TCP连接状态分布
	IfDistroTypeL7Category          IfDistroType = "l7_category"    // 应用程序类别概述
	IfDistroTypeTopHosts            IfDistroType = "top_hosts"      // Top主机
)

// FlowHostType 主机类型
type FlowHostType string

const (
	FlowHostTypeAll           FlowHostType = ""
	FlowHostTypeLocalOnly     FlowHostType = "local_only"
	FlowHostTypeRemoteOnly    FlowHostType = "remote_only"
	FlowHostTypeLocalToRemote FlowHostType = "local_origin_remote_target"
	FlowHostTypeRemoteToLocal FlowHostType = "remote_origin_local_target"
)

// AlertType 警告类型
//	所有流警告的Key也可作为警告类型，详见 https://www.ntop.org/guides/ntopng/scripts/alert_definitions.html#alert-key
type AlertType string

const (
	AlertTypeAll      AlertType = ""         // 全部
	AlertTypeNormal   AlertType = "normal"   // 正常
	AlertTypeAlerted  AlertType = "alerted"  // 所有警告
	AlertTypePeriodic AlertType = "periodic" // All Periodic
)

// AlertTypeSeverity 严重性
type AlertTypeSeverity string

const (
	AlertTypeSeverityAll           AlertTypeSeverity = ""                // 全部
	AlertTypeSeverityNoticeOrLower AlertTypeSeverity = "notice_or_lower" // 通知或更低
	AlertTypeSeverityWarning       AlertTypeSeverity = "warning"         // 警告
	AlertTypeSeverityError         AlertTypeSeverity = "error"           // 错误或更高
)

// TrafficType 流方向
type TrafficType string

const (
	TrafficTypeAll TrafficType = "" // 全部
	// 流 方向
	TrafficTypeUnicast                    TrafficType = "unicast"                     // 单播(非组播/非广播)
	TrafficTypeBroadcastOrMulticast       TrafficType = "broadcast_multicast"         // 组播/广播
	TrafficTypeOneWayUnicast              TrafficType = "one_way_unicast"             // 单向单播(非组播/非广播)
	TrafficTypeOneWayBroadcastOrMulticast TrafficType = "one_way_broadcast_multicast" // 单向组播/广播
	// 主机 流量方向
	TrafficTypeOneWay        TrafficType = "one_way"       // 单向
	TrafficTypeBidirectional TrafficType = "bidirectional" // 双向
)

// IPVersion IP版本
type IPVersion int

const (
	IPVersionAll IPVersion = 0 // 全部
	IPVersion4   IPVersion = 4 // IPv4
	IPVersion6   IPVersion = 6 // IPv6
)

// L4Proto 4层协议
type L4Proto int

const (
	L4ProtoAll    L4Proto = 0  // 全部
	L4ProtoICMP   L4Proto = 1  // ICMP
	L4ProtoTCP    L4Proto = 6  // TCP
	L4ProtoUDP    L4Proto = 17 // UDP
	L4ProtoICMPv6 L4Proto = 58 // ICMPv6
)

// HostMode 过滤主机
type HostMode string

const (
	HostModeAll                  HostMode = ""                    // 全部
	HostModeBlacklisted          HostMode = "blacklisted"         // 列入黑名单的主机
	HostModeBroadcastDomain      HostMode = "broadcast_domain"    // 广播域主机
	HostModeBroadcastOrMulticast HostMode = "broadcast_multicast" // 组播/广播主机
	HostModeDHCP                 HostMode = "dhcp"                // DHCP主机
	HostModeLocal                HostMode = "local"               // 本地主机
	HostModeLocalNoTx            HostMode = "local_no_tx"         // 本地无发送流量主机
	HostModeLocalNoTcpTx         HostMode = "local_no_tcp_tx"     // 本地无TCP/UDP发送流量主机
	HostModeRemote               HostMode = "remote"              // 远程主机
	HostModeRemoteNoRx           HostMode = "remote_no_rx"        // 远程无接收流量主机
	HostModeRemoteNoTcpRx        HostMode = "remote_no_tcp_rx"    // 远程无TCP/UDP接收流量主机
)

// MacMode 过滤MAC
type MacMode string

const (
	MacModeAll            MacMode = ""                 // 全部
	MacModeSourceMacsOnly MacMode = "source_macs_only" // 仅源MAC
)

type HostDistroType string

const (
	HostDistroTypeL4Proto         = "l4_proto"   // 4层协议
	HostDistroTypeL4Traffic       = "l4_traffic" // 4层流量
	HostDistroTypeL4ConnectedHost = "l4_connected_host"
	HostDistroTypeL7Proto         = "l7_proto"
	HostDistroTypeL7Breed         = "l7_breed"
	HostDistroTypePktSendSize     = "pkt_send_size"
	HostDistroTypePktRcvdSize     = "pkt_rcvd_size"
	HostDistroTypePktTcpFlags     = "pkt_tcp_flags"
	HostDistroTypePktArp          = "pkt_arp"
	HostDistroTypePortTraffic     = "port_traffic"
	HostDistroTypeDnsBreakdown    = "dns_breakdown"
	HostDistroTypeHttpBreakdown   = "http_breakdown"
)

// DeviceType 设备类型
type DeviceType int

const (
	DeviceTypeUnknown        DeviceType = iota // 未知
	DeviceTypePrinter                          // 打印机
	DeviceTypeRecording                        // 录像
	DeviceTypePC                               // 计算机
	DeviceTypeLaptop                           // 笔记本电脑
	DeviceTypePad                              // 平板
	DeviceTypeMobile                           // 手机
	DeviceTypeTV                               // TV
	DeviceTypeRouterOrSwitch                   // 路由器/交换机
	DeviceTypeWireless                         // 无线网络
	DeviceTypeNAS                              // NAS
	DeviceTypeMultimedia                       // 多媒体
	DeviceTypeIoT                              // IoT
)

// PolicyFilter 过滤策略
type PolicyFilter int

const (
	PolicyFilterWarning PolicyFilter = iota // 触发告警
	PolicyFilterAllow                       // 可接受
)

// EnabledStatus 启用状态
type EnabledStatus string

const (
	EnabledStatusAll      EnabledStatus = "all"
	EnabledStatusEnabled  EnabledStatus = "enabled"
	EnabledStatusDisabled EnabledStatus = "disabled"
)

type CliSrvType string

const (
	CliSrvTypeClient CliSrvType = "client"
	CliSrvTypeServer CliSrvType = "server"
)

type HttpMode string

const (
	HttpModeQueries   HttpMode = "queries"
	HttpModeResponses HttpMode = "responses"
)
