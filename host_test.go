package ntopng

import (
	"testing"
)

func TestNtopng_GetMacList(t *testing.T) {
	resp, err := n.GetMacList(&MacReq{
		BasePageReq: BasePageReq{
			CurrentPage: 1,
			PerPage:     10,
		},
	})
	if err != nil {
		t.Fatal(err)
		return
	}
	for _, v := range resp.Data {
		t.Log(v.MAC(), v.Manufacturer(), v.DeviceType(), v.Hosts(), v.ArpTotal(), v.Breakdown())
	}
}

func TestNtopng_GetHostList(t *testing.T) {
	resp, err := n.GetHostList(&HostReq{
		BasePageReq: BasePageReq{
			CurrentPage: 1,
			PerPage:     10,
		},
	})
	if err != nil {
		t.Fatal(err)
		return
	}
	for _, v := range resp.Data {
		t.Log(v.IP(), v.Name(), v.NumFlows(), v.Score(), v.Thpt(), v.TrafficSent(), v.Traffic(), v.Breakdown(), v.Since())
	}
}

func TestNtopng_GetNetworkList(t *testing.T) {
	resp, err := n.GetNetworkList(&NetworksReq{
		BasePageReq: BasePageReq{
			CurrentPage: 1,
			PerPage:     10,
		},
	})
	if err != nil {
		t.Fatal(err)
		return
	}
	for _, v := range resp.Data {
		t.Log(v.Name(), v.Hosts(), v.Thpt(), v.Traffic())
	}
}

func TestNtopng_GetHostStats(t *testing.T) {
	resp, err := n.GetHostStats("59.36.97.33")
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(resp.Name, resp.Mac)
}
