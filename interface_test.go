package ntopng

import (
	"testing"
)

func TestNtopng_GetInterface(t *testing.T) {
	res, err := n.GetInterface(0)
	if err != nil {
		t.Fatal(err)
		return
	}
	t.Log(res.Ifid, res.Ifname)
}

func TestNtopng_GetInterfaceList(t *testing.T) {
	arr, err := n.GetInterfaceList()
	if err != nil {
		t.Fatal(err)
		return
	}
	for _, a := range arr {
		t.Log(a.Ifid, a.Ifname)
	}
}

func TestNtopng_Find(t *testing.T) {
	resp, err := n.Find(&FindReq{
		IfId:  0,
		Query: "1",
	})
	if err != nil {
		t.Error(err)
		return
	}

	t.Log(resp.Interface)
	for _, v := range resp.Results {
		t.Log(v.Type, v.Name)
	}
}

func TestNtopng_GetInterfaceDistro(t *testing.T) {
	arr, err := n.GetInterfaceDistro(&IfDistroReq{
		IfId: 0,
		Type: IfDistroTypeTopHosts,
	})
	if err != nil {
		t.Error(err)
		return
	}
	for _, v := range arr {
		t.Log(v.Label, v.Value)
	}
}
