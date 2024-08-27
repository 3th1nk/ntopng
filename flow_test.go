package ntopng

import (
	"github.com/3th1nk/easygo/util/jsonUtil"
	"testing"
)

func TestNtopng_GetFlowList(t *testing.T) {
	resp, err := n.GetFlowList(&FlowReq{
		BasePageReq: BasePageReq{
			CurrentPage: 1,
			PerPage:     10,
		},
		IfId: 0,
	})
	if err != nil {
		t.Fatal(err)
		return
	}
	for _, a := range resp.Data {
		t.Log(a.Id(), a.Protocol(), a.Client(), a.Server(), a.Breakdown(), a.FirstSeenTime(), a.LastSeenTime())
	}
}

func TestNtopng_GetFlowStats(t *testing.T) {
	resp, err := n.GetFlowStats(&FlowStatsReq{
		IfId:   0,
		Key:    "3249078908",
		HashId: "11971067",
	})
	if err != nil {
		t.Fatal(err)
		return
	}
	t.Log(jsonUtil.MustMarshalToStringIndent(resp))
}
