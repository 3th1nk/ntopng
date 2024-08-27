package ntopng

import (
	"github.com/3th1nk/easygo/util/jsonUtil"
	"testing"
)

func TestNtopng_GetTsData(t *testing.T) {
	resp, err := n.GetTsData(&TsDataReq{
		Schema: "host:traffic",
		Query: map[string]interface{}{
			"ifid": 0,
			"host": "192.168.1.226",
		},
		TsKey: "192.168.1.226",
	})
	if err != nil {
		t.Fatal(err)
		return
	}
	t.Log(jsonUtil.MustMarshalToStringIndent(resp))
}
