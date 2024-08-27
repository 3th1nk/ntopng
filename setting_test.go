package ntopng

import (
	"testing"
)

func TestNtopng_GetApplicationList(t *testing.T) {
	arr, err := n.GetApplicationList()
	if err != nil {
		t.Error(err)
		return
	}
	for _, v := range arr {
		t.Log(v.ApplicationId, v.Application, v.CategoryId, v.Category)
	}
}

func TestNtopng_GetApplicationCategoryList(t *testing.T) {
	arr, err := n.GetApplicationCategoryList()
	if err != nil {
		t.Error(err)
		return
	}
	for _, v := range arr {
		t.Log(v.Id(), "|", v.Name(), "|", v.NumProtocols())
	}
}

func TestNtopng_GetDeviceApplicationList(t *testing.T) {
	devType := DeviceTypeUnknown
	resp, err := n.GetDeviceApplicationList(&DeviceApplicationReq{
		BasePageReq: BasePageReq{
			CurrentPage: 1,
			PerPage:     10,
		},
		DeviceType: &devType,
	})
	if err != nil {
		t.Error(err)
		return
	}
	for _, v := range resp.Data {
		t.Log(v.NdpiAppId(), v.NdpiAppName(), v.NdpiCategory(), v.ClientPolicy(), v.ServerPolicy())
	}
}

func TestNtopng_GetCategoryList(t *testing.T) {
	resp, err := n.GetCategoryList(&CategoryReq{
		BasePageReq: BasePageReq{
			CurrentPage: 1,
			PerPage:     10,
		},
		EnabledStatus: EnabledStatusAll,
	})
	if err != nil {
		t.Error(err)
		return
	}
	for _, v := range resp.Data {
		t.Log(v.Name(), v.Status(), v.CategoryName(), v.UpdateIntervalLabel(), v.LastUpdate(), v.NumHosts(), v.NumHits())
	}
}
