package ntopng

import (
	"strings"
)

const (
	urlApplications          = "/lua/rest/v2/get/ntopng/applications.lua"
	urlApplicationCategories = "/lua/rest/v2/get/category/list.lua" // 应用程序类别
	urlAdminCategories       = "/lua/admin/get_category_lists.lua"  // 类别列表
	urlDeviceProtocols       = "/lua/admin/get_device_protocols.lua"
)

type Application struct {
	ApplicationId int    `json:"application_id"`
	Application   string `json:"application"`
	CategoryId    int    `json:"category_id"`
	Category      string `json:"category"`
	NumHosts      int    `json:"num_hosts"`
	CustomRules   string `json:"custom_rules"`
	IsCustom      bool   `json:"is_custom"`
}

func (this *Ntopng) GetApplicationList() ([]*Application, error) {
	bs, err := this.Get(urlApplications, nil, nil)
	if err != nil {
		return nil, err
	}

	var arr []*Application
	if err = UnmarshalRsp(bs, &arr); err != nil {
		return nil, err
	}

	return arr, nil
}

type ApplicationCategory struct {
	ColumnCategoryId    int    `json:"column_category_id"`
	ColumnCategoryName  string `json:"column_category_name"`
	ColumnCategoryHosts string `json:"column_category_hosts"`
	ColumnNumHosts      string `json:"column_num_hosts"`
	ColumnNumProtos     string `json:"column_num_protos"`
}

func (c ApplicationCategory) Id() int {
	return c.ColumnCategoryId
}

func (c ApplicationCategory) Name() string {
	return c.ColumnCategoryName
}

func (c ApplicationCategory) NumHosts() int {
	return strNumToInt(c.ColumnNumHosts)
}

func (c ApplicationCategory) NumProtocols() int {
	return strNumToInt(getFirstHtmlInnerText(c.ColumnNumProtos, "//a"))
}

func (this *Ntopng) GetApplicationCategoryList() ([]*ApplicationCategory, error) {
	bs, err := this.Get(urlApplicationCategories, nil, nil)
	if err != nil {
		return nil, err
	}
	var arr []*ApplicationCategory
	if err = UnmarshalRsp(bs, &arr); err != nil {
		return nil, err
	}
	return arr, nil
}

type DeviceApplicationReq struct {
	BasePageReq
	DeviceType   *DeviceType   `json:"device_type"`             // 设备类型
	PolicyFilter *PolicyFilter `json:"policy_filter,omitempty"` // 过滤策略
	Category     string        `json:"category,omitempty"`      // 类别
	L7Proto      int           `json:"l7_proto,omitempty"`      // 协议
}

type DeviceApplicationResp struct {
	BasePageResp
	Data []*DeviceApplication `json:"data"`
}

type DeviceApplication struct {
	ColumnNdpiApplicationId int    `json:"column_ndpi_application_id"`
	ColumnNdpiApplication   string `json:"column_ndpi_application"`
	ColumnNdpiCategory      string `json:"column_ndpi_category"`
	ColumnServerPolicy      string `json:"column_server_policy"`
	ColumnClientPolicy      string `json:"column_client_policy"`
}

func (dp DeviceApplication) NdpiAppId() int {
	return dp.ColumnNdpiApplicationId
}

func (dp DeviceApplication) NdpiAppName() string {
	return dp.ColumnNdpiApplication
}

func (dp DeviceApplication) NdpiCategory() string {
	return dp.ColumnNdpiCategory
}

func (dp DeviceApplication) ServerPolicy() PolicyFilter {
	classAttr := getClassAttrByCheckedRadio(dp.ColumnServerPolicy)
	if strings.Contains(classAttr, "fa-check") {
		return PolicyFilterAllow
	}
	// fa-exclamation-triangle
	return PolicyFilterWarning
}

func (dp DeviceApplication) ClientPolicy() PolicyFilter {
	classAttr := getClassAttrByCheckedRadio(dp.ColumnClientPolicy)
	if strings.Contains(classAttr, "fa-check") {
		return PolicyFilterAllow
	}
	// fa-exclamation-triangle
	return PolicyFilterWarning
}

func (this *Ntopng) GetDeviceApplicationList(req *DeviceApplicationReq) (*DeviceApplicationResp, error) {
	req.defaultIfEmpty()
	query := map[string]interface{}{
		"currentPage": req.CurrentPage,
		"perPage":     req.PerPage,
		"sortColumn":  req.SortColumn,
		"sortOrder":   req.SortOrder,
	}
	if req.DeviceType != nil {
		query["device_type"] = *req.DeviceType
	}
	if req.PolicyFilter != nil {
		query["policy_filter"] = *req.PolicyFilter
	}
	if req.Category != "" {
		query["category"] = req.Category
	}
	if req.L7Proto > 0 {
		query["l7_proto"] = req.L7Proto
	}
	bs, err := this.Get(urlDeviceProtocols, nil, query)
	if err != nil {
		return nil, err
	}
	var resp DeviceApplicationResp
	if err = UnmarshalRsp(bs, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

type CategoryReq struct {
	BasePageReq
	EnabledStatus EnabledStatus `json:"enabled_status"`     // 启用状态
	Category      string        `json:"category,omitempty"` // 应用程序类别
}

func (r *CategoryReq) defaultIfEmpty() {
	r.BasePageReq.defaultIfEmpty()
	if r.SortColumn == "" {
		r.SortColumn = "column_label"
	}
	if r.EnabledStatus == "" {
		r.EnabledStatus = EnabledStatusAll
	}
}

type CategoryResp struct {
	BasePageResp
	Data []*Category `json:"data"`
}

type Category struct {
	ColumnStatus              string `json:"column_status"`
	ColumnName                string `json:"column_name"`
	ColumnCategoryName        string `json:"column_category_name"`
	ColumnCategory            string `json:"column_category"`
	ColumnUpdateIntervalLabel string `json:"column_update_interval_label"`
	ColumnLabel               string `json:"column_label"`
	ColumnNumHits             string `json:"column_num_hits"`
	ColumnEnabled             bool   `json:"column_enabled"`
	ColumnNumHosts            string `json:"column_num_hosts"`
	ColumnUrl                 string `json:"column_url"`
	ColumnUpdateInterval      int    `json:"column_update_interval"`
	ColumnLastUpdate          string `json:"column_last_update"`
}

func (c Category) Name() string {
	return c.ColumnName
}

// CategoryName 应用程序类别名称
func (c Category) CategoryName() string {
	return c.ColumnCategoryName
}

func (c Category) NumHosts() int {
	return strNumToInt(c.ColumnNumHosts)
}

func (c Category) NumHits() int {
	return strNumToInt(c.ColumnNumHits)
}

func (c Category) UpdateInterval() int {
	return c.ColumnUpdateInterval
}

func (c Category) UpdateIntervalLabel() string {
	return c.ColumnUpdateIntervalLabel
}

func (c Category) LastUpdate() string {
	return c.ColumnLastUpdate
}

func (c Category) Enabled() bool {
	return c.ColumnEnabled
}

func (c Category) Status() string {
	return getFirstHtmlInnerText(c.ColumnStatus, "//span")
}

func (this *Ntopng) GetCategoryList(req *CategoryReq) (*CategoryResp, error) {
	req.defaultIfEmpty()
	query := map[string]interface{}{
		"currentPage":    req.CurrentPage,
		"perPage":        req.PerPage,
		"sortColumn":     req.SortColumn,
		"sortOrder":      req.SortOrder,
		"enabled_status": req.EnabledStatus,
	}
	if req.Category != "" {
		query["category"] = req.Category
	}
	bs, err := this.Get(urlAdminCategories, nil, query)
	if err != nil {
		return nil, err
	}

	var resp CategoryResp
	if err = UnmarshalRaw(bs, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
