package ntopng

type BasePageReq struct {
	CurrentPage int    `json:"currentPage"`          // 当前页
	PerPage     int    `json:"perPage"`              // 每页条数
	SortColumn  string `json:"sortColumn,omitempty"` // 排序字段
	SortOrder   string `json:"sortOrder,omitempty"`  // 排序顺序 asc desc
}

func (r *BasePageReq) defaultIfEmpty() {
	if r.CurrentPage == 0 {
		r.CurrentPage = 1
	}
	if r.PerPage == 0 {
		r.PerPage = 10
	}
	if r.SortOrder == "" {
		r.SortOrder = "desc"
	}
}
