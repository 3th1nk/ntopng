package ntopng

import (
	"fmt"
	"github.com/3th1nk/easygo/util/jsonUtil"
)

const (
	CodeOK                                            = 0
	CodeNotFound                                      = -1
	CodeInvalidInterface                              = -2
	CodeNotGranted                                    = -3
	CodeInvalidHost                                   = -4
	CodeInvalidArguments                              = -5
	CodeInternalError                                 = -6
	CodeBadFormat                                     = -7
	CodeBadContent                                    = -8
	CodeNameResolutionFailed                          = -9
	CodeSnmpDeviceAlreadyAdded                        = -10
	CodeSnmpDeviceUnreachable                         = -11
	CodeNoSnmpDeviceDiscovered                        = -12
	CodeAddPoolFailed                                 = -13
	CodeEditPoolFailed                                = -14
	CodePoolNotFound                                  = -16
	CodeBindPoolMemberFailed                          = -17
	CodePasswordMismatch                              = -19
	CodeAddUserFailed                                 = -20
	CodeDeleteUserFailed                              = -21
	CodeSnmpUnknownDevice                             = -22
	CodeUserAlreadyExisting                           = -23
	CodeEditUserFailed                                = -24
	CodeSnmpDeviceInterfaceStatusChangeFailed         = -26
	CodeConfigurationFileMismatch                     = -27
	CodePartialImport                                 = -28
	CodeInfrastructureInstanceNotFound                = -32
	CodeInfrastructureInstanceEmptyID                 = -33
	CodeInfrastructureInstanceEmptyAlias              = -34
	CodeInfrastructureInstanceEmptyURL                = -35
	CodeInfrastructureInstanceEmptyToken              = -36
	CodeInfrastructureInstanceEmptyRTTThreshold       = -37
	CodeInfrastructureInstanceSameAlias               = -39
	CodeInfrastructureInstanceSameURL                 = -40
	CodeInfrastructureInstanceSameToken               = -41
	CodeInfrastructureInstanceAlreadyExisting         = -42
	CodeInfrastructureInstanceCheckFailed             = -43
	CodeInfrastructureInstanceCheckNotFound           = -44
	CodeInfrastructureInstanceCheckInvalidResponse    = -45
	CodeInfrastructureInstanceCheckAuthFailed         = -46
	CodeInfrastructureInstanceEmptyBandwidthThreshold = -47
)

func UnmarshalRsp(b []byte, v interface{}) error {
	var resp struct {
		Rc    int         `json:"rc,omitempty"`
		RcStr string      `json:"rc_str,omitempty"`
		Rsp   interface{} `json:"rsp,omitempty"`
	}
	if err := jsonUtil.Unmarshal(b, &resp); err != nil {
		return err
	}
	if resp.Rc != CodeOK {
		return fmt.Errorf(resp.RcStr)
	}

	return jsonUtil.UnmarshalFromObject(resp.Rsp, v)
}

func UnmarshalRaw(b []byte, v interface{}) error {
	return jsonUtil.Unmarshal(b, v)
}

type BasePageResp struct {
	TotalRows   int64      `json:"totalRows"`
	CurrentPage int        `json:"currentPage"`
	PerPage     int        `json:"perPage"`
	Sort        [][]string `json:"sort,omitempty"` // 排序字段 [["字段名","asc|desc"],...]
}
