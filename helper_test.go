package ntopng

import (
	"github.com/antchfx/htmlquery"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func Test_getHtmlInnerTextAndWidth(t *testing.T) {
	htmlStr := `<a href='/lua/host_details.lua?host=172.16.20.110' data-bs-toggle='tooltip' title='172.16.20.110'>172.16.20.110</a> <abbr title=\"本地\"><span class=\"badge bg-success\">L</span></abbr>:<A HREF='/lua/flows_stats.lua?port=51590'>51590</A>`

	doc, err := htmlquery.Parse(strings.NewReader(htmlStr))
	if err != nil {
		t.Error(err)
		return
	}
	// 提取 IP 地址
	ipNode := htmlquery.FindOne(doc, "//a[contains(@href, 'host_details.lua')]")
	ip := htmlquery.InnerText(ipNode)

	// 提取端口号
	portNode := htmlquery.FindOne(doc, "//a[contains(@href, 'flows_stats.lua')]")
	port := htmlquery.InnerText(portNode)

	t.Log(ip, port)
}

func Test_trimRightTag(t *testing.T) {
	assert.Equal(t, "TCP", trimRightTag("TCP ", "<i"))
	assert.Equal(t, "TCP", trimRightTag("TCP <i class='fa-fw fas fa-info-circle text-info' title='TLS（可能）不携带 HTTPS'></i>", "<i"))
	assert.Equal(t, "1.33 kbps", trimRightTag("1.33 kbps <i class='fas fa-arrow-down'></i>", "<i"))
}

func Test_parseProgressBarDiv(t *testing.T) {
	htmlStr := `<div class='progress'><div class='progress-bar bg-warning' style='width: 0%;'>Sent</div><div class='progress-bar bg-success' style='width: 100%;'>Rcvd</div></div>`
	t.Log(getProgressBarDivWidth(htmlStr))
}

func Test_getClassAttrByCheckedRadio(t *testing.T) {
	htmlStr := `
	<label class="radio-inline mx-2">
    <input type="radio" name="7_client_action" value="0" >
    <span class="mx-1" style="font-size: 16px;">
        <i class="fas fa-exclamation-triangle" aria-hidden="true"></i>
    </span>
</label>
<label class="radio-inline mx-2">
    <input type="radio" name="7_client_action" value="1" checked>
    <span class="mx-1" style="font-size: 16px;">
        <i class="fas fa-check" aria-hidden="true"></i>
    </span>
</label>
`
	t.Log(getClassAttrByCheckedRadio(htmlStr))
}
