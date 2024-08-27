package ntopng

import (
	"github.com/3th1nk/easygo/util/convertor"
	"github.com/antchfx/htmlquery"
	"regexp"
	"strings"
)

func getFirstHtmlInnerText(htmlStr, expr string) string {
	if htmlStr == "" || expr == "" {
		return ""
	}
	doc, err := htmlquery.Parse(strings.NewReader(htmlStr))
	if err != nil {
		return ""
	}
	if node := htmlquery.FindOne(doc, expr); node != nil {
		return strings.TrimSpace(htmlquery.InnerText(node))
	}
	return ""
}

func getProgressBarDivWidth(htmlStr string) []float64 {
	if htmlStr == "" {
		return nil
	}
	doc, err := htmlquery.Parse(strings.NewReader(htmlStr))
	if err != nil {
		return nil
	}

	nodes := htmlquery.Find(doc, "//div[contains(@class, 'progress-bar')]")
	if len(nodes) == 0 {
		return nil
	}

	var arr []float64
	re := regexp.MustCompile(`width:\s*([\d.]+)%`)
	for _, node := range nodes {
		var width float64
		styleAttr := htmlquery.SelectAttr(node, "style")
		if match := re.FindStringSubmatch(styleAttr); len(match) > 1 {
			width = convertor.ToFloatNoError(match[1])
		}
		arr = append(arr, width)
	}
	return arr
}

func trimRightTag(s string, tag string) string {
	if idx := strings.Index(s, tag); idx != -1 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}

func getClassAttrByCheckedRadio(htmlStr string) string {
	doc, err := htmlquery.Parse(strings.NewReader(htmlStr))
	if err != nil {
		return ""
	}
	if node := htmlquery.FindOne(doc, "//input[@checked]"); node != nil {
		if node = htmlquery.FindOne(node.Parent, "//i"); node != nil {
			return htmlquery.SelectAttr(node, "class")
		}
	}
	return ""
}

func strNumToInt(s string) int {
	if s == "" {
		return 0
	}
	return convertor.ToIntNoError(strings.Replace(s, ",", "", -1))
}

func strNumToFloat(s string) float64 {
	if s == "" {
		return 0
	}
	return convertor.ToFloatNoError(strings.Replace(s, ",", "", -1))
}
