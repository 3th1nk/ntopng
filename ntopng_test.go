package ntopng

import (
	"testing"
)

var (
	n *Ntopng
)

func TestMain(m *testing.M) {
	n = New(
		WithBaseUrl("http://192.168.1.29:3000"),
		WithBasicAuth("admin", "Geesunn@123"),
	)
	m.Run()
}
