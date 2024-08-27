package ntopng

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Option func(n *Ntopng)

func WithBaseUrl(url string) Option {
	return func(n *Ntopng) {
		if !strings.HasPrefix(url, "http") {
			url = "http://" + url
		}
		n.baseUrl = strings.TrimRight(url, "/")
	}
}

func WithBasicAuth(user, pass string) Option {
	return func(n *Ntopng) {
		auth := fmt.Sprintf("%v:%v", user, pass)
		n.token = "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
	}
}

func WithToken(token string) Option {
	return func(n *Ntopng) {
		n.token = "Token " + token
	}
}

func WithClient(client *http.Client) Option {
	return func(n *Ntopng) {
		n.client = client
	}
}

func WithTimeout(timeout time.Duration) Option {
	return func(n *Ntopng) {
		n.client.Timeout = timeout
	}
}

func WithTransport(transport http.RoundTripper) Option {
	return func(n *Ntopng) {
		n.client.Transport = transport
	}
}
