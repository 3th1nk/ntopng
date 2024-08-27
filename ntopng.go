package ntopng

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Ntopng struct {
	client  *http.Client
	baseUrl string
	token   string
}

func New(opts ...Option) *Ntopng {
	var client http.Client
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConnsPerHost = 32
	t.IdleConnTimeout = time.Minute
	t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client.Transport = t
	client.Timeout = time.Minute
	obj := &Ntopng{
		client:  &client,
		baseUrl: "http://localhost:3000",
	}
	for _, opt := range opts {
		opt(obj)
	}
	if obj.token == "" {
		WithBasicAuth("admin", "admin")(obj)
	}
	return obj
}

func (this *Ntopng) Get(path string, headers, params map[string]interface{}) ([]byte, error) {
	reqUrl := this.baseUrl + path
	if len(params) > 0 {
		var arr []string
		for k, v := range params {
			arr = append(arr, fmt.Sprintf("%v=%v", k, v))
		}
		reqUrl += "?" + strings.Join(arr, "&")
	}

	req, err := http.NewRequest(http.MethodGet, reqUrl, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", this.token)
	for k, v := range headers {
		req.Header.Set(k, fmt.Sprintf("%v", v))
	}

	resp, err := this.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(resp.Status)
	}

	return io.ReadAll(resp.Body)
}

func (this *Ntopng) Post(path string, headers, body map[string]interface{}) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, this.baseUrl+path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	req.Header.Set("Authorization", this.token)
	for k, v := range headers {
		req.Header.Set(k, fmt.Sprintf("%v", v))
	}

	resp, err := this.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(resp.Status)
	}

	return io.ReadAll(resp.Body)
}
