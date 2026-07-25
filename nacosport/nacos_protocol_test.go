package nacosport

import (
	"strings"
	"testing"
)

func TestDetectNacos_ServiceRegistry(t *testing.T) {
	data := []byte("POST /nacos/v1/ns/instance HTTP/1.1\r\nHost: 127.0.0.1:8848\r\n\r\n")
	if !DetectNacos(data) {
		t.Error("DetectNacos should detect POST /nacos/v1/ns/instance")
	}
}

func TestDetectNacos_ConfigGet(t *testing.T) {
	data := []byte("GET /nacos/v1/cs/configs?dataId=test&group=DEFAULT_GROUP HTTP/1.1\r\n")
	if !DetectNacos(data) {
		t.Error("DetectNacos should detect GET /nacos/v1/cs/configs")
	}
}

func TestDetectNacos_Heartbeat(t *testing.T) {
	data := []byte("PUT /nacos/v1/ns/instance/beat HTTP/1.1\r\nHost: 127.0.0.1:8848\r\n\r\n")
	if !DetectNacos(data) {
		t.Error("DetectNacos should detect PUT /nacos/v1/ns/instance/beat")
	}
}

func TestDetectNacos_NonNacos(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"plain HTTP", []byte("GET /api/users HTTP/1.1\r\n")},
		{"empty", []byte{}},
		{"too short", []byte("SHORT")},
		{"binary", []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}},
		{"HTTP response", []byte("HTTP/1.1 200 OK\r\n")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if DetectNacos(tt.data) {
				t.Errorf("DetectNacos(%q) should return false", tt.data)
			}
		})
	}
}

func TestReadNacosMessage_Request(t *testing.T) {
	raw := "POST /nacos/v1/ns/instance?namespaceId=public&groupName=DEFAULT_GROUP HTTP/1.1\r\n" +
		"Host: 127.0.0.1:8848\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 50\r\n" +
		"\r\n" +
		`{"serviceName":"demo","ip":"10.0.0.1","port":8080}`

	msg, err := ReadNacosMessage(strings.NewReader(raw), "C->S")
	if err != nil {
		t.Fatalf("ReadNacosMessage failed: %v", err)
	}

	if msg.Method != "POST" {
		t.Errorf("Method = %s, want POST", msg.Method)
	}
	if msg.Path != "/nacos/v1/ns/instance" {
		t.Errorf("Path = %s, want /nacos/v1/ns/instance", msg.Path)
	}
	if msg.APIType != "service" {
		t.Errorf("APIType = %s, want service", msg.APIType)
	}
	if msg.Direction != "C->S" {
		t.Errorf("Direction = %s, want C->S", msg.Direction)
	}
	if msg.Params["namespaceId"] != "public" {
		t.Errorf("Params[namespaceId] = %s, want public", msg.Params["namespaceId"])
	}
	if msg.Params["groupName"] != "DEFAULT_GROUP" {
		t.Errorf("Params[groupName] = %s, want DEFAULT_GROUP", msg.Params["groupName"])
	}
	if msg.Body != `{"serviceName":"demo","ip":"10.0.0.1","port":8080}` {
		t.Errorf("Body = %s", msg.Body)
	}
	if msg.Summary == "" {
		t.Error("Summary should not be empty")
	}
}

func TestReadNacosMessage_Response(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 15\r\n" +
		"\r\n" +
		`{"code":0,"ok"}`

	msg, err := ReadNacosMessage(strings.NewReader(raw), "S->C")
	if err != nil {
		t.Fatalf("ReadNacosMessage failed: %v", err)
	}

	if msg.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", msg.StatusCode)
	}
	if msg.Direction != "S->C" {
		t.Errorf("Direction = %s, want S->C", msg.Direction)
	}
	if msg.Body != `{"code":0,"ok"}` {
		t.Errorf("Body = %s", msg.Body)
	}
	if msg.Summary == "" {
		t.Error("Summary should not be empty")
	}
}

func TestClassifyNacosPath(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/nacos/v1/ns/instance/beat", "heartbeat"},
		{"/nacos/v1/ns/instance", "service"},
		{"/nacos/v1/ns/instance/list", "discovery"},
		{"/nacos/v1/cs/configs", "config"},
		{"/nacos/v1/ns/service/list", "service_list"},
		{"/nacos/v1/auth/login", "auth"},
		{"/nacos/v1/ns/operator/switches", "nacos"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := classifyNacosPath(tt.path)
			if got != tt.expected {
				t.Errorf("classifyNacosPath(%s) = %s, want %s", tt.path, got, tt.expected)
			}
		})
	}
}

func TestFormatNacosMessage(t *testing.T) {
	// Request formatting — with form params parsed from body
	t.Run("request", func(t *testing.T) {
		msg := &NacosMessage{
			Method:    "POST",
			Path:      "/nacos/v1/ns/instance",
			APIType:   "service",
			Direction: "C->S",
			Params:    map[string]string{"namespaceId": "public", "serviceName": "demo", "ip": "10.0.0.1", "port": "8080"},
			Summary:   "[Nacos service] POST /nacos/v1/ns/instance",
		}
		out := FormatNacosMessage(msg)
		if !strings.Contains(out, "[Nacos service]") {
			t.Errorf("output should contain [Nacos service], got: %s", out)
		}
		if !strings.Contains(out, "namespaceId:") {
			t.Errorf("output should contain namespaceId:, got: %s", out)
		}
		if !strings.Contains(out, "serviceName:") {
			t.Errorf("output should contain serviceName:, got: %s", out)
		}
		if !strings.Contains(out, "ip:") {
			t.Errorf("output should contain ip:, got: %s", out)
		}
	})

	// Response formatting
	t.Run("response", func(t *testing.T) {
		msg := &NacosMessage{
			StatusCode: 200,
			Direction:  "S->C",
			Body:       `{"code":0}`,
			Summary:    "[Nacos] HTTP 200",
		}
		out := FormatNacosMessage(msg)
		if !strings.Contains(out, "[Nacos] HTTP 200") {
			t.Errorf("output should contain [Nacos] HTTP 200, got: %s", out)
		}
		if !strings.Contains(out, "Status: 200") {
			t.Errorf("output should contain Status: 200, got: %s", out)
		}
	})
}

func TestFormatNacosURL(t *testing.T) {
	// Request URL formatting
	t.Run("request_with_params", func(t *testing.T) {
		msg := &NacosMessage{
			Method:  "GET",
			Path:    "/nacos/v1/cs/configs",
			APIType: "config",
			Params:  map[string]string{"dataId": "test", "group": "DEFAULT_GROUP"},
		}
		out := FormatNacosURL(msg)
		if !strings.Contains(out, "[config] GET /nacos/v1/cs/configs") {
			t.Errorf("output should contain [config] GET /nacos/v1/cs/configs, got: %s", out)
		}
		if !strings.Contains(out, "dataId=test") {
			t.Errorf("output should contain dataId=test, got: %s", out)
		}
	})

	// Response URL formatting
	t.Run("response", func(t *testing.T) {
		msg := &NacosMessage{
			StatusCode: 200,
		}
		out := FormatNacosURL(msg)
		if !strings.Contains(out, "200") {
			t.Errorf("FormatNacosURL should contain 200, got: %q", out)
		}
	})
}
