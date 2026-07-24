package httpport

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestDetectHTTP(t *testing.T) {
	tests := []struct {
		data []byte
		want bool
	}{
		{[]byte("GET / HTTP/1.1\r\n"), true},
		{[]byte("POST /api HTTP/1.1\r\n"), true},
		{[]byte("HTTP/1.1 200 OK\r\n"), true},
		{[]byte("HTTP/1.0 404 Not Found\r\n"), true},
		{[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, false},
		{[]byte("SHORT"), false},
	}

	for _, tt := range tests {
		if got := DetectHTTP(tt.data); got != tt.want {
			t.Errorf("DetectHTTP(%q) = %v, want %v", tt.data, got, tt.want)
		}
	}
}

func TestReadHTTPRequest(t *testing.T) {
	// Standard GET request with headers
	t.Run("GET", func(t *testing.T) {
		raw := "GET /index.html HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"User-Agent: TestAgent/1.0\r\n" +
			"Accept: text/html\r\n" +
			"\r\n"
		r := bufio.NewReader(strings.NewReader(raw))
		msg, err := ReadHTTPMessage(r)
		if err != nil {
			t.Fatalf("ReadHTTPMessage failed: %v", err)
		}
		if msg.Type != "request" {
			t.Errorf("Type = %s, want request", msg.Type)
		}
		if msg.Method != "GET" {
			t.Errorf("Method = %s, want GET", msg.Method)
		}
		if msg.Path != "/index.html" {
			t.Errorf("Path = %s, want /index.html", msg.Path)
		}
		if msg.RawLine != "GET /index.html HTTP/1.1" {
			t.Errorf("RawLine = %s", msg.RawLine)
		}
		if v := msg.Headers["host"]; v != "example.com" {
			t.Errorf("Headers[host] = %s, want example.com", v)
		}
		if v := msg.Headers["user-agent"]; v != "TestAgent/1.0" {
			t.Errorf("Headers[user-agent] = %s, want TestAgent/1.0", v)
		}
		if v := msg.Headers["accept"]; v != "text/html" {
			t.Errorf("Headers[accept] = %s, want text/html", v)
		}
		if len(msg.RawHeaders) != 3 {
			t.Errorf("len(RawHeaders) = %d, want 3", len(msg.RawHeaders))
		}
	})

	// POST request with Content-Type and Content-Length
	t.Run("POST", func(t *testing.T) {
		raw := "POST /api/data HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Content-Type: application/json\r\n" +
			"Content-Length: 42\r\n" +
			"\r\n"
		r := bufio.NewReader(strings.NewReader(raw))
		msg, err := ReadHTTPMessage(r)
		if err != nil {
			t.Fatalf("ReadHTTPMessage failed: %v", err)
		}
		if msg.Type != "request" {
			t.Errorf("Type = %s, want request", msg.Type)
		}
		if msg.Method != "POST" {
			t.Errorf("Method = %s, want POST", msg.Method)
		}
		if msg.Path != "/api/data" {
			t.Errorf("Path = %s, want /api/data", msg.Path)
		}
		if v := msg.Headers["content-type"]; v != "application/json" {
			t.Errorf("Headers[content-type] = %s, want application/json", v)
		}
		if v := msg.Headers["content-length"]; v != "42" {
			t.Errorf("Headers[content-length] = %s, want 42", v)
		}
		if msg.BodySize != 42 {
			t.Errorf("BodySize = %d, want 42", msg.BodySize)
		}
	})
}

func TestReadHTTPResponse(t *testing.T) {
	// Standard 200 response with headers
	t.Run("200 OK", func(t *testing.T) {
		raw := "HTTP/1.1 200 OK\r\n" +
			"Content-Type: text/html\r\n" +
			"Content-Length: 1234\r\n" +
			"Server: nginx\r\n" +
			"\r\n"
		r := bufio.NewReader(strings.NewReader(raw))
		msg, err := ReadHTTPMessage(r)
		if err != nil {
			t.Fatalf("ReadHTTPMessage failed: %v", err)
		}
		if msg.Type != "response" {
			t.Errorf("Type = %s, want response", msg.Type)
		}
		if msg.StatusCode != 200 {
			t.Errorf("StatusCode = %d, want 200", msg.StatusCode)
		}
		if msg.StatusText != "OK" {
			t.Errorf("StatusText = %s, want OK", msg.StatusText)
		}
		if msg.RawLine != "HTTP/1.1 200 OK" {
			t.Errorf("RawLine = %s", msg.RawLine)
		}
		if v := msg.Headers["content-type"]; v != "text/html" {
			t.Errorf("Headers[content-type] = %s, want text/html", v)
		}
		if v := msg.Headers["content-length"]; v != "1234" {
			t.Errorf("Headers[content-length] = %s, want 1234", v)
		}
		if v := msg.Headers["server"]; v != "nginx" {
			t.Errorf("Headers[server] = %s, want nginx", v)
		}
		if msg.BodySize != 1234 {
			t.Errorf("BodySize = %d, want 1234", msg.BodySize)
		}
		if len(msg.RawHeaders) != 3 {
			t.Errorf("len(RawHeaders) = %d, want 3", len(msg.RawHeaders))
		}
	})

	// 404 response
	t.Run("404 Not Found", func(t *testing.T) {
		raw := "HTTP/1.1 404 Not Found\r\n" +
			"Server: nginx\r\n" +
			"\r\n"
		r := bufio.NewReader(strings.NewReader(raw))
		msg, err := ReadHTTPMessage(r)
		if err != nil {
			t.Fatalf("ReadHTTPMessage failed: %v", err)
		}
		if msg.Type != "response" {
			t.Errorf("Type = %s, want response", msg.Type)
		}
		if msg.StatusCode != 404 {
			t.Errorf("StatusCode = %d, want 404", msg.StatusCode)
		}
		if msg.StatusText != "Not Found" {
			t.Errorf("StatusText = %s, want Not Found", msg.StatusText)
		}
	})
}

func TestFormatHTTP(t *testing.T) {
	// Request formatting
	t.Run("request", func(t *testing.T) {
		msg := &HTTPMessage{
			Type:    "request",
			Method:  "GET",
			Path:    "/",
			Headers: map[string]string{"host": "example.com"},
		}
		out := FormatHTTP(msg)
		if !bytes.Contains([]byte(out), []byte("GET /")) {
			t.Errorf("Output should contain GET /, got: %s", out)
		}
		if !bytes.Contains([]byte(out), []byte("host: example.com")) {
			t.Errorf("Output should contain host header, got: %s", out)
		}
	})

	// Response formatting
	t.Run("response", func(t *testing.T) {
		msg := &HTTPMessage{
			Type:       "response",
			StatusCode: 200,
			StatusText: "OK",
			Headers:    map[string]string{"server": "nginx", "content-type": "text/html"},
		}
		out := FormatHTTP(msg)
		if !bytes.Contains([]byte(out), []byte("200 OK")) {
			t.Errorf("Output should contain 200 OK, got: %s", out)
		}
		if !bytes.Contains([]byte(out), []byte("server: nginx")) {
			t.Errorf("Output should contain server header, got: %s", out)
		}
		if !bytes.Contains([]byte(out), []byte("content-type: text/html")) {
			t.Errorf("Output should contain content-type header, got: %s", out)
		}
	})

	// URL-level formatting
	t.Run("url_request", func(t *testing.T) {
		msg := &HTTPMessage{
			Type:   "request",
			Method: "POST",
			Path:   "/api/data",
		}
		out := FormatHTTPURL(msg)
		expected := "POST /api/data\n"
		if out != expected {
			t.Errorf("FormatHTTPURL = %q, want %q", out, expected)
		}
	})

	t.Run("url_response", func(t *testing.T) {
		msg := &HTTPMessage{
			Type:       "response",
			StatusCode: 404,
			StatusText: "Not Found",
		}
		out := FormatHTTPURL(msg)
		expected := "404 Not Found\n"
		if out != expected {
			t.Errorf("FormatHTTPURL = %q, want %q", out, expected)
		}
	})
}

func TestDetectHTTPEdgeCases(t *testing.T) {
	// Empty data
	t.Run("empty", func(t *testing.T) {
		if DetectHTTP([]byte{}) != false {
			t.Error("DetectHTTP on empty data should return false")
		}
	})

	// Incomplete line - no newline, ReadHTTPMessage should error
	t.Run("incomplete_line", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader("GET / HT"))
		_, err := ReadHTTPMessage(r)
		if err == nil {
			t.Error("ReadHTTPMessage on incomplete line should return error")
		}
	})

	// Only spaces - long enough but not valid HTTP
	t.Run("only_spaces", func(t *testing.T) {
		if DetectHTTP([]byte("        ")) != false {
			t.Error("DetectHTTP on spaces should return false")
		}
	})
}
