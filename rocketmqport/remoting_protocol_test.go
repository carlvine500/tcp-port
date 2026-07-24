package rocketmqport

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func TestDetectRocketMQ(t *testing.T) {
	// Build a minimal valid RocketMQ frame
	header := map[string]interface{}{
		"code":     10,
		"language": "JAVA",
		"version":  1,
		"opaque":   1,
		"flag":     0,
		"remark":   "",
	}
	headerJSON, _ := json.Marshal(header)
	headerLen := 4 + len(headerJSON) // includes the 4-byte length field
	frameLen := 4 + headerLen        // frame length = 4 + header length

	buf := make([]byte, frameLen)
	binary.BigEndian.PutUint32(buf[0:4], uint32(frameLen))
	binary.BigEndian.PutUint32(buf[4:8], uint32(headerLen))
	copy(buf[8:], headerJSON)

	if !DetectRocketMQ(buf) {
		t.Error("Should detect valid RocketMQ frame")
	}

	// Bad frame (too small)
	bad := make([]byte, 5)
	binary.BigEndian.PutUint32(bad[0:4], 5)
	if DetectRocketMQ(bad) {
		t.Error("Should not detect too-small frame")
	}

	// Non-rocketmq data
	if DetectRocketMQ([]byte("GET / HTTP/1.1\r\n")) {
		t.Error("Should not detect HTTP as RocketMQ")
	}
}

func TestReadRemotingCommand(t *testing.T) {
	header := map[string]interface{}{
		"code":     10,
		"language": "JAVA",
		"version":  1,
		"opaque":   42,
		"flag":     0,
		"remark":   "",
		"extFields": map[string]string{
			"topic":        "TestTopic",
			"consumerGroup": "TestGroup",
		},
	}
	headerJSON, _ := json.Marshal(header)
	headerLen := 4 + len(headerJSON)
	body := []byte("hello world")
	frameLen := 4 + headerLen + len(body)

	buf := make([]byte, frameLen)
	binary.BigEndian.PutUint32(buf[0:4], uint32(frameLen))
	binary.BigEndian.PutUint32(buf[4:8], uint32(headerLen))
	copy(buf[8:8+len(headerJSON)], headerJSON)
	copy(buf[8+len(headerJSON):], body)

	cmd, err := ReadRemotingCommand(strings.NewReader(string(buf)))
	if err != nil {
		t.Fatalf("ReadRemotingCommand failed: %v", err)
	}

	if cmd.Code != 10 {
		t.Errorf("Code = %d, want 10", cmd.Code)
	}
	if cmd.Language != "JAVA" {
		t.Errorf("Language = %s, want JAVA", cmd.Language)
	}
	if cmd.Opaque != 42 {
		t.Errorf("Opaque = %d, want 42", cmd.Opaque)
	}
	if len(cmd.Body) != len(body) {
		t.Errorf("Body len = %d, want %d", len(cmd.Body), len(body))
	}
	if cmd.ExtFields["topic"] != "TestTopic" {
		t.Errorf("Topic = %s, want TestTopic", cmd.ExtFields["topic"])
	}
}

func TestRequestCodeName(t *testing.T) {
	if name := RequestCodeName(10); name != "SEND_MESSAGE" {
		t.Errorf("Code 10 = %s, want SEND_MESSAGE", name)
	}
	if name := RequestCodeName(99999); name != "UNKNOWN(99999)" {
		t.Errorf("Unknown code: %s", name)
	}
}

func TestReadRemotingCommandInvalid(t *testing.T) {
	// Too small
	_, err := ReadRemotingCommand(strings.NewReader("\x00\x00\x00\x05"))
	if err == nil {
		t.Error("Expected error for too-small frame")
	}
}
