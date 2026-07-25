package websocketport

import (
	"bytes"
	"strings"
	"testing"
)

func TestDetectWebSocket_Handshake(t *testing.T) {
	// Client handshake: GET with Upgrade: websocket
	data := []byte("GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	if !DetectWebSocket(data) {
		t.Error("DetectWebSocket should detect WebSocket handshake")
	}
}

func TestDetectWebSocket_Frame(t *testing.T) {
	// Unmasked text frame: FIN=1, opcode=1 (text), no mask, payload length 5, "Hello"
	// Byte 0: 0x81 (FIN=1, opcode=1)
	// Byte 1: 0x05 (no mask, length 5)
	// Payload: "Hello"
	data := []byte{0x81, 0x05, 'H', 'e', 'l', 'l', 'o'}
	if !DetectWebSocket(data) {
		t.Error("DetectWebSocket should detect WebSocket frame")
	}
}

func TestDetectWebSocket_NonWS(t *testing.T) {
	// Plain HTTP without WebSocket upgrade
	data := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if DetectWebSocket(data) {
		t.Error("DetectWebSocket should NOT detect plain HTTP")
	}

	// Empty data
	if DetectWebSocket([]byte{}) {
		t.Error("DetectWebSocket should return false for empty data")
	}

	// Random binary that doesn't match valid opcode
	data = []byte{0x8F, 0x80} // opcode=0xF (invalid), masked
	if DetectWebSocket(data) {
		t.Error("DetectWebSocket should NOT detect invalid opcode")
	}
}

func TestReadWebSocketMessage_Text(t *testing.T) {
	// Build a text frame: FIN=1, opcode=1, masked, payload="Hello, WebSocket!"
	payload := []byte("Hello, WebSocket!")
	maskKey := []byte{0x12, 0x34, 0x56, 0x78}

	// Mask the payload
	maskedPayload := make([]byte, len(payload))
	for i := range payload {
		maskedPayload[i] = payload[i] ^ maskKey[i%4]
	}

	var buf bytes.Buffer
	// Byte 0: FIN(1) + opcode(1) = 0x81
	buf.WriteByte(0x81)
	// Byte 1: MASK(1) + len(17) = 0x80 | 17 = 0x91
	buf.WriteByte(0x80 | byte(len(payload)))
	buf.Write(maskKey)
	buf.Write(maskedPayload)

	r := bytes.NewReader(buf.Bytes())
	msg, err := ReadWebSocketMessage(r, "C→S")
	if err != nil {
		t.Fatalf("ReadWebSocketMessage failed: %v", err)
	}
	if !msg.FIN {
		t.Error("Expected FIN=true")
	}
	if msg.OpCode != OpText {
		t.Errorf("OpCode = %d, want %d", msg.OpCode, OpText)
	}
	if !msg.IsText {
		t.Error("Expected IsText=true")
	}
	if msg.Payload != "Hello, WebSocket!" {
		t.Errorf("Payload = %q, want %q", msg.Payload, "Hello, WebSocket!")
	}
	if msg.PayloadLen != 17 {
		t.Errorf("PayloadLen = %d, want 17", msg.PayloadLen)
	}
}

func TestReadWebSocketMessage_Binary(t *testing.T) {
	// Build a binary frame: FIN=1, opcode=2, masked, payload=4 bytes
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	maskKey := []byte{0xAA, 0xBB, 0xCC, 0xDD}

	maskedPayload := make([]byte, len(payload))
	for i := range payload {
		maskedPayload[i] = payload[i] ^ maskKey[i%4]
	}

	var buf bytes.Buffer
	buf.WriteByte(0x82) // FIN=1, opcode=2 (binary)
	buf.WriteByte(0x80 | byte(len(payload))) // MASK=1, len=4
	buf.Write(maskKey)
	buf.Write(maskedPayload)

	r := bytes.NewReader(buf.Bytes())
	msg, err := ReadWebSocketMessage(r, "C→S")
	if err != nil {
		t.Fatalf("ReadWebSocketMessage failed: %v", err)
	}
	if msg.OpCode != OpBinary {
		t.Errorf("OpCode = %d, want %d", msg.OpCode, OpBinary)
	}
	if !msg.IsBinary {
		t.Error("Expected IsBinary=true")
	}
	if msg.PayloadLen != 4 {
		t.Errorf("PayloadLen = %d, want 4", msg.PayloadLen)
	}
	if msg.Summary == "" {
		t.Error("Expected non-empty Summary")
	}
}

func TestReadWebSocketMessage_Ping(t *testing.T) {
	// Build a ping frame: FIN=1, opcode=9, masked, payload="ping-data"
	payload := []byte("ping-data")
	maskKey := []byte{0x01, 0x02, 0x03, 0x04}

	maskedPayload := make([]byte, len(payload))
	for i := range payload {
		maskedPayload[i] = payload[i] ^ maskKey[i%4]
	}

	var buf bytes.Buffer
	buf.WriteByte(0x89) // FIN=1, opcode=9 (ping)
	buf.WriteByte(0x80 | byte(len(payload))) // MASK=1, len=9
	buf.Write(maskKey)
	buf.Write(maskedPayload)

	r := bytes.NewReader(buf.Bytes())
	msg, err := ReadWebSocketMessage(r, "C→S")
	if err != nil {
		t.Fatalf("ReadWebSocketMessage failed: %v", err)
	}
	if msg.OpCode != OpPing {
		t.Errorf("OpCode = %d, want %d", msg.OpCode, OpPing)
	}
	if !msg.IsControl {
		t.Error("Expected IsControl=true for ping")
	}
	if msg.Summary == "" {
		t.Error("Expected non-empty Summary")
	}
}

func TestReadWebSocketMessage_Close(t *testing.T) {
	// Build a close frame: FIN=1, opcode=8, masked, close code=1000 + reason
	payload := make([]byte, 2+5) // 2 bytes code + 5 bytes reason
	payload[0] = 0x03 // status code 1000 = 0x03E8
	payload[1] = 0xE8
	copy(payload[2:], []byte("bye!!"))
	maskKey := []byte{0x11, 0x22, 0x33, 0x44}

	maskedPayload := make([]byte, len(payload))
	for i := range payload {
		maskedPayload[i] = payload[i] ^ maskKey[i%4]
	}

	var buf bytes.Buffer
	buf.WriteByte(0x88) // FIN=1, opcode=8 (close)
	buf.WriteByte(0x80 | byte(len(payload))) // MASK=1, len=7
	buf.Write(maskKey)
	buf.Write(maskedPayload)

	r := bytes.NewReader(buf.Bytes())
	msg, err := ReadWebSocketMessage(r, "C→S")
	if err != nil {
		t.Fatalf("ReadWebSocketMessage failed: %v", err)
	}
	if msg.OpCode != OpClose {
		t.Errorf("OpCode = %d, want %d", msg.OpCode, OpClose)
	}
	if !msg.IsControl {
		t.Error("Expected IsControl=true for close")
	}
	if !strings.Contains(msg.Payload, "code=1000") {
		t.Errorf("Payload should contain close code, got: %s", msg.Payload)
	}
}

func TestFormatWebSocketMessage(t *testing.T) {
	msg := &WebSocketMessage{
		OpCode:  OpText,
		OpName:  "Text",
		Payload: "Hello",
		IsText:  true,
		FIN:     true,
	}
	out := FormatWebSocketMessage(msg)
	if !bytes.Contains([]byte(out), []byte("Text")) {
		t.Error("Output should contain opcode name")
	}
	if !bytes.Contains([]byte(out), []byte("Hello")) {
		t.Error("Output should contain payload")
	}
}

func TestFormatWebSocketURL(t *testing.T) {
	msg := &WebSocketMessage{
		OpCode:  OpText,
		OpName:  "Text",
		Payload: "Hello",
		IsText:  true,
		Summary: `Text frame: "Hello"`,
	}
	out := FormatWebSocketURL(msg)
	if out == "" {
		t.Error("FormatWebSocketURL should not return empty string")
	}
}
