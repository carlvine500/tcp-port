package zookeeperport

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

// ---- Helpers ----

// buildZKFrame builds a complete ZK wire protocol frame.
// length is the total length including the 4-byte length field itself.
func buildZKFrame(xid, typ int32, body []byte) []byte {
	bodyLen := len(body)
	totalLen := int32(12 + bodyLen) // 4(length) + 4(xid) + 4(type) + body
	buf := make([]byte, totalLen)
	binary.BigEndian.PutUint32(buf[0:4], uint32(totalLen))
	binary.BigEndian.PutUint32(buf[4:8], uint32(xid))
	binary.BigEndian.PutUint32(buf[8:12], uint32(typ))
	copy(buf[12:], body)
	return buf
}

// juteString encodes a string in ZooKeeper Jute wire format:
// 4 bytes BE int32 length + string bytes.
func juteString(s string) []byte {
	buf := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(s)))
	copy(buf[4:], s)
	return buf
}

// ---- DetectZK tests ----

func TestDetectZK_Valid(t *testing.T) {
	// Build a valid ping request frame: length=12 (just header), xid=1, type=11
	frame := buildZKFrame(1, TypePing, nil)
	if !DetectZK(frame) {
		t.Errorf("DetectZK should return true for valid ping frame")
	}
}

func TestDetectZK_Invalid(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte{0x00, 0x00, 0x00}},
		{"wrong length", []byte{0x00, 0x00, 0x00, 0xFF}}, // length=255, data too short
		{"bad type 99", buildZKFrame(1, 99, nil)},
		{"bad type 0", buildZKFrame(1, 0, nil)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if DetectZK(tt.data) {
				t.Errorf("DetectZK should return false for %s", tt.name)
			}
		})
	}
}

// ---- ReadZKMessage tests ----

func TestReadZKMessage_Ping(t *testing.T) {
	// ping request: xid=3, type=ping(11), no body
	frame := buildZKFrame(3, TypePing, nil)
	r := bytes.NewReader(frame)

	msg, err := ReadZKMessage(r, "C->S")
	if err != nil {
		t.Fatalf("ReadZKMessage failed: %v", err)
	}

	req, ok := msg.(*ZKRequest)
	if !ok {
		t.Fatalf("expected *ZKRequest, got %T", msg)
	}
	if req.Type != TypePing {
		t.Errorf("Type = %d, want %d", req.Type, TypePing)
	}
	if req.XID != 3 {
		t.Errorf("XID = %d, want 3", req.XID)
	}
	if req.OpName != "ping" {
		t.Errorf("OpName = %s, want ping", req.OpName)
	}
	if req.Path != "" {
		t.Errorf("Path should be empty for ping, got %q", req.Path)
	}
}

func TestReadZKMessage_GetData(t *testing.T) {
	// getData request: xid=5, type=getData(4), body has path "/mynode"
	path := "/mynode"
	body := juteString(path) // path only
	frame := buildZKFrame(5, TypeGetData, body)
	r := bytes.NewReader(frame)

	msg, err := ReadZKMessage(r, "C->S")
	if err != nil {
		t.Fatalf("ReadZKMessage failed: %v", err)
	}

	req, ok := msg.(*ZKRequest)
	if !ok {
		t.Fatalf("expected *ZKRequest, got %T", msg)
	}
	if req.Type != TypeGetData {
		t.Errorf("Type = %d, want %d", req.Type, TypeGetData)
	}
	if req.XID != 5 {
		t.Errorf("XID = %d, want 5", req.XID)
	}
	if req.Path != path {
		t.Errorf("Path = %q, want %q", req.Path, path)
	}
}

func TestReadZKMessage_Create(t *testing.T) {
	// create request: xid=7, type=create(1), body has path "/newNode" + create flags
	path := "/newNode"
	// Jute body for create: path(string) + data(bytes) + acl(vector) + flags(int32)
	// Just path + zero-length data + zero ACL count + flags=0
	body := make([]byte, 0)
	body = append(body, juteString(path)...)          // path
	body = append(body, juteString("")...)             // data (zero-length)
	body = append(body, 0x00, 0x00, 0x00, 0x00)       // acl count = 0 (int32)
	body = append(body, 0x00, 0x00, 0x00, 0x00)       // flags = 0 (int32)

	frame := buildZKFrame(7, TypeCreate, body)
	r := bytes.NewReader(frame)

	msg, err := ReadZKMessage(r, "C->S")
	if err != nil {
		t.Fatalf("ReadZKMessage failed: %v", err)
	}

	req, ok := msg.(*ZKRequest)
	if !ok {
		t.Fatalf("expected *ZKRequest, got %T", msg)
	}
	if req.Type != TypeCreate {
		t.Errorf("Type = %d, want %d", req.Type, TypeCreate)
	}
	if req.XID != 7 {
		t.Errorf("XID = %d, want 7", req.XID)
	}
	if req.Path != path {
		t.Errorf("Path = %q, want %q", req.Path, path)
	}
}

func TestReadZKMessage_Response(t *testing.T) {
	// Response body: ReplyHeader (zxid=8 bytes + err=4 bytes) then response-specific body
	// Build a getData response with zxid=0x100, err=0
	zxid := int64(0x100)
	errCode := int32(0)
	respBody := make([]byte, 12)
	binary.BigEndian.PutUint64(respBody[0:8], uint64(zxid))
	binary.BigEndian.PutUint32(respBody[8:12], uint32(errCode))

	frame := buildZKFrame(5, TypeGetData, respBody)
	r := bytes.NewReader(frame)

	msg, err := ReadZKMessage(r, "S->C")
	if err != nil {
		t.Fatalf("ReadZKMessage failed: %v", err)
	}

	resp, ok := msg.(*ZKResponse)
	if !ok {
		t.Fatalf("expected *ZKResponse, got %T", msg)
	}
	if resp.OpName != "getData" {
		t.Errorf("OpName = %s, want getData", resp.OpName)
	}
	if resp.XID != 5 {
		t.Errorf("XID = %d, want 5", resp.XID)
	}
	if resp.ZXID != zxid {
		t.Errorf("ZXID = 0x%x, want 0x%x", resp.ZXID, zxid)
	}
	if resp.Err != errCode {
		t.Errorf("Err = %d, want %d", resp.Err, errCode)
	}
}

// ---- Additional detection edge cases ----

func TestDetectZK_LengthEdgeCases(t *testing.T) {
	// Valid frame where length exactly matches
	frame := buildZKFrame(1, TypePing, nil)
	if !DetectZK(frame) {
		t.Error("DetectZK should return true for exact-length frame")
	}

	// Frame with extra trailing data (still valid)
	frameExtra := append(frame, 0x00, 0x00)
	if !DetectZK(frameExtra) {
		t.Error("DetectZK should return true for frame with trailing data")
	}
}

// ---- Reader edge cases ----

func TestReadZKMessage_InvalidLength(t *testing.T) {
	// Frame where length field claims more data than available
	header := make([]byte, 3) // too short for even the header
	r := bytes.NewReader(header)
	_, err := ReadZKMessage(r, "C->S")
	if err == nil {
		t.Error("expected error for too-short data")
	}
	if err != io.EOF && err != io.ErrUnexpectedEOF {
		// This is fine - any error is acceptable for malformed data
	}
}

// ---- Formatting tests ----

func TestFormatZKRequest(t *testing.T) {
	req := &ZKRequest{
		Length:  12,
		XID:     1,
		Type:    TypePing,
		OpName:  "ping",
		Summary: "ping (xid=1, body=0 bytes)",
	}
	out := FormatZKRequest(req)
	if !strings.Contains(out, "ping") {
		t.Errorf("output should contain 'ping': %s", out)
	}
	if !strings.Contains(out, "XID: 1") {
		t.Errorf("output should contain 'XID: 1': %s", out)
	}
}

func TestFormatZKResponse(t *testing.T) {
	resp := &ZKResponse{
		Length:  24,
		XID:     1,
		ZXID:    0x100,
		Err:     0,
		OpName:  "ping",
		Summary: "ping response (zxid=0x100, xid=1)",
	}
	out := FormatZKResponse(resp)
	if !strings.Contains(out, "ping") {
		t.Errorf("output should contain 'ping': %s", out)
	}
	if !strings.Contains(out, "0x100") {
		t.Errorf("output should contain '0x100': %s", out)
	}
}

func TestFormatZKURL(t *testing.T) {
	req := &ZKRequest{
		OpName: "getData",
		Path:   "/my/node",
	}
	out := FormatZKURL(req)
	if !strings.Contains(out, "getData /my/node") {
		t.Errorf("output should contain path: %s", out)
	}

	reqNoPath := &ZKRequest{OpName: "ping"}
	out2 := FormatZKURL(reqNoPath)
	if !strings.Contains(out2, "ping") {
		t.Errorf("output should contain 'ping': %s", out2)
	}
}
