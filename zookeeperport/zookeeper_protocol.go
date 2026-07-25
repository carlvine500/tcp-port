package zookeeperport

import (
	"encoding/binary"
	"fmt"
	"io"
)

// ZK message type constants.
const (
	TypeNotification  int32 = -1
	TypeCreate        int32 = 1
	TypeDelete        int32 = 2
	TypeExists        int32 = 3
	TypeGetData       int32 = 4
	TypeSetData       int32 = 5
	TypeGetACL        int32 = 6
	TypeSetACL        int32 = 7
	TypeGetChildren   int32 = 8
	TypeSync          int32 = 9
	TypePing          int32 = 11
	TypeGetChildren2  int32 = 12
	TypeCheck         int32 = 13
	TypeMulti         int32 = 14
	TypeCreate2       int32 = 15
	TypeReconfig      int32 = 16
	TypeRemoveWatches int32 = 20

	// ZK message header size: 4(length) + 4(xid) + 4(type) = 12 bytes
	zkHeaderSize = 12
	// MaxZKMessageSize is a reasonable upper bound for a single ZK message.
	MaxZKMessageSize = 1 << 20 // 1 MB
)

var opcodeNames = map[int32]string{
	TypeNotification:  "notification",
	TypeCreate:        "create",
	TypeDelete:        "delete",
	TypeExists:        "exists",
	TypeGetData:       "getData",
	TypeSetData:       "setData",
	TypeGetACL:        "getACL",
	TypeSetACL:        "setACL",
	TypeGetChildren:   "getChildren",
	TypeSync:          "sync",
	TypePing:          "ping",
	TypeGetChildren2:  "getChildren2",
	TypeCheck:         "check",
	TypeMulti:         "multi",
	TypeCreate2:       "create2",
	TypeReconfig:      "reconfig",
	TypeRemoveWatches: "removeWatches",
}

// OpcodeName returns the human-readable name for a ZK opcode type.
func OpcodeName(t int32) string {
	if name, ok := opcodeNames[t]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", t)
}

// IsValidType returns true if t is a recognized ZooKeeper message type.
func IsValidType(t int32) bool {
	_, ok := opcodeNames[t]
	return ok
}

// ZKRequest represents a parsed ZooKeeper request message.
type ZKRequest struct {
	Length    int32
	XID       int32
	Type      int32
	OpName    string
	Path      string
	Summary   string
	Direction string
}

// ZKResponse represents a parsed ZooKeeper response message.
type ZKResponse struct {
	Length    int32
	XID       int32
	ZXID      int64
	Err       int32
	OpName    string
	Summary   string
	Direction string
}

// DetectZK checks if data looks like a ZooKeeper wire protocol message.
// It verifies: length >= 4, total length field matches (big-endian int32),
// and the type field is a valid ZK message type (-1 or 1-16 or 20).
func DetectZK(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	totalLen := int32(binary.BigEndian.Uint32(data[0:4]))
	if totalLen < zkHeaderSize || totalLen > MaxZKMessageSize {
		return false
	}
	if totalLen < 4 || int(totalLen) > len(data) {
		return false
	}
	if len(data) < 12 {
		return false
	}
	typ := int32(binary.BigEndian.Uint32(data[8:12]))
	return IsValidType(typ)
}

// ReadZKMessage reads a complete ZooKeeper message from reader.
// Returns *ZKRequest for client→server messages, *ZKResponse for server→client
// messages. Direction should be "C->S" or "S->C".
func ReadZKMessage(r io.Reader, direction string) (interface{}, error) {
	// Read the 12-byte header
	header := make([]byte, zkHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	totalLen := int32(binary.BigEndian.Uint32(header[0:4]))
	xid := int32(binary.BigEndian.Uint32(header[4:8]))
	typ := int32(binary.BigEndian.Uint32(header[8:12]))

	if totalLen < zkHeaderSize || totalLen > MaxZKMessageSize {
		return nil, fmt.Errorf("invalid ZK message length: %d", totalLen)
	}

	// Read remaining body
	bodyLen := totalLen - zkHeaderSize
	body := make([]byte, bodyLen)
	if bodyLen > 0 {
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, err
		}
	}

	opName := OpcodeName(typ)
	isRequest := direction == "C->S"

	if isRequest {
		return parseZKRequest(totalLen, xid, typ, opName, body, direction), nil
	}
	return parseZKResponse(totalLen, xid, typ, opName, body, direction), nil
}

func parseZKRequest(length, xid, typ int32, opName string, body []byte, direction string) *ZKRequest {
	req := &ZKRequest{
		Length:    length,
		XID:       xid,
		Type:      typ,
		OpName:    opName,
		Direction: direction,
	}

	// Best-effort path extraction from body (first Jute string)
	req.Path = extractFirstString(body)

	if req.Path != "" {
		req.Summary = fmt.Sprintf("%s %s (xid=%d)", opName, req.Path, xid)
	} else {
		req.Summary = fmt.Sprintf("%s (xid=%d, body=%d bytes)", opName, xid, len(body))
	}

	return req
}

func parseZKResponse(length, xid, typ int32, opName string, body []byte, direction string) *ZKResponse {
	resp := &ZKResponse{
		Length:    length,
		XID:       xid,
		OpName:    opName,
		Direction: direction,
	}

	// Response body starts with ReplyHeader: zxid (8 bytes BE int64) + err (4 bytes BE int32)
	if len(body) >= 12 {
		resp.ZXID = int64(binary.BigEndian.Uint64(body[0:8]))
		resp.Err = int32(binary.BigEndian.Uint32(body[8:12]))
	}

	if resp.Err != 0 {
		resp.Summary = fmt.Sprintf("%s response (zxid=0x%x, err=%d, xid=%d)", opName, resp.ZXID, resp.Err, xid)
	} else {
		resp.Summary = fmt.Sprintf("%s response (zxid=0x%x, xid=%d)", opName, resp.ZXID, xid)
	}

	return resp
}

// extractFirstString extracts the first Jute-encoded string from body data.
// Jute string format: 4 bytes BE int32 length + string content.
// Returns empty string if the body is too short or parsing fails.
func extractFirstString(body []byte) string {
	if len(body) < 4 {
		return ""
	}
	strLen := int32(binary.BigEndian.Uint32(body[0:4]))
	if strLen < 0 {
		return ""
	}
	start := 4
	end := start + int(strLen)
	if end > len(body) {
		return ""
	}
	return string(body[start:end])
}
