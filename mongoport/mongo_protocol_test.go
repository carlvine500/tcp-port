package mongoport

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func TestDetectMongo_OPMSG(t *testing.T) {
	// Build a minimal OP_MSG frame
	// Header: msgLen(4) + reqID(4) + respTo(4) + opCode(4) = 16
	// Body: flagBits(4) + kind(1) + bson doc with simple command
	bsonDoc := buildBSON(map[string]interface{}{"ping": int32(1)})
	bodyLen := 4 + 1 + len(bsonDoc) // flags + kind + bson

	msgLen := MsgHeaderSize + bodyLen
	buf := make([]byte, msgLen)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint32(buf[4:8], 1)  // requestID
	binary.LittleEndian.PutUint32(buf[8:12], 0) // responseTo
	binary.LittleEndian.PutUint32(buf[12:16], uint32(OpMsg))
	binary.LittleEndian.PutUint32(buf[16:20], 0) // flags
	buf[20] = 0                                   // kind=0 body only
	copy(buf[21:], bsonDoc)

	if !DetectMongo(buf) {
		t.Error("Should detect OP_MSG frame")
	}
}

func TestDetectMongo_OPQUERY(t *testing.T) {
	// Build a minimal OP_QUERY frame
	headerLen := 4 + 4 + 4 + 4
	body := []byte{
		0x00, 0x00, 0x00, 0x00, // flags
		't', 'e', 's', 't', '.', 'c', 'o', 'l', 'l', 0x00, // collection name
		0x00, 0x00, 0x00, 0x00, // skip
		0x01, 0x00, 0x00, 0x00, // batch size = 1
	}
	msgLen := headerLen + len(body)
	buf := make([]byte, msgLen)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint32(buf[4:8], 2)
	binary.LittleEndian.PutUint32(buf[8:12], 0)
	binary.LittleEndian.PutUint32(buf[12:16], uint32(OpQuery))
	copy(buf[16:], body)

	if !DetectMongo(buf) {
		t.Error("Should detect OP_QUERY frame")
	}
}

func TestDetectMongo_NonMongo(t *testing.T) {
	if DetectMongo([]byte("GET / HTTP/1.1\r\n")) {
		t.Error("Should NOT detect HTTP as Mongo")
	}
	// Too small
	small := make([]byte, 8)
	binary.LittleEndian.PutUint32(small[0:4], 8)
	if DetectMongo(small) {
		t.Error("Should NOT detect too-small frame")
	}
}

func TestOpcodeName(t *testing.T) {
	if n := OpcodeName(OpMsg); n != "OP_MSG" {
		t.Errorf("OpMsg = %s, want OP_MSG", n)
	}
	if n := OpcodeName(OpQuery); n != "OP_QUERY" {
		t.Errorf("OpQuery = %s, want OP_QUERY", n)
	}
	if n := OpcodeName(99999); n != "UNKNOWN(99999)" {
		t.Errorf("Unknown opcode = %s", n)
	}
}

func TestReadMongoMessage_OPMSG(t *testing.T) {
	bsonDoc := buildBSON(map[string]interface{}{"ping": int32(1)})
	bodyLen := 4 + 1 + len(bsonDoc)
	msgLen := MsgHeaderSize + bodyLen

	buf := make([]byte, msgLen)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint32(buf[4:8], 42)
	binary.LittleEndian.PutUint32(buf[8:12], 0)
	binary.LittleEndian.PutUint32(buf[12:16], uint32(OpMsg))
	binary.LittleEndian.PutUint32(buf[16:20], 0)
	buf[20] = 0
	copy(buf[21:], bsonDoc)

	msg, err := ReadMongoMessage(strings.NewReader(string(buf)), "C->S")
	if err != nil {
		t.Fatalf("ReadMongoMessage failed: %v", err)
	}
	if msg.Header.OpCode != OpMsg {
		t.Errorf("OpCode = %d, want OpMsg", msg.Header.OpCode)
	}
	if msg.Header.RequestID != 42 {
		t.Errorf("RequestID = %d, want 42", msg.Header.RequestID)
	}
	if msg.Command != "ping" {
		t.Errorf("Command = %s, want ping", msg.Command)
	}
}

func TestReadMongoMessage_OPQUERY(t *testing.T) {
	body := []byte{
		0x00, 0x00, 0x00, 0x00,
		't', 'e', 's', 't', '.', 'u', 's', 'e', 'r', 's', 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x00,
	}
	msgLen := MsgHeaderSize + len(body)
	buf := make([]byte, msgLen)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint32(buf[4:8], 1)
	binary.LittleEndian.PutUint32(buf[8:12], 0)
	binary.LittleEndian.PutUint32(buf[12:16], uint32(OpQuery))
	copy(buf[16:], body)

	msg, err := ReadMongoMessage(strings.NewReader(string(buf)), "C->S")
	if err != nil {
		t.Fatalf("ReadMongoMessage failed: %v", err)
	}
	if msg.FullCollectionName != "test.users" {
		t.Errorf("Collection = %s, want test.users", msg.FullCollectionName)
	}
	if msg.NumberToReturn != 10 {
		t.Errorf("NumberToReturn = %d, want 10", msg.NumberToReturn)
	}
}

func TestExtractBSONFirstKey(t *testing.T) {
	bsonDoc := buildBSON(map[string]interface{}{
		"find":    "users",
		"filter":  map[string]interface{}{"age": int32(25)},
		"batchSize": int32(100),
	})
	key := extractBSONFirstKey(bsonDoc)
	if key != "find" && key != "filter" && key != "batchSize" {
		t.Errorf("First key = %s, expected one of find/filter/batchSize", key)
	}
}

func TestBSONToJSON(t *testing.T) {
	bsonDoc := buildBSON(map[string]interface{}{
		"find":    "users",
		"filter":  map[string]interface{}{"age": int32(25)},
		"batchSize": int32(100),
	})
	json := bsonToJSON(bsonDoc)
	if json == "" {
		t.Error("bsonToJSON returned empty")
	}
	if !strings.Contains(json, `"find"`) {
		t.Errorf("JSON should contain find: %s", json)
	}
	if !strings.Contains(json, `"users"`) {
		t.Errorf("JSON should contain users: %s", json)
	}
	if !strings.Contains(json, `"age"`) {
		t.Errorf("JSON should contain age: %s", json)
	}
}

func TestReadMongoMessage_BSONBody(t *testing.T) {
	// Build a find command
	bsonDoc := buildBSON(map[string]interface{}{
		"find":   "orders",
		"filter": map[string]interface{}{"status": "pending"},
		"limit":  int32(50),
	})
	bodyLen := 4 + 1 + len(bsonDoc)
	msgLen := MsgHeaderSize + bodyLen
	buf := make([]byte, msgLen)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint32(buf[4:8], 100)
	binary.LittleEndian.PutUint32(buf[8:12], 0)
	binary.LittleEndian.PutUint32(buf[12:16], uint32(OpMsg))
	binary.LittleEndian.PutUint32(buf[16:20], 0)
	buf[20] = 0
	copy(buf[21:], bsonDoc)

	msg, err := ReadMongoMessage(strings.NewReader(string(buf)), "C->S")
	if err != nil {
		t.Fatalf("ReadMongoMessage failed: %v", err)
	}
	if msg.BSONBody == "" {
		t.Error("BSONBody should not be empty")
	}
	if !strings.Contains(msg.BSONBody, `"find"`) {
		t.Errorf("BSONBody should contain find: %s", msg.BSONBody)
	}
	if !strings.Contains(msg.BSONBody, `"orders"`) {
		t.Errorf("BSONBody should contain orders: %s", msg.BSONBody)
	}
	if !strings.Contains(msg.BSONBody, `"pending"`) {
		t.Errorf("BSONBody should contain pending: %s", msg.BSONBody)
	}
}

func TestReadMongoMessage_CursorResponse(t *testing.T) {
	// Build a cursor response
	cursorDoc := buildBSON(map[string]interface{}{
		"cursor": map[string]interface{}{
			"firstBatch": []interface{}{},
			"id":         int64(0),
			"ns":         "test.orders",
		},
		"ok": int32(1),
	})
	bodyLen := 4 + 1 + len(cursorDoc)
	msgLen := MsgHeaderSize + bodyLen
	buf := make([]byte, msgLen)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint32(buf[4:8], 200)
	binary.LittleEndian.PutUint32(buf[8:12], 100)
	binary.LittleEndian.PutUint32(buf[12:16], uint32(OpMsg))
	binary.LittleEndian.PutUint32(buf[16:20], 0)
	buf[20] = 0
	copy(buf[21:], cursorDoc)

	msg, err := ReadMongoMessage(strings.NewReader(string(buf)), "S->C")
	if err != nil {
		t.Fatalf("ReadMongoMessage failed: %v", err)
	}
	if msg.Command != "cursor" {
		t.Errorf("Command = %s, want cursor", msg.Command)
	}
	if msg.BSONBody == "" {
		t.Error("BSONBody should not be empty for cursor response")
	}
	if !strings.Contains(msg.BSONBody, `"ok"`) {
		t.Errorf("BSONBody should contain ok: %s", msg.BSONBody)
	}
}

// buildBSON creates a minimal BSON document for testing.
func buildBSON(fields map[string]interface{}) []byte {
	var buf []byte
	for key, val := range fields {
		switch v := val.(type) {
		case string:
			buf = append(buf, 0x02) // string type
			buf = append(buf, []byte(key)...)
			buf = append(buf, 0x00) // null terminator
			strLen := len(v) + 1
			lbuf := make([]byte, 4)
			binary.LittleEndian.PutUint32(lbuf, uint32(strLen))
			buf = append(buf, lbuf...)
			buf = append(buf, []byte(v)...)
			buf = append(buf, 0x00)
		case int32:
			buf = append(buf, 0x10) // int32 type
			buf = append(buf, []byte(key)...)
			buf = append(buf, 0x00)
			lbuf := make([]byte, 4)
			binary.LittleEndian.PutUint32(lbuf, uint32(v))
			buf = append(buf, lbuf...)
		case int64:
			buf = append(buf, 0x12) // int64 type
			buf = append(buf, []byte(key)...)
			buf = append(buf, 0x00)
			lbuf := make([]byte, 8)
			binary.LittleEndian.PutUint64(lbuf, uint64(v))
			buf = append(buf, lbuf...)
		case map[string]interface{}:
			buf = append(buf, 0x03) // embedded document
			buf = append(buf, []byte(key)...)
			buf = append(buf, 0x00)
			// buildBSON already prepends the total length, so use sub directly
			sub := buildBSON(v)
			buf = append(buf, sub...)
		case []interface{}:
			buf = append(buf, 0x04) // array
			buf = append(buf, []byte(key)...)
			buf = append(buf, 0x00)
			// Build array as BSON doc with "0", "1", ... keys
			arrMap := make(map[string]interface{})
			for i, item := range v {
				arrMap[fmt.Sprintf("%d", i)] = item
			}
			sub := buildBSON(arrMap)
			buf = append(buf, sub...)
		}
	}
	buf = append(buf, 0x00) // terminator

	// Prepend total length
	result := make([]byte, 4+len(buf))
	binary.LittleEndian.PutUint32(result[0:4], uint32(len(result)))
	copy(result[4:], buf)
	return result
}
