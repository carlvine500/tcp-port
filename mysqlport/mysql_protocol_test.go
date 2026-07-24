package mysqlport

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestDetectMySQL_Handshake(t *testing.T) {
	// Build a minimal server handshake packet
	payload := []byte{
		0x0a,                                           // protocol version 10
		'8', '.', '0', '.', '3', '6', 0x00,             // "8.0.36\0"
		0x01, 0x00, 0x00, 0x00,                         // connection ID = 1
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',         // auth data part 1
		0x00,                                           // filler
		0xff, 0xff,                                     // capability lower
		0x21,                                           // charset utf8mb4
		0x02, 0x00,                                     // status
		0xff, 0xff,                                     // capability upper
		0x15,                                           // auth data length
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reserved
		'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 0x00, // auth part 2
		'm', 'y', 's', 'q', 'l', '_', 'n', 'a', 't', 'i', 'v', 'e', '_', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 0x00, // plugin name
	}

	// Build packet: 3-byte len + 1-byte seq + payload
	pktLen := len(payload)
	pkt := make([]byte, 4+pktLen)
	pkt[0] = byte(pktLen)
	pkt[1] = byte(pktLen >> 8)
	pkt[2] = byte(pktLen >> 16)
	pkt[3] = 0 // seq 0
	copy(pkt[4:], payload)

	if !DetectMySQL(pkt) {
		t.Error("Should detect MySQL handshake packet")
	}
}

func TestDetectMySQL_Query(t *testing.T) {
	payload := []byte{ComQuery, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1'}
	pktLen := len(payload)
	pkt := make([]byte, 4+pktLen)
	pkt[0] = byte(pktLen)
	pkt[1] = 0
	pkt[2] = 0
	pkt[3] = 0
	copy(pkt[4:], payload)

	if !DetectMySQL(pkt) {
		t.Error("Should detect MySQL query packet")
	}
}

func TestDetectMySQL_NonMySQL(t *testing.T) {
	if DetectMySQL([]byte("GET / HTTP/1.1")) {
		t.Error("Should NOT detect HTTP as MySQL")
	}
	if DetectMySQL([]byte{0xda, 0xbb}) {
		t.Error("Should NOT detect Dubbo as MySQL")
	}
}

func TestCommandNames(t *testing.T) {
	if n := CommandName(ComQuery); n != "Query" {
		t.Errorf("ComQuery = %s, want Query", n)
	}
	if n := CommandName(ComPing); n != "Ping" {
		t.Errorf("ComPing = %s, want Ping", n)
	}
	if n := CommandName(ComStmtPrepare); n != "StmtPrepare" {
		t.Errorf("ComStmtPrepare = %s, want StmtPrepare", n)
	}
	if n := CommandName(0xff); n != "UNKNOWN(0xff)" {
		t.Errorf("Unknown = %s", n)
	}
}

func TestReadMySQLPacket(t *testing.T) {
	payload := []byte{ComQuery, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1'}
	pktLen := len(payload)
	raw := make([]byte, 4+pktLen)
	raw[0] = byte(pktLen)
	raw[1] = byte(pktLen >> 8)
	raw[2] = byte(pktLen >> 16)
	raw[3] = 5 // seq 5
	copy(raw[4:], payload)

	pkt, err := ReadMySQLPacket(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("ReadMySQLPacket failed: %v", err)
	}
	if pkt.SequenceID != 5 {
		t.Errorf("SequenceID = %d, want 5", pkt.SequenceID)
	}
	if pkt.Length != uint32(pktLen) {
		t.Errorf("Length = %d, want %d", pkt.Length, pktLen)
	}
	if pkt.Payload[0] != ComQuery {
		t.Errorf("First payload byte = 0x%02x, want ComQuery", pkt.Payload[0])
	}
}

func TestReadMySQLMessage_Query(t *testing.T) {
	query := "SELECT * FROM users WHERE id = 1"
	payload := []byte{ComQuery}
	payload = append(payload, []byte(query)...)

	pktLen := len(payload)
	raw := make([]byte, 4+pktLen)
	raw[0] = byte(pktLen)
	raw[1] = byte(pktLen >> 8)
	raw[2] = byte(pktLen >> 16)
	copy(raw[4:], payload)

	msg, err := ReadMySQLMessage(strings.NewReader(string(raw)), "C->S")
	if err != nil {
		t.Fatalf("ReadMySQLMessage failed: %v", err)
	}
	if msg.Type != "command" {
		t.Errorf("Type = %s, want command", msg.Type)
	}
	if msg.Command != ComQuery {
		t.Errorf("Command = 0x%02x, want ComQuery", msg.Command)
	}
	if msg.Query != query {
		t.Errorf("Query = %s, want %s", msg.Query, query)
	}
}

func TestReadMySQLMessage_Error(t *testing.T) {
	payload := []byte{
		ResponseERR,
		0x6a, 0x04, // error code 1130
		'#', '4', '2', '0', '0', '0',
		'H', 'o', 's', 't', ' ', 'n', 'o', 't', ' ', 'a', 'l', 'l', 'o', 'w', 'e', 'd',
	}
	pktLen := len(payload)
	raw := make([]byte, 4+pktLen)
	raw[0] = byte(pktLen)
	raw[1] = byte(pktLen >> 8)
	raw[2] = byte(pktLen >> 16)
	copy(raw[4:], payload)

	msg, err := ReadMySQLMessage(strings.NewReader(string(raw)), "S->C")
	if err != nil {
		t.Fatalf("ReadMySQLMessage failed: %v", err)
	}
	if msg.Type != "error" {
		t.Errorf("Type = %s, want error", msg.Type)
	}
	if msg.ErrorCode != 1130 {
		t.Errorf("ErrorCode = %d, want 1130", msg.ErrorCode)
	}
}

func TestReadLenEncInt(t *testing.T) {
	// 1-byte (value < 251)
	data := []byte{42}
	v, pos := readLenEncInt(data, 0)
	if v != 42 || pos != 1 {
		t.Errorf("1-byte: v=%d pos=%d, want v=42 pos=1", v, pos)
	}

	// 2-byte (0xfc prefix)
	data = []byte{0xfc, 0x34, 0x12}
	v, pos = readLenEncInt(data, 0)
	if v != 0x1234 || pos != 3 {
		t.Errorf("2-byte: v=%d pos=%d, want v=0x1234 pos=3", v, pos)
	}

	// 3-byte (0xfd prefix)
	data = []byte{0xfd, 0x78, 0x56, 0x34}
	v, pos = readLenEncInt(data, 0)
	if v != 0x345678 || pos != 4 {
		t.Errorf("3-byte: v=%d pos=%d, want v=0x345678 pos=4", v, pos)
	}

	// 8-byte (0xfe prefix)
	data = make([]byte, 9)
	data[0] = 0xfe
	binary.LittleEndian.PutUint64(data[1:], 0x0102030405060708)
	v, pos = readLenEncInt(data, 0)
	if v != 0x0102030405060708 || pos != 9 {
		t.Errorf("8-byte: v=%d pos=%d", v, pos)
	}
}

func TestSanitizeQuery(t *testing.T) {
	q := "SELECT *\nFROM   users\nWHERE  id = 1"
	clean := SanitizeQuery(q)
	if len(clean) > 0 && clean[0] != 'S' {
		t.Errorf("Sanitized query doesn't start with SELECT: %s", clean)
	}
	if strings.Contains(clean, "\n") {
		t.Error("Sanitized query contains newlines")
	}
}
