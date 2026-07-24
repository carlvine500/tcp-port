package mongoport

import (
	"encoding/binary"
	"fmt"
	"io"
)

// MongoDB wire protocol constants.
const (
	MsgHeaderSize = 16 // 4+4+4+4
	MaxMsgSize    = 48 * 1024 * 1024 // 48MB max BSON
	MinMsgSize    = MsgHeaderSize

	// Opcodes
	OpReply         int32 = 1
	OpUpdate        int32 = 2001
	OpInsert        int32 = 2002
	OpReserved      int32 = 2003
	OpQuery         int32 = 2004
	OpGetMore       int32 = 2005
	OpDelete        int32 = 2006
	OpKillCursors   int32 = 2007
	OpCommand       int32 = 2010
	OpCommandReply  int32 = 2011
	OpMsg           int32 = 2013 // MongoDB 3.6+ primary
)

var opcodeNames = map[int32]string{
	OpReply:        "OP_REPLY",
	OpUpdate:       "OP_UPDATE",
	OpInsert:       "OP_INSERT",
	OpReserved:     "RESERVED",
	OpQuery:        "OP_QUERY",
	OpGetMore:      "OP_GET_MORE",
	OpDelete:       "OP_DELETE",
	OpKillCursors:  "OP_KILL_CURSORS",
	OpCommand:      "OP_COMMAND",
	OpCommandReply: "OP_COMMANDREPLY",
	OpMsg:          "OP_MSG",
}

// OpcodeName returns the human-readable opcode name.
func OpcodeName(op int32) string {
	if name, ok := opcodeNames[op]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", op)
}

// MsgHeader represents the standard 16-byte MongoDB message header.
type MsgHeader struct {
	MessageLength int32
	RequestID     int32
	ResponseTo    int32
	OpCode        int32
}

// MongoMessage represents a decoded MongoDB wire protocol message.
type MongoMessage struct {
	Header MsgHeader

	// OP_MSG (2013) fields
	FlagBits   uint32
	Kind       byte   // 0=body only, 1=document sequence
	BodySize   int    // rough size of BSON body
	Collection string // extracted from BSON body (best effort)
	Command    string // extracted command name

	// OP_QUERY (2004) fields
	FullCollectionName string
	NumberToSkip       int32
	NumberToReturn     int32

	// Generic
	Direction string
	Summary   string
}

// ReadMongoMessage reads a complete MongoDB message from reader.
func ReadMongoMessage(r io.Reader, direction string) (*MongoMessage, error) {
	headerBuf := make([]byte, MsgHeaderSize)
	if _, err := io.ReadFull(r, headerBuf); err != nil {
		return nil, err
	}

	header := MsgHeader{
		MessageLength: int32(binary.LittleEndian.Uint32(headerBuf[0:4])),
		RequestID:     int32(binary.LittleEndian.Uint32(headerBuf[4:8])),
		ResponseTo:    int32(binary.LittleEndian.Uint32(headerBuf[8:12])),
		OpCode:        int32(binary.LittleEndian.Uint32(headerBuf[12:16])),
	}

	if header.MessageLength < MinMsgSize || header.MessageLength > MaxMsgSize {
		return nil, fmt.Errorf("invalid message length: %d", header.MessageLength)
	}

	// Read remaining body
	bodyLen := header.MessageLength - MsgHeaderSize
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}

	msg := &MongoMessage{
		Header:    header,
		Direction: direction,
		BodySize:  len(body),
	}

	msg.parseBody(body)
	return msg, nil
}

func (msg *MongoMessage) parseBody(body []byte) {
	switch msg.Header.OpCode {
	case OpMsg:
		msg.parseOpMsg(body)
	case OpQuery:
		msg.parseOpQuery(body)
	case OpReply:
		msg.parseOpReply(body)
	case OpInsert:
		msg.parseOpInsert(body)
	case OpUpdate:
		msg.TypeAs("UPDATE")
	case OpDelete:
		msg.TypeAs("DELETE")
	case OpGetMore:
		msg.TypeAs("GET_MORE")
	case OpKillCursors:
		msg.TypeAs("KILL_CURSORS")
	case OpCommand:
		msg.parseOpCommand(body)
	case OpCommandReply:
		msg.TypeAs("COMMAND_REPLY")
	default:
		msg.TypeAs(OpcodeName(msg.Header.OpCode))
	}
}

func (msg *MongoMessage) TypeAs(t string) {
	msg.Summary = fmt.Sprintf("%s (body=%d bytes)", t, msg.BodySize)
}

// parseOpMsg parses OP_MSG format (MongoDB 3.6+).
func (msg *MongoMessage) parseOpMsg(body []byte) {
	if len(body) < 5 {
		msg.TypeAs("OP_MSG (truncated)")
		return
	}

	msg.FlagBits = binary.LittleEndian.Uint32(body[0:4])
	msg.Kind = body[4]

	// Try to extract command name from BSON body
	bodyData := body[5:]
	if msg.Kind == 1 && len(bodyData) > 0 {
		// Document sequence: skip sequence section, find body section
		// Simplified: just scan the body section
		idx := findBodySection(bodyData)
		if idx >= 0 && idx < len(bodyData) {
			bodyData = bodyData[idx:]
		}
	}

	// Extract first key from BSON document (the command name)
	msg.Command = extractBSONFirstKey(bodyData)
	if msg.Command != "" {
		msg.Summary = fmt.Sprintf("OP_MSG %s (body=%d bytes)", msg.Command, msg.BodySize)
	} else {
		msg.Summary = fmt.Sprintf("OP_MSG (body=%d bytes, kind=%d)", msg.BodySize, msg.Kind)
	}

	// Also try to find collection name
	msg.Collection = extractBSONValue(bodyData, msg.Command)
}

// parseOpQuery parses OP_QUERY format (legacy).
func (msg *MongoMessage) parseOpQuery(body []byte) {
	if len(body) < 12 {
		msg.TypeAs(fmt.Sprintf("OP_QUERY (truncated, %d bytes)", msg.BodySize))
		return
	}

	flags := binary.LittleEndian.Uint32(body[0:4])
	_ = flags

	// Find null-terminated collection name
	end := 4
	for end < len(body) && body[end] != 0x00 {
		end++
	}
	msg.FullCollectionName = string(body[4:end])
	end++ // skip null

	if end+8 <= len(body) {
		msg.NumberToSkip = int32(binary.LittleEndian.Uint32(body[end : end+4]))
		msg.NumberToReturn = int32(binary.LittleEndian.Uint32(body[end+4 : end+8]))
	}

	msg.Summary = fmt.Sprintf("OP_QUERY %s (skip=%d, batch=%d)",
		msg.FullCollectionName, msg.NumberToSkip, msg.NumberToReturn)
}

func (msg *MongoMessage) parseOpReply(body []byte) {
	nDocs := int32(0)
	if len(body) >= 20 {
		nDocs = int32(binary.LittleEndian.Uint32(body[16:20]))
	}
	msg.Summary = fmt.Sprintf("OP_REPLY (docs=%d, body=%d bytes)", nDocs, msg.BodySize)
}

func (msg *MongoMessage) parseOpInsert(body []byte) {
	flags := int32(0)
	if len(body) >= 4 {
		flags = int32(binary.LittleEndian.Uint32(body[0:4]))
	}
	_ = flags

	// Find collection name
	end := 4
	for end < len(body) && body[end] != 0x00 {
		end++
	}
	msg.Collection = string(body[4:end])
	msg.Summary = fmt.Sprintf("OP_INSERT %s (body=%d bytes)", msg.Collection, msg.BodySize)
}

func (msg *MongoMessage) parseOpCommand(body []byte) {
	// OP_COMMAND: database name + command name + command BSON + metadata BSON
	if len(body) < 8 {
		msg.TypeAs("OP_COMMAND (truncated)")
		return
	}

	// Database name (null-terminated)
	end := 0
	for end < len(body) && body[end] != 0x00 {
		end++
	}
	db := string(body[0:end])
	end++

	// Command name (null-terminated)
	cmdEnd := end
	for cmdEnd < len(body) && body[cmdEnd] != 0x00 {
		cmdEnd++
	}
	cmdName := string(body[end:cmdEnd])

	msg.Command = cmdName
	msg.Summary = fmt.Sprintf("OP_COMMAND %s.%s (body=%d bytes)", db, cmdName, msg.BodySize)
}

// findBodySection finds the body section marker (kind 0) in an OP_MSG body.
func findBodySection(data []byte) int {
	for i := 0; i < len(data)-4; i++ {
		if data[i] == 0x00 {
			// Found kind 0 section marker
			return i + 1
		}
		// Look for null-terminated identifier (kind 1 section)
		if data[i] == 0x00 {
			return i + 1 // next section starts here
		}
	}
	return -1
}

// extractBSONFirstKey extracts the first key from a BSON document.
// BSON document format: total_len(int32) + elements... + \x00
// Each element: type(byte) + key(null-terminated) + value
func extractBSONFirstKey(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	// Skip total document size (4 bytes)
	typ := data[4]
	if typ == 0x00 {
		return "" // empty document
	}
	// Read key (null-terminated C string)
	end := 5
	for end < len(data) && data[end] != 0x00 {
		end++
	}
	return string(data[5:end])
}

// extractBSONValue tries to extract the value of a named field from BSON.
func extractBSONValue(data []byte, field string) string {
	if len(data) < 5 {
		return ""
	}
	// Skip document size
	pos := 4
	for pos < len(data)-1 {
		typ := data[pos]
		if typ == 0x00 {
			break // end of document
		}
		pos++
		// Read key
		keyStart := pos
		for pos < len(data) && data[pos] != 0x00 {
			pos++
		}
		key := string(data[keyStart:pos])
		pos++ // skip null

		// Skip value based on type
		pos = skipBSONValue(data, pos, typ)

		if key == field && field != "" {
			// We found the matching field but already skipped value
			// Return a placeholder
			return "(found)"
		}
	}
	return ""
}

func skipBSONValue(data []byte, pos int, typ byte) int {
	if pos >= len(data) {
		return pos
	}
	switch typ {
	case 0x01: // double
		return pos + 8
	case 0x02: // string
		if pos+4 <= len(data) {
			length := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
			return pos + 4 + length
		}
	case 0x03, 0x04: // embedded document / array
		if pos+4 <= len(data) {
			length := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
			return pos + length
		}
	case 0x05: // binary
		if pos+5 <= len(data) {
			length := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
			return pos + 5 + length
		}
	case 0x08: // boolean
		return pos + 1
	case 0x09: // UTC datetime
		return pos + 8
	case 0x0a: // null
		return pos
	case 0x10: // int32
		return pos + 4
	case 0x12: // int64
		return pos + 8
	case 0x13: // decimal128
		return pos + 16
	}
	return pos
}

// DetectMongo checks if data looks like MongoDB wire protocol.
func DetectMongo(data []byte) bool {
	if len(data) < MsgHeaderSize {
		return false
	}

	msgLen := int32(binary.LittleEndian.Uint32(data[0:4]))
	if msgLen < MinMsgSize || msgLen > MaxMsgSize {
		return false
	}

	opCode := int32(binary.LittleEndian.Uint32(data[12:16]))
	switch opCode {
	case OpReply, OpUpdate, OpInsert, OpQuery, OpGetMore,
		OpDelete, OpKillCursors, OpCommand, OpCommandReply, OpMsg:
		return true
	}

	return false
}
