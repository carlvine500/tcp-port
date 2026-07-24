package mysqlport

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// MySQL packet format: 3-byte length + 1-byte seq + payload
const (
	HeaderSize    = 4
	MaxPayloadLen = 1<<24 - 1 // 16MB
)

// Client command types
const (
	ComSleep            byte = 0x00
	ComQuit             byte = 0x01
	ComInitDB           byte = 0x02
	ComQuery            byte = 0x03
	ComFieldList        byte = 0x04
	ComCreateDB         byte = 0x05
	ComDropDB           byte = 0x06
	ComRefresh          byte = 0x07
	ComShutdown         byte = 0x08
	ComStatistics       byte = 0x09
	ComProcessInfo      byte = 0x0a
	ComConnect          byte = 0x0b
	ComProcessKill      byte = 0x0c
	ComDebug            byte = 0x0d
	ComPing             byte = 0x0e
	ComTime             byte = 0x0f
	ComDelayedInsert    byte = 0x10
	ComChangeUser       byte = 0x11
	ComBinlogDump       byte = 0x12
	ComTableDump        byte = 0x13
	ComConnectOut       byte = 0x14
	ComRegisterSlave    byte = 0x15
	ComStmtPrepare      byte = 0x16
	ComStmtExecute      byte = 0x17
	ComStmtSendLongData byte = 0x18
	ComStmtClose        byte = 0x19
	ComStmtReset        byte = 0x1a
	ComSetOption        byte = 0x1b
	ComStmtFetch        byte = 0x1c
	ComDaemon           byte = 0x1d
	ComBinlogDumpGTID   byte = 0x1e
	ComResetConnection  byte = 0x1f
)

var commandNames = map[byte]string{
	ComSleep:            "Sleep",
	ComQuit:             "Quit",
	ComInitDB:           "InitDB",
	ComQuery:            "Query",
	ComFieldList:        "FieldList",
	ComCreateDB:         "CreateDB",
	ComDropDB:           "DropDB",
	ComRefresh:          "Refresh",
	ComShutdown:         "Shutdown",
	ComStatistics:       "Statistics",
	ComProcessInfo:      "ProcessInfo",
	ComConnect:          "Connect",
	ComProcessKill:      "ProcessKill",
	ComDebug:            "Debug",
	ComPing:             "Ping",
	ComTime:             "Time",
	ComDelayedInsert:    "DelayedInsert",
	ComChangeUser:       "ChangeUser",
	ComBinlogDump:       "BinlogDump",
	ComTableDump:        "TableDump",
	ComConnectOut:       "ConnectOut",
	ComRegisterSlave:    "RegisterSlave",
	ComStmtPrepare:      "StmtPrepare",
	ComStmtExecute:      "StmtExecute",
	ComStmtSendLongData: "StmtSendLongData",
	ComStmtClose:        "StmtClose",
	ComStmtReset:        "StmtReset",
	ComSetOption:        "SetOption",
	ComStmtFetch:        "StmtFetch",
	ComDaemon:           "Daemon",
	ComBinlogDumpGTID:   "BinlogDumpGTID",
	ComResetConnection:  "ResetConnection",
}

// CommandName returns the human-readable command name.
func CommandName(b byte) string {
	if name, ok := commandNames[b]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(0x%02x)", b)
}

// Server response types
const (
	ResponseOK     byte = 0x00
	ResponseEOF    byte = 0xfe
	ResponseERR    byte = 0xff
	ResponseLocal  byte = 0xfb // local infile request
)

// MySQLPacket represents a parsed MySQL packet.
type MySQLPacket struct {
	Length     uint32 // 24-bit payload length
	SequenceID byte
	Payload    []byte
	Direction  string // "C->S" or "S->C"
}

// MySQLMessage represents a decoded MySQL protocol message.
type MySQLMessage struct {
	Packets     []MySQLPacket
	Type        string      // "handshake", "command", "ok", "err", "eof", "resultset", etc.
	Summary     string
	// Command
	Command     byte
	CommandName string
	Query       string
	// Handshake
	ProtocolVersion byte
	ServerVersion   string
	AuthPlugin      string
	// Result
	AffectedRows uint64
	LastInsertID uint64
	StatusFlags  uint16
	ErrorCode    uint16
	ErrorMsg     string
	SQLState     string
}

// ReadMySQLPacket reads a single MySQL packet from reader.
func ReadMySQLPacket(r io.Reader) (*MySQLPacket, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	pkt := &MySQLPacket{
		Length:     uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16,
		SequenceID: header[3],
	}

	pkt.Payload = make([]byte, pkt.Length)
	if _, err := io.ReadFull(r, pkt.Payload); err != nil {
		return nil, err
	}

	return pkt, nil
}

// ReadMySQLMessage reads a complete MySQL protocol message.
// Some messages span multiple packets (e.g. large queries > 16MB).
func ReadMySQLMessage(r io.Reader, direction string) (*MySQLMessage, error) {
	pkt, err := ReadMySQLPacket(r)
	if err != nil {
		return nil, err
	}
	pkt.Direction = direction

	msg := &MySQLMessage{
		Packets: []MySQLPacket{*pkt},
	}

	// Parse based on direction
	if direction == "C->S" {
		msg.parseClientPacket()
	} else {
		msg.parseServerPacket()
	}

	return msg, nil
}

func (msg *MySQLMessage) parseClientPacket() {
	pkt := &msg.Packets[0]

	if len(pkt.Payload) == 0 {
		return
	}

	msg.Command = pkt.Payload[0]
	msg.CommandName = CommandName(msg.Command)
	msg.Type = "command"

	switch msg.Command {
	case ComQuery:
		msg.Query = string(pkt.Payload[1:])
		// Truncate long queries for display
		if len(msg.Query) > 200 {
			msg.Query = msg.Query[:200] + "..."
		}
		msg.Summary = fmt.Sprintf("Query: %s", msg.Query)
	case ComStmtPrepare:
		msg.Query = string(pkt.Payload[1:])
		if len(msg.Query) > 200 {
			msg.Query = msg.Query[:200] + "..."
		}
		msg.Summary = fmt.Sprintf("Prepare: %s", msg.Query)
	case ComStmtExecute:
		if len(pkt.Payload) >= 5 {
			stmtID := binary.LittleEndian.Uint32(pkt.Payload[1:5])
			msg.Summary = fmt.Sprintf("Execute stmt_id=%d", stmtID)
		}
	case ComInitDB:
		msg.Query = string(pkt.Payload[1:])
		msg.Summary = fmt.Sprintf("Use DB: %s", msg.Query)
	case ComQuit:
		msg.Summary = "Quit"
	case ComPing:
		msg.Summary = "Ping"
	case ComBinlogDump, ComBinlogDumpGTID:
		msg.Summary = "BinlogDump"
	case ComRegisterSlave:
		msg.Summary = "RegisterSlave"
	default:
		msg.Summary = msg.CommandName
	}
}

func (msg *MySQLMessage) parseServerPacket() {
	pkt := &msg.Packets[0]

	if len(pkt.Payload) == 0 {
		return
	}

	firstByte := pkt.Payload[0]

	// Check for server greeting (handshake v10)
	if firstByte == 0x0a && len(pkt.Payload) > 4 {
		msg.Type = "handshake"
		msg.ProtocolVersion = firstByte

		// Find null-terminated server version
		pos := 1
		for pos < len(pkt.Payload) && pkt.Payload[pos] != 0x00 {
			pos++
		}
		msg.ServerVersion = string(pkt.Payload[1:pos])
		pos++ // skip null

		// Check for auth plugin name at end (capability CLIENT_PLUGIN_AUTH)
		if pos+13 < len(pkt.Payload) {
			// Find the last null-terminated string (auth plugin name)
			end := len(pkt.Payload) - 1
			for end > pos && pkt.Payload[end] != 0x00 {
				end--
			}
			if end > pos && end < len(pkt.Payload)-1 {
				msg.AuthPlugin = string(pkt.Payload[end+1 : len(pkt.Payload)])
			}
		}

		msg.Summary = fmt.Sprintf("Handshake: MySQL %s (plugin=%s)", msg.ServerVersion, msg.AuthPlugin)
		return
	}

	// OK packet (0x00 or 0xfe for OK with EOF deprecation)
	if firstByte == ResponseOK || firstByte == ResponseEOF {
		if len(pkt.Payload) < 7 {
			msg.Type = "ok"
			msg.Summary = "OK"
			return
		}
		msg.Type = "ok"
		pos := 1
		msg.AffectedRows, pos = readLenEncInt(pkt.Payload, pos)
		msg.LastInsertID, pos = readLenEncInt(pkt.Payload, pos)
		if pos+1 < len(pkt.Payload) {
			msg.StatusFlags = binary.LittleEndian.Uint16(pkt.Payload[pos : pos+2])
		}
		msg.Summary = fmt.Sprintf("OK (rows=%d, insert_id=%d)", msg.AffectedRows, msg.LastInsertID)
		return
	}

	// ERR packet
	if firstByte == ResponseERR {
		msg.Type = "error"
		if len(pkt.Payload) >= 3 {
			msg.ErrorCode = binary.LittleEndian.Uint16(pkt.Payload[1:3])
		}
		if len(pkt.Payload) > 3 {
			// Skip SQL state marker '#' if present
			pos := 3
			if pkt.Payload[pos] == '#' {
				msg.SQLState = string(pkt.Payload[pos+1 : pos+6])
				pos += 6
			}
			msg.ErrorMsg = string(pkt.Payload[pos:])
		}
		msg.Summary = fmt.Sprintf("ERROR %d (%s): %s", msg.ErrorCode, msg.SQLState, msg.ErrorMsg)
		return
	}

	// EOF packet (0xfe)
	if firstByte == ResponseEOF {
		msg.Type = "eof"
		if len(pkt.Payload) >= 5 {
			msg.StatusFlags = binary.LittleEndian.Uint16(pkt.Payload[3:5])
		}
		msg.Summary = "EOF"
		return
	}

	// Otherwise, it might be a column count (length-encoded integer for result set)
	colCount, _ := readLenEncInt(pkt.Payload, 0)
	if colCount > 0 && colCount < 10000 {
		msg.Type = "resultset"
		msg.AffectedRows = colCount
		msg.Summary = fmt.Sprintf("ResultSet: %d columns", colCount)
		return
	}

	msg.Type = "unknown"
	msg.Summary = fmt.Sprintf("%d bytes payload", len(pkt.Payload))
}

// readLenEncInt reads a length-encoded integer from MySQL protocol.
func readLenEncInt(data []byte, pos int) (uint64, int) {
	if pos >= len(data) {
		return 0, pos
	}
	switch {
	case data[pos] < 0xfb:
		return uint64(data[pos]), pos + 1
	case data[pos] == 0xfc:
		if pos+2 >= len(data) {
			return 0, pos
		}
		return uint64(binary.LittleEndian.Uint16(data[pos+1 : pos+3])), pos + 3
	case data[pos] == 0xfd:
		if pos+3 >= len(data) {
			return 0, pos
		}
		return uint64(data[pos+1]) | uint64(data[pos+2])<<8 | uint64(data[pos+3])<<16, pos + 4
	case data[pos] == 0xfe:
		if pos+8 >= len(data) {
			return 0, pos
		}
		return binary.LittleEndian.Uint64(data[pos+1 : pos+9]), pos + 9
	default:
		return 0, pos
	}
}

// DetectMySQL checks if data looks like MySQL protocol.
func DetectMySQL(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// Check 3-byte length header
	length := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16

	// Length must be reasonable (non-zero, < 16MB)
	if length == 0 || length > MaxPayloadLen {
		return false
	}

	// If we have the full payload, validate its first byte
	if len(data) >= int(4+length) {
		payload := data[4 : 4+length]
		if len(payload) == 0 {
			return false
		}
		b := payload[0]
		// Server handshake starts with protocol version 0x0a (v10)
		if b == 0x0a {
			return true
		}
		// Client commands (0x01-0x1f, excluding 0x00=SLEEP which is rare)
		if b >= 0x01 && b <= 0x1f {
			return true
		}
		// Server OK (0x00 or 0xfe), ERR (0xff)
		if b == ResponseOK || b == ResponseERR || b == ResponseEOF {
			return true
		}
		// Resultset: first byte is length-encoded column count
		colCount, _ := readLenEncInt(payload, 0)
		if colCount > 0 && colCount <= 4096 {
			return true
		}
		return false
	}

	// Without full payload, check if first byte is a known MySQL marker
	if len(data) > 4 {
		b := data[4]
		if b == 0x0a || (b >= 0x01 && b <= 0x1f) || b == ResponseOK || b == ResponseERR || b == ResponseEOF {
			return true
		}
		return false
	}

	// Only header available — reasonable length is not enough alone
	return false
}

// SanitizeQuery cleans up a SQL query for display.
func SanitizeQuery(q string) string {
	q = strings.TrimSpace(q)
	q = strings.ReplaceAll(q, "\n", " ")
	q = strings.ReplaceAll(q, "\r", "")
	q = strings.ReplaceAll(q, "\t", " ")
	// Collapse spaces
	parts := strings.Fields(q)
	return strings.Join(parts, " ")
}
