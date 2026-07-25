package websocketport

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// WebSocket opcodes
const (
	OpContinuation = 0x0
	OpText         = 0x1
	OpBinary       = 0x2
	OpClose        = 0x8
	OpPing         = 0x9
	OpPong         = 0xA
)

// WebSocket connection states
const (
	StateHandshake = "handshake"
	StateOpen      = "open"
	StateClosing   = "closing"
	StateClosed    = "closed"
)

// OpcodeName returns the human-readable name for a WebSocket opcode.
func OpcodeName(op int) string {
	switch op {
	case OpContinuation:
		return "Continuation"
	case OpText:
		return "Text"
	case OpBinary:
		return "Binary"
	case OpClose:
		return "Close"
	case OpPing:
		return "Ping"
	case OpPong:
		return "Pong"
	default:
		return fmt.Sprintf("Unknown(0x%x)", op)
	}
}

// WebSocketMessage represents a parsed WebSocket frame.
type WebSocketMessage struct {
	OpCode    int    // frame opcode
	OpName    string // human-readable opcode name
	PayloadLen int   // payload length in bytes
	Payload   string // payload content (for text/close frames)
	IsText    bool   // true if text frame
	IsBinary  bool   // true if binary frame
	IsControl bool   // true if control frame (close/ping/pong)
	FIN       bool   // final fragment flag
	Direction string // "C→S" or "S→C"
	Summary   string // one-line summary
}

// DetectWebSocket checks if data looks like a WebSocket connection.
// Detection covers both:
// 1. HTTP Upgrade handshake with "websocket" Upgrade header
// 2. Valid WebSocket frame with recognizable opcode and masking
func DetectWebSocket(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Check for HTTP Upgrade handshake
	s := string(data)
	if strings.Contains(s, "\r\n") {
		lower := strings.ToLower(s)
		if strings.Contains(lower, "upgrade:") && strings.Contains(lower, "websocket") {
			return true
		}
		// Also check if it's an HTTP response switching protocols
		if strings.Contains(lower, "101") && strings.Contains(lower, "switching") {
			return true
		}
	}

	// Check for WebSocket frame pattern
	if len(data) >= 2 {
		return isValidWebSocketFrameStart(data[0], data[1])
	}

	return false
}

// isValidWebSocketFrameStart checks if the first two bytes look like a valid
// WebSocket frame. Valid opcodes: 0x0-0x2, 0x8-0xA.
// Mask bit must be set (clients always mask, servers respond without).
// We accept both masked and unmasked for detection flexibility.
func isValidWebSocketFrameStart(b0, b1 byte) bool {
	opcode := b0 & 0x0F

	// Valid opcodes: continuation(0), text(1), binary(2), close(8), ping(9), pong(10)
	switch opcode {
	case OpContinuation, OpText, OpBinary, OpClose, OpPing, OpPong:
		// Valid opcode, but also validate payload length encoding
		payloadLen := b1 & 0x7F
		// Payload length must be valid: 0-125, or 126/127 with enough trailing bytes
		// We can't fully check without more context, but 126/127 are valid encodings
		_ = payloadLen
		return true
	default:
		return false
	}
}

// ReadWebSocketMessage reads a single WebSocket frame from the reader.
// Returns the parsed message or an error if the frame is malformed.
func ReadWebSocketMessage(r io.Reader, direction string) (*WebSocketMessage, error) {
	// Read first 2 bytes (minimum frame header)
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("websocket: failed to read header: %w", err)
	}

	b0 := header[0]
	b1 := header[1]

	fin := (b0 & 0x80) != 0
	// rsv := (b0 >> 4) & 0x07
	opcode := int(b0 & 0x0F)
	masked := (b1 & 0x80) != 0
	payloadLen7 := int(b1 & 0x7F)

	opName := OpcodeName(opcode)
	if opcode > 0xA || (opcode > 2 && opcode < 8) {
		return nil, fmt.Errorf("websocket: invalid opcode 0x%x", opcode)
	}

	// Determine payload length
	payloadLen := int64(payloadLen7)
	if payloadLen7 == 126 {
		extLen := make([]byte, 2)
		if _, err := io.ReadFull(r, extLen); err != nil {
			return nil, fmt.Errorf("websocket: failed to read extended length (16-bit): %w", err)
		}
		payloadLen = int64(binary.BigEndian.Uint16(extLen))
	} else if payloadLen7 == 127 {
		extLen := make([]byte, 8)
		if _, err := io.ReadFull(r, extLen); err != nil {
			return nil, fmt.Errorf("websocket: failed to read extended length (64-bit): %w", err)
		}
		payloadLen = int64(binary.BigEndian.Uint64(extLen))
	}

	// Read mask key if present
	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(r, maskKey[:]); err != nil {
			return nil, fmt.Errorf("websocket: failed to read mask key: %w", err)
		}
	}

	// Read payload
	// Cap payload at a reasonable size for display (max 64KB for safety)
	if payloadLen > 65536 {
		return nil, fmt.Errorf("websocket: payload too large: %d bytes", payloadLen)
	}

	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("websocket: failed to read payload: %w", err)
		}
	}

	// Unmask payload if masked
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	msg := &WebSocketMessage{
		OpCode:    opcode,
		OpName:    opName,
		PayloadLen: int(payloadLen),
		FIN:       fin,
		Direction: direction,
		IsControl: opcode >= 0x8,
	}

	switch opcode {
	case OpText:
		msg.IsText = true
		msg.Payload = string(payload)
		if len(msg.Payload) > 200 {
			msg.Payload = msg.Payload[:200] + "..."
		}
		msg.Summary = fmt.Sprintf("%s frame: %q", opName, msg.Payload)
	case OpBinary:
		msg.IsBinary = true
		msg.Summary = fmt.Sprintf("%s frame: %d bytes", opName, payloadLen)
	case OpClose:
		msg.IsControl = true
		if len(payload) >= 2 {
			code := binary.BigEndian.Uint16(payload[:2])
			reason := ""
			if len(payload) > 2 {
				reason = string(payload[2:])
			}
			msg.Payload = fmt.Sprintf("code=%d", code)
			if reason != "" {
				msg.Payload += fmt.Sprintf(" reason=%q", reason)
			}
			msg.Summary = fmt.Sprintf("%s frame: code=%d %s", opName, code, reason)
		} else {
			msg.Summary = fmt.Sprintf("%s frame", opName)
		}
	case OpPing:
		msg.IsControl = true
		msg.Summary = fmt.Sprintf("%s frame: %d bytes", opName, payloadLen)
	case OpPong:
		msg.IsControl = true
		msg.Summary = fmt.Sprintf("%s frame: %d bytes", opName, payloadLen)
	case OpContinuation:
		msg.Summary = fmt.Sprintf("%s frame: %d bytes (FIN=%v)", opName, payloadLen, fin)
	default:
		msg.Summary = fmt.Sprintf("%s frame: %d bytes", opName, payloadLen)
	}

	return msg, nil
}
