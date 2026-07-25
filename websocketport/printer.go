package websocketport

import (
	"fmt"
	"strings"
)

// FormatWebSocketMessage formats a WebSocket message for display.
func FormatWebSocketMessage(msg *WebSocketMessage) string {
	var sb strings.Builder

	// Direction indicator
	arrow := "→"
	if msg.Direction == "S→C" || msg.Direction == "response" {
		arrow = "←"
	}

	sb.WriteString(fmt.Sprintf("  WS %s %s", arrow, msg.OpName))

	if msg.FIN {
		sb.WriteString(" [FIN]")
	}

	switch {
	case msg.IsText:
		sb.WriteString(fmt.Sprintf(" %q", msg.Payload))
	case msg.IsBinary:
		sb.WriteString(fmt.Sprintf(" (%d bytes)", msg.PayloadLen))
	case msg.OpCode == OpClose:
		sb.WriteString(fmt.Sprintf(" %s", msg.Payload))
	case msg.OpCode == OpPing || msg.OpCode == OpPong:
		sb.WriteString(fmt.Sprintf(" (%d bytes)", msg.PayloadLen))
	default:
		sb.WriteString(fmt.Sprintf(" (%d bytes)", msg.PayloadLen))
	}

	sb.WriteString("\n")
	return sb.String()
}

// FormatWebSocketURL formats a minimal URL-level WebSocket message.
func FormatWebSocketURL(msg *WebSocketMessage) string {
	return fmt.Sprintf("WS %s\n", msg.Summary)
}
