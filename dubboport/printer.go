package dubboport

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// FormatDubbo formats a Dubbo message for display.
func FormatDubbo(msg *DubboMessage) string {
	var sb strings.Builder

	if !msg.Header.IsRequest {
		// Response
		sb.WriteString(fmt.Sprintf("Dubbo Response  id=%d  status=%s\n", msg.Header.RequestID, msg.ResponseStatus))
		sb.WriteString(fmt.Sprintf("  Serialization: %s\n", msg.Header.SerializationID))
		sb.WriteString(fmt.Sprintf("  Data Length: %d bytes\n", msg.Header.DataLength))
		if msg.HasException && len(msg.Body) > 0 {
			sb.WriteString(fmt.Sprintf("  Body:\n%s\n", hex.Dump(msg.Body)))
		}
		return sb.String()
	}

	// Request
	sb.WriteString(fmt.Sprintf("Dubbo Request  id=%d  twoway=%v\n", msg.Header.RequestID, msg.Header.IsTwoway))
	sb.WriteString(fmt.Sprintf("  Service: %s\n", msg.ServiceName))
	if msg.ServiceVersion != "" {
		sb.WriteString(fmt.Sprintf("  Version: %s\n", msg.ServiceVersion))
	}
	sb.WriteString(fmt.Sprintf("  Method: %s\n", msg.MethodName))
	sb.WriteString(fmt.Sprintf("  Serialization: %s\n", msg.Header.SerializationID))
	if msg.ParamTypes != "" {
		sb.WriteString(fmt.Sprintf("  Param Types: %s\n", msg.ParamTypes))
	}
	sb.WriteString(fmt.Sprintf("  Data Length: %d bytes\n", msg.Header.DataLength))

	// Show parsed body fields if requested
	if msg.ShowBody {
		if msg.ParsedArgs != nil {
			jsonBytes, err := json.MarshalIndent(msg.ParsedArgs, "    ", "  ")
			if err == nil {
				sb.WriteString("  Args: ")
				sb.Write(jsonBytes)
				sb.WriteString("\n")
			}
		} else {
			if len(msg.Params) > 0 {
				sb.WriteString("  Params:\n")
				for _, p := range msg.Params {
					sb.WriteString(fmt.Sprintf("    %-22s %s\n", p.Key+":", p.Value))
				}
			}
			if len(msg.Attachments) > 0 {
				sb.WriteString("  Attachments:\n")
				for _, a := range msg.Attachments {
					sb.WriteString(fmt.Sprintf("    %-22s %s\n", a.Key+":", a.Value))
				}
			}
			// Fall back to hex dump if no parsed fields
			if len(msg.Params) == 0 && len(msg.Attachments) == 0 && len(msg.Body) > 0 {
				sb.WriteString(fmt.Sprintf("  Body:\n%s\n", hex.Dump(msg.Body)))
			}
		}
	}

	return sb.String()
}

// FormatTriple formats a Triple message for display.
func FormatTriple(msg *TripleMessage) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Triple Request\n"))
	sb.WriteString(fmt.Sprintf("  Service: %s\n", msg.ServiceName))
	sb.WriteString(fmt.Sprintf("  Method: %s\n", msg.MethodName))
	if msg.ContentType != "" {
		sb.WriteString(fmt.Sprintf("  Content-Type: %s\n", msg.ContentType))
	}
	if len(msg.Messages) > 0 {
		for i, m := range msg.Messages {
			compressed := ""
			if m.Compressed {
				compressed = " (compressed)"
			}
			sb.WriteString(fmt.Sprintf("  Message[%d]: %d bytes%s\n", i, m.Length, compressed))
		}
	}
	return sb.String()
}

// FormatDubboURL formats a minimal URL-level dubbo message.
func FormatDubboURL(msg *DubboMessage) string {
	if msg.IsRealHeartbeat {
		return fmt.Sprintf("[heartbeat] id=%d\n", msg.Header.RequestID)
	}
	if msg.Header.IsEvent {
		return fmt.Sprintf("%s/%s [event] id=%d\n", msg.ServiceName, msg.MethodName, msg.Header.RequestID)
	}
	if msg.Header.IsRequest {
		return fmt.Sprintf("%s/%s\n", msg.ServiceName, msg.MethodName)
	}
	return fmt.Sprintf("id=%d  %s\n", msg.Header.RequestID, msg.ResponseStatus)
}

// FormatTripleURL formats a minimal URL-level triple message.
func FormatTripleURL(msg *TripleMessage) string {
	return fmt.Sprintf("%s/%s\n", msg.ServiceName, msg.MethodName)
}
