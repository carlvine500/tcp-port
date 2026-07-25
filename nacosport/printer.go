package nacosport

import (
	"fmt"
	"strings"
)

// FormatNacosMessage formats a Nacos message for detailed display.
func FormatNacosMessage(msg *NacosMessage) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("  %s\n", msg.Summary))

	if msg.Method != "" {
		// Request
		if len(msg.Params) > 0 {
			sb.WriteString("  Params:\n")
			for k, v := range msg.Params {
				sb.WriteString(fmt.Sprintf("    %s=%s\n", k, v))
			}
		}
		if msg.Body != "" {
			body := msg.Body
			if len(body) > 500 {
				body = body[:500] + "..."
			}
			sb.WriteString(fmt.Sprintf("  Body: %s\n", body))
		}
	} else {
		// Response
		sb.WriteString(fmt.Sprintf("  Status: %d\n", msg.StatusCode))
		if msg.Body != "" {
			body := msg.Body
			if len(body) > 300 {
				body = body[:300] + "..."
			}
			sb.WriteString(fmt.Sprintf("  Body: %s\n", body))
		}
	}

	return sb.String()
}

// FormatNacosURL formats a minimal URL-level Nacos message.
func FormatNacosURL(msg *NacosMessage) string {
	if msg.Method != "" {
		if len(msg.Params) > 0 {
			parts := make([]string, 0, len(msg.Params))
			for k, v := range msg.Params {
				parts = append(parts, fmt.Sprintf("%s=%s", k, v))
			}
			return fmt.Sprintf("[%s] %s %s?%s\n", msg.APIType, msg.Method, msg.Path, strings.Join(parts, "&"))
		}
		return fmt.Sprintf("[%s] %s %s\n", msg.APIType, msg.Method, msg.Path)
	}
	return fmt.Sprintf("%d\n", msg.StatusCode)
}
