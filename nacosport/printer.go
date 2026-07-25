package nacosport

import (
	"fmt"
	"strings"
)

// FormatNacosMessage formats a Nacos message for detailed display.
func FormatNacosMessage(msg *NacosMessage) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("  %s\n", msg.Summary))

	if msg.Method == "GRPC" {
		return sb.String()
	}

	if msg.Method != "" {
		// Request
		// Show key fields from params first (serviceName, ip, port, group, dataId, etc.)
		keyFields := []string{"serviceName", "groupName", "dataId", "ip", "port", "weight",
			"healthy", "enabled", "ephemeral", "namespaceId", "clusterName", "tenant", "username"}
		shown := make(map[string]bool)
		for _, k := range keyFields {
			if v, ok := msg.Params[k]; ok {
				shown[k] = true
				sb.WriteString(fmt.Sprintf("  %-14s %s\n", k+":", v))
			}
		}
		// Show remaining params
		for k, v := range msg.Params {
			if !shown[k] {
				sb.WriteString(fmt.Sprintf("  %-14s %s\n", k+":", v))
			}
		}

		// Show body if not form-encoded (JSON etc.)
		if msg.Body != "" && len(msg.Params) == 0 {
			body := msg.Body
			// Try to format JSON
			if msg.IsJSON {
				body = formatJSONBody(body)
			}
			if len(body) > 500 {
				body = body[:500] + "..."
			}
			sb.WriteString(fmt.Sprintf("  Body: %s\n", body))
		}
	} else {
		// Response
		statusText := "OK"
		if msg.StatusCode >= 400 {
			statusText = "ERROR"
		}
		sb.WriteString(fmt.Sprintf("  Status: %d %s\n", msg.StatusCode, statusText))
		if msg.Body != "" && msg.Body != "ok" {
			body := msg.Body
			if msg.IsJSON {
				body = formatJSONBody(body)
			}
			if len(body) > 300 {
				body = body[:300] + "..."
			}
			sb.WriteString(fmt.Sprintf("  Body: %s\n", body))
		}
	}

	return sb.String()
}

// formatJSONBody attempts to compact/pretty-print a JSON body.
func formatJSONBody(body string) string {
	m, err := ParseJSONBody(body)
	if err != nil {
		return body
	}
	// Convert to key=value style for readability
	var parts []string
	for k, v := range m {
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
	}
	return strings.Join(parts, ", ")
}

// FormatNacosURL formats a minimal URL-level Nacos message.
func FormatNacosURL(msg *NacosMessage) string {
	if msg.Method == "GRPC" {
		return "[Nacos 2.x gRPC]\n"
	}
	if msg.Method != "" {
		// Show key fields compactly
		keyVals := []string{}
		for _, k := range []string{"serviceName", "group", "dataId", "username"} {
			if v, ok := msg.Params[k]; ok {
				keyVals = append(keyVals, k+"="+v)
			}
		}
		extra := ""
		if len(keyVals) > 0 {
			extra = " (" + strings.Join(keyVals, ", ") + ")"
		}
		return fmt.Sprintf("[%s] %s %s%s\n", msg.APIType, msg.Method, msg.Path, extra)
	}
	return fmt.Sprintf("[Nacos] HTTP %d\n", msg.StatusCode)
}
