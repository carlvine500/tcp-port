package mysqlport

import (
	"fmt"
	"strings"
)

// FormatMySQLMessage formats a MySQL message for display.
func FormatMySQLMessage(msg *MySQLMessage) string {
	var sb strings.Builder

	switch msg.Type {
	case "handshake":
		sb.WriteString(fmt.Sprintf("  Handshake v%d\n", msg.ProtocolVersion))
		sb.WriteString(fmt.Sprintf("  Server: %s\n", msg.ServerVersion))
		if msg.AuthPlugin != "" {
			sb.WriteString(fmt.Sprintf("  Auth: %s\n", msg.AuthPlugin))
		}

	case "command":
		sb.WriteString(fmt.Sprintf("  %s", msg.CommandName))
		if msg.Query != "" {
			sb.WriteString(fmt.Sprintf("  %s", SanitizeQuery(msg.Query)))
		}
		sb.WriteString("\n")

	case "ok":
		sb.WriteString(fmt.Sprintf("  OK  rows=%d  insert_id=%d\n", msg.AffectedRows, msg.LastInsertID))

	case "error":
		sb.WriteString(fmt.Sprintf("  ERROR %d (%s): %s\n", msg.ErrorCode, msg.SQLState, msg.ErrorMsg))

	case "resultset":
		sb.WriteString(fmt.Sprintf("  ResultSet: %d columns\n", msg.AffectedRows))

	case "eof":
		sb.WriteString("  EOF\n")

	default:
		sb.WriteString(fmt.Sprintf("  %s\n", msg.Summary))
	}

	return sb.String()
}

// FormatMySQLURL formats a minimal URL-level MySQL message.
func FormatMySQLURL(msg *MySQLMessage) string {
	switch msg.Type {
	case "command":
		detail := msg.CommandName
		if msg.Query != "" {
			detail = SanitizeQuery(msg.Query)
		}
		return fmt.Sprintf("%s\n", detail)
	case "error":
		return fmt.Sprintf("ERROR %d: %s\n", msg.ErrorCode, msg.ErrorMsg)
	case "handshake":
		return fmt.Sprintf("Handshake %s\n", msg.ServerVersion)
	default:
		return fmt.Sprintf("%s\n", msg.Summary)
	}
}
