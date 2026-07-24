package redisport

import (
	"fmt"
	"strings"
)

// FormatRESPCommand formats a Redis command for display.
func FormatRESPCommand(cmd *RESPCommand, src, dst string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s -----> %s\n", src, dst))

	if cmd.Command != "" {
		known := ""
		if !IsKnownRedisCommand(cmd.Command) {
			known = " (custom)"
		}
		sb.WriteString(fmt.Sprintf("  %s%s", cmd.Command, known))
	} else {
		sb.WriteString(fmt.Sprintf("  %s", cmd.Raw))
	}

	if len(cmd.Args) > 1 {
		// Show key name
		sb.WriteString(fmt.Sprintf("  %s", cmd.Args[1]))
		if len(cmd.Args) > 2 {
			sb.WriteString("  ...")
		}
	}
	sb.WriteString("\n")
	return sb.String()
}

// FormatRESPResponse formats a Redis response for display.
func FormatRESPResponse(resp *RESPResponse, src, dst string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s <----- %s\n", dst, src))
	typeName := RESPType(resp.Type)
	if resp.IsError {
		sb.WriteString(fmt.Sprintf("  [%s] ERR: %s\n", typeName, resp.Value))
	} else {
		val := resp.Value
		if len(val) > 200 {
			val = val[:200] + "..."
		}
		sb.WriteString(fmt.Sprintf("  [%s] %s\n", typeName, val))
	}
	return sb.String()
}

// FormatRESPURL formats a minimal URL-level Redis command.
func FormatRESPURL(cmd *RESPCommand, src, dst string) string {
	if cmd.Command != "" {
		key := ""
		if len(cmd.Args) > 1 {
			key = " " + cmd.Args[1]
		}
		return fmt.Sprintf("%s --> %s  %s%s\n", src, dst, cmd.Command, key)
	}
	return fmt.Sprintf("%s --> %s  %s\n", src, dst, cmd.Raw)
}
