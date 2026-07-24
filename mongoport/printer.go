package mongoport

import (
	"fmt"
	"strings"
)

// FormatMongoMessage formats a MongoDB message for display.
func FormatMongoMessage(msg *MongoMessage) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("  %s\n", msg.Summary))

	if msg.Collection != "" && msg.Command == "" {
		sb.WriteString(fmt.Sprintf("  Collection: %s\n", msg.Collection))
	}
	if msg.FullCollectionName != "" {
		sb.WriteString(fmt.Sprintf("  Collection: %s\n", msg.FullCollectionName))
	}
	if msg.Command != "" {
		sb.WriteString(fmt.Sprintf("  Command: %s\n", msg.Command))
	}

	flags := []string{}
	if msg.FlagBits&1 != 0 {
		flags = append(flags, "checksumPresent")
	}
	if msg.FlagBits&2 != 0 {
		flags = append(flags, "moreToCome")
	}
	if msg.FlagBits&(1<<16) != 0 {
		flags = append(flags, "exhaustAllowed")
	}
	if len(flags) > 0 {
		sb.WriteString(fmt.Sprintf("  Flags: %s\n", strings.Join(flags, ", ")))
	}

	sb.WriteString(fmt.Sprintf("  RequestID: %d  ResponseTo: %d\n", msg.Header.RequestID, msg.Header.ResponseTo))

	return sb.String()
}

// FormatMongoResponse formats a MongoDB response for display.
func FormatMongoResponse(msg *MongoMessage) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("  %s\n", msg.Summary))

	if msg.Command != "" {
		sb.WriteString(fmt.Sprintf("  Command: %s\n", msg.Command))
	}

	sb.WriteString(fmt.Sprintf("  RequestID: %d  ResponseTo: %d\n", msg.Header.RequestID, msg.Header.ResponseTo))

	return sb.String()
}

// FormatMongoURL formats a minimal URL-level MongoDB message.
func FormatMongoURL(msg *MongoMessage) string {
	return fmt.Sprintf("%s\n", msg.Summary)
}
