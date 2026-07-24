package rocketmqport

import (
	"fmt"
	"strings"
)

// FormatRemotingCommand formats a RocketMQ remoting command for display.
func FormatRemotingCommand(cmd *RemotingCommand, src, dst string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s -----> %s\n", src, dst))

	codeName := RequestCodeName(cmd.Code)
	sb.WriteString(fmt.Sprintf("  Code: %d (%s)\n", cmd.Code, codeName))

	if cmd.Language != "" {
		sb.WriteString(fmt.Sprintf("  Language: %s\n", cmd.Language))
	}
	sb.WriteString(fmt.Sprintf("  Version: %d  Opaque: %d  Flag: %d\n", cmd.Version, cmd.Opaque, cmd.Flag))

	if cmd.Remark != "" {
		sb.WriteString(fmt.Sprintf("  Remark: %s\n", cmd.Remark))
	}

	// Print ext fields
	if len(cmd.ExtFields) > 0 {
		for k, v := range cmd.ExtFields {
			// Show topic/brokerName/consumerGroup prominently
			if k == "topic" || k == "brokerName" || k == "consumerGroup" || k == "group" {
				sb.WriteString(fmt.Sprintf("  %s: %s\n", k, v))
			}
		}
	}

	if cmd.BodyPreview != "" {
		sb.WriteString(fmt.Sprintf("  Body: %d bytes\n", len(cmd.Body)))
	}

	sb.WriteString("\n")
	return sb.String()
}

// FormatRemotingURL formats a minimal URL-level RocketMQ command.
func FormatRemotingURL(cmd *RemotingCommand, src, dst string) string {
	codeName := RequestCodeName(cmd.Code)
	return fmt.Sprintf("%s --> %s  %s\n", src, dst, codeName)
}

// FormatRemotingResponse formats a RocketMQ response.
func FormatRemotingResponse(cmd *RemotingCommand, src, dst string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s <----- %s\n", dst, src))

	codeName := RequestCodeName(cmd.Code)
	sb.WriteString(fmt.Sprintf("  Response: %d (%s)\n", cmd.Code, codeName))

	if cmd.Remark != "" {
		sb.WriteString(fmt.Sprintf("  Remark: %s\n", cmd.Remark))
	}

	if cmd.BodyPreview != "" {
		sb.WriteString(fmt.Sprintf("  Body: %d bytes\n", len(cmd.Body)))
	}

	sb.WriteString("\n")
	return sb.String()
}
