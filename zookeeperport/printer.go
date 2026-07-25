package zookeeperport

import (
	"fmt"
	"strings"
)

// FormatZKRequest formats a ZooKeeper request for display.
func FormatZKRequest(req *ZKRequest) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("  %s\n", req.Summary))
	if req.Path != "" {
		sb.WriteString(fmt.Sprintf("  Path: %s\n", req.Path))
	}
	sb.WriteString(fmt.Sprintf("  XID: %d  Type: %s\n", req.XID, req.OpName))

	return sb.String()
}

// FormatZKResponse formats a ZooKeeper response for display.
func FormatZKResponse(resp *ZKResponse) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("  %s\n", resp.Summary))
	if resp.Err != 0 {
		sb.WriteString(fmt.Sprintf("  Error: %d\n", resp.Err))
	}
	sb.WriteString(fmt.Sprintf("  XID: %d  ZXID: 0x%x  Type: %s\n", resp.XID, resp.ZXID, resp.OpName))

	return sb.String()
}

// FormatZKURL formats a minimal URL-level ZooKeeper request.
func FormatZKURL(req *ZKRequest) string {
	if req.Path != "" {
		return fmt.Sprintf("%s %s\n", req.OpName, req.Path)
	}
	return fmt.Sprintf("%s\n", req.OpName)
}
