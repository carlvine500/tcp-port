package redisport

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestDetectRESP(t *testing.T) {
	tests := []struct {
		data []byte
		want bool
	}{
		{[]byte("*3\r\n"), true},
		{[]byte("+OK\r\n"), true},
		{[]byte("-ERR\r\n"), true},
		{[]byte(":1000\r\n"), true},
		{[]byte("$5\r\n"), true},
		{[]byte("X\r\n"), false},
		{[]byte{}, false},
	}

	for _, tt := range tests {
		if got := DetectRESP(tt.data); got != tt.want {
			t.Errorf("DetectRESP(%q) = %v, want %v", tt.data, got, tt.want)
		}
	}
}

func TestReadRESPCommandArray(t *testing.T) {
	// Build a SET command: *3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n
	raw := "*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n"
	r := bufio.NewReader(strings.NewReader(raw))
	cmd, err := ReadRESPCommand(r)
	if err != nil {
		t.Fatalf("ReadRESPCommand failed: %v", err)
	}
	if cmd.Command != "SET" {
		t.Errorf("Command = %s, want SET", cmd.Command)
	}
	if len(cmd.Args) != 3 {
		t.Errorf("len(Args) = %d, want 3", len(cmd.Args))
	}
	if cmd.Args[1] != "foo" || cmd.Args[2] != "bar" {
		t.Errorf("Args = %v, want [SET foo bar]", cmd.Args)
	}
}

func TestReadRESPCommandInline(t *testing.T) {
	// Inline: PING\r\n
	r := bufio.NewReader(strings.NewReader("PING\r\n"))
	cmd, err := ReadRESPCommand(r)
	if err != nil {
		t.Fatalf("ReadRESPCommand failed: %v", err)
	}
	if cmd.Command != "PING" {
		t.Errorf("Command = %s, want PING", cmd.Command)
	}
}

func TestReadRESPResponseSimpleString(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("+OK\r\n"))
	resp, err := ReadRESPResponse(r)
	if err != nil {
		t.Fatalf("ReadRESPResponse failed: %v", err)
	}
	if resp.Type != TypeSimpleString {
		t.Errorf("Type = %c, want +", resp.Type)
	}
	if resp.Value != "OK" {
		t.Errorf("Value = %s, want OK", resp.Value)
	}
}

func TestReadRESPResponseError(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("-ERR unknown command\r\n"))
	resp, err := ReadRESPResponse(r)
	if err != nil {
		t.Fatalf("ReadRESPResponse failed: %v", err)
	}
	if !resp.IsError {
		t.Error("Expected error response")
	}
	if resp.Value != "ERR unknown command" {
		t.Errorf("Value = %s, want 'ERR unknown command'", resp.Value)
	}
}

func TestReadRESPResponseInteger(t *testing.T) {
	r := bufio.NewReader(strings.NewReader(":42\r\n"))
	resp, err := ReadRESPResponse(r)
	if err != nil {
		t.Fatalf("ReadRESPResponse failed: %v", err)
	}
	if resp.Value != "42" {
		t.Errorf("Value = %s, want 42", resp.Value)
	}
}

func TestReadRESPResponseBulkString(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("$5\r\nhello\r\n"))
	resp, err := ReadRESPResponse(r)
	if err != nil {
		t.Fatalf("ReadRESPResponse failed: %v", err)
	}
	if resp.Value != "hello" {
		t.Errorf("Value = %s, want hello", resp.Value)
	}
}

func TestReadRESPResponseNilBulk(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("$-1\r\n"))
	resp, err := ReadRESPResponse(r)
	if err != nil {
		t.Fatalf("ReadRESPResponse failed: %v", err)
	}
	if resp.Value != "(nil)" {
		t.Errorf("Value = %s, want (nil)", resp.Value)
	}
}

func TestIsKnownRedisCommand(t *testing.T) {
	if !IsKnownRedisCommand("SET") {
		t.Error("SET should be known")
	}
	if !IsKnownRedisCommand("get") {
		t.Error("get should be known (case-insensitive)")
	}
	if IsKnownRedisCommand("FAKECMD") {
		t.Error("FAKECMD should not be known")
	}
}

func TestReadRESPCommandPipeline(t *testing.T) {
	raw := "*1\r\n$4\r\nPING\r\n*2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n"
	r := bufio.NewReader(strings.NewReader(raw))

	cmd1, err := ReadRESPCommand(r)
	if err != nil {
		t.Fatalf("Read cmd1: %v", err)
	}
	if cmd1.Command != "PING" {
		t.Errorf("cmd1 = %s, want PING", cmd1.Command)
	}

	cmd2, err := ReadRESPCommand(r)
	if err != nil {
		t.Fatalf("Read cmd2: %v", err)
	}
	if cmd2.Command != "GET" {
		t.Errorf("cmd2 = %s, want GET", cmd2.Command)
	}
	if cmd2.Args[1] != "foo" {
		t.Errorf("cmd2 key = %s, want foo", cmd2.Args[1])
	}
}

func TestFormatRESPCommand(t *testing.T) {
	cmd := &RESPCommand{Command: "SET", Args: []string{"SET", "mykey", "myval"}}
	out := FormatRESPCommand(cmd, "10.0.0.1:12345", "10.0.0.2:6379")
	if !bytes.Contains([]byte(out), []byte("SET")) {
		t.Errorf("Output should contain SET")
	}
	if !bytes.Contains([]byte(out), []byte("10.0.0.1")) {
		t.Errorf("Output should contain src IP")
	}
}
