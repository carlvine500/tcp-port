package redisport

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// RESP types
const (
	TypeSimpleString = '+'
	TypeError        = '-'
	TypeInteger      = ':'
	TypeBulkString   = '$'
	TypeArray        = '*'
)

// RESPType returns the human-readable name for a RESP type byte.
func RESPType(b byte) string {
	switch b {
	case TypeSimpleString:
		return "SimpleString"
	case TypeError:
		return "Error"
	case TypeInteger:
		return "Integer"
	case TypeBulkString:
		return "BulkString"
	case TypeArray:
		return "Array"
	default:
		return fmt.Sprintf("Unknown(0x%x)", b)
	}
}

// RESPCommand represents a parsed Redis command.
type RESPCommand struct {
	Raw      string   // raw request line
	Command  string   // uppercase command name (SET, GET, etc.)
	Args     []string // command arguments
	ArgCount int
}

// REDISResponse represents a parsed Redis response.
type RESPResponse struct {
	Raw      string
	Type     byte
	Value    string
	IsError  bool
}

// ReadRESPCommand reads a RESP command from reader (client → server).
// Redis commands are sent as RESP arrays of bulk strings.
func ReadRESPCommand(r *bufio.Reader) (*RESPCommand, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) == 0 {
		return nil, io.EOF
	}

	if line[0] != TypeArray {
		// Inline command (old style), e.g., "PING\r\n"
		parts := strings.Fields(line)
		if len(parts) == 0 {
			return &RESPCommand{Raw: line}, nil
		}
		return &RESPCommand{
			Raw:      line,
			Command:  strings.ToUpper(parts[0]),
			Args:     parts[1:],
			ArgCount: len(parts),
		}, nil
	}

	// RESP array: *<count>\r\n<elements...>
	count, err := strconv.Atoi(line[1:])
	if err != nil {
		return nil, fmt.Errorf("bad array count: %s", line)
	}

	args := make([]string, 0, count)
	rawLines := []string{line}

	for i := 0; i < count; i++ {
		bl, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		bl = strings.TrimRight(bl, "\r\n")
		rawLines = append(rawLines, bl)

		if len(bl) == 0 || bl[0] != TypeBulkString {
			continue
		}

		blen, err := strconv.Atoi(bl[1:])
		if err != nil {
			continue
		}

		if blen < 0 {
			args = append(args, "") // null bulk string
			continue
		}

		// Read the bulk string content
		buf := make([]byte, blen+2) // +2 for \r\n
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		val := string(buf[:blen])
		rawLines = append(rawLines, val)
		args = append(args, val)
	}

	cmd := ""
	if len(args) > 0 {
		cmd = strings.ToUpper(args[0])
	}

	return &RESPCommand{
		Raw:      strings.Join(rawLines, "\\r\\n"),
		Command:  cmd,
		Args:     args,
		ArgCount: len(args),
	}, nil
}

// ReadRESPResponse reads a Redis response from reader (server → client).
func ReadRESPResponse(r *bufio.Reader) (*RESPResponse, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) == 0 {
		return nil, io.EOF
	}

	resp := &RESPResponse{Raw: line}
	resp.Type = line[0]

	switch line[0] {
	case TypeSimpleString:
		resp.Value = line[1:]
	case TypeError:
		resp.Value = line[1:]
		resp.IsError = true
	case TypeInteger:
		resp.Value = line[1:]
	case TypeBulkString:
		blen, err := strconv.Atoi(line[1:])
		if err != nil {
			return resp, nil
		}
		if blen < 0 {
			resp.Value = "(nil)"
			return resp, nil
		}
		buf := make([]byte, blen+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return resp, err
		}
		resp.Value = string(buf[:blen])
	case TypeArray:
		count, err := strconv.Atoi(line[1:])
		if err != nil {
			return resp, nil
		}
		if count < 0 {
			resp.Value = "(nil array)"
			return resp, nil
		}
		// Read array elements (simplified: just count them)
		parts := make([]string, 0, count)
		for i := 0; i < count; i++ {
			sub, err := ReadRESPResponse(r)
			if err != nil {
				break
			}
			parts = append(parts, sub.Value)
		}
		resp.Value = "[" + strings.Join(parts, ", ") + "]"
		if len(parts) > 4 {
			resp.Value = fmt.Sprintf("[%d elements: %s, ...]", count, strings.Join(parts[:3], ", "))
		}
	}

	return resp, nil
}

// DetectRESP checks if data looks like Redis RESP protocol.
func DetectRESP(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	b := data[0]
	return b == TypeArray || b == TypeSimpleString || b == TypeError ||
		b == TypeInteger || b == TypeBulkString
}

var redisCommands = map[string]bool{
	// Keys
	"DEL": true, "DUMP": true, "EXISTS": true, "EXPIRE": true, "EXPIREAT": true,
	"KEYS": true, "MIGRATE": true, "MOVE": true, "OBJECT": true, "PERSIST": true,
	"PEXPIRE": true, "PEXPIREAT": true, "PTTL": true, "RANDOMKEY": true,
	"RENAME": true, "RENAMENX": true, "RESTORE": true, "SORT": true, "TTL": true,
	"TYPE": true, "SCAN": true, "UNLINK": true,
	// Strings
	"APPEND": true, "BITCOUNT": true, "BITOP": true, "BITPOS": true,
	"DECR": true, "DECRBY": true, "GET": true, "GETBIT": true, "GETRANGE": true,
	"GETSET": true, "INCR": true, "INCRBY": true, "INCRBYFLOAT": true,
	"MGET": true, "MSET": true, "MSETNX": true, "PSETEX": true,
	"SET": true, "SETBIT": true, "SETEX": true, "SETNX": true, "SETRANGE": true,
	"STRLEN": true,
	// Hashes
	"HDEL": true, "HEXISTS": true, "HGET": true, "HGETALL": true, "HINCRBY": true,
	"HINCRBYFLOAT": true, "HKEYS": true, "HLEN": true, "HMGET": true, "HMSET": true,
	"HSET": true, "HSETNX": true, "HVALS": true, "HSCAN": true, "HSTRLEN": true,
	// Lists
	"BLPOP": true, "BRPOP": true, "BRPOPLPUSH": true, "LINDEX": true, "LINSERT": true,
	"LLEN": true, "LPOP": true, "LPUSH": true, "LPUSHX": true, "LRANGE": true,
	"LREM": true, "LSET": true, "LTRIM": true, "RPOP": true, "RPOPLPUSH": true,
	"RPUSH": true, "RPUSHX": true,
	// Sets
	"SADD": true, "SCARD": true, "SDIFF": true, "SDIFFSTORE": true, "SINTER": true,
	"SINTERSTORE": true, "SISMEMBER": true, "SMEMBERS": true, "SMOVE": true,
	"SPOP": true, "SRANDMEMBER": true, "SREM": true, "SUNION": true,
	"SUNIONSTORE": true, "SSCAN": true,
	// Sorted Sets
	"ZADD": true, "ZCARD": true, "ZCOUNT": true, "ZINCRBY": true,
	"ZINTERSTORE": true, "ZLEXCOUNT": true, "ZRANGE": true, "ZRANGEBYLEX": true,
	"ZRANGEBYSCORE": true, "ZRANK": true, "ZREM": true, "ZREMRANGEBYLEX": true,
	"ZREMRANGEBYRANK": true, "ZREMRANGEBYSCORE": true, "ZREVRANGE": true,
	"ZREVRANGEBYLEX": true, "ZREVRANGEBYSCORE": true, "ZREVRANK": true,
	"ZSCORE": true, "ZUNIONSTORE": true, "ZSCAN": true,
	// Pub/Sub
	"PSUBSCRIBE": true, "PUBLISH": true, "PUBSUB": true, "PUNSUBSCRIBE": true,
	"SUBSCRIBE": true, "UNSUBSCRIBE": true,
	// Transactions
	"DISCARD": true, "EXEC": true, "MULTI": true, "UNWATCH": true, "WATCH": true,
	// Scripting
	"EVAL": true, "EVALSHA": true, "SCRIPT": true,
	// Server
	"AUTH": true, "CLIENT": true, "CLUSTER": true, "COMMAND": true, "CONFIG": true,
	"DBSIZE": true, "DEBUG": true, "ECHO": true, "FLUSHALL": true, "FLUSHDB": true,
	"INFO": true, "LATENCY": true, "MEMORY": true, "MONITOR": true, "PING": true,
	"QUIT": true, "REPLICAOF": true, "ROLE": true, "SAVE": true, "SELECT": true,
	"SHUTDOWN": true, "SLAVEOF": true, "SLOWLOG": true, "SYNC": true, "TIME": true,
	// Streams
	"XADD": true, "XDEL": true, "XLEN": true, "XRANGE": true, "XREAD": true,
	"XREVRANGE": true, "XGROUP": true, "XPENDING": true, "XACK": true,
	// Sentinel
	"SENTINEL": true,
}

// IsKnownRedisCommand checks if a cmd is a known Redis command.
func IsKnownRedisCommand(cmd string) bool {
	return redisCommands[strings.ToUpper(cmd)]
}
