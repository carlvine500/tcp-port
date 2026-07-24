// Protocol sender tool: sends raw protocol packets to simulate traffic
// for tcp-port to capture and analyze.
//
// Usage: go run tools/protocol_sender.go dubbo|rocketmq|mongo
//
// Protocols:
//   dubbo    - Dubbo 2.x RPC request to 127.0.0.1:20880
//   rocketmq - RocketMQ RemotingCommand to 127.0.0.1:9876
//   mongo    - MongoDB OP_QUERY to 127.0.0.1:27017

package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: go run tools/protocol_sender.go dubbo|rocketmq|mongo\n")
		os.Exit(1)
	}

	protocol := os.Args[1]

	switch protocol {
	case "dubbo":
		sendDubbo()
	case "rocketmq":
		sendRocketMQ()
	case "mongo":
		sendMongo()
	default:
		fmt.Fprintf(os.Stderr, "Unknown protocol: %s (use: dubbo, rocketmq, mongo)\n", protocol)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// Dubbo protocol
// ---------------------------------------------------------------------------

func sendDubbo() {
	const addr = "127.0.0.1:20880"

	body := buildDubboBody()
	header := buildDubboHeader(uint32(len(body)))
	packet := append(header, body...)

	fmt.Printf("Sending Dubbo request (%d bytes) to %s ...\n", len(packet), addr)
	sendPacket("dubbo", "Dubbo", addr, packet)
}

func buildDubboHeader(dataLength uint32) []byte {
	// 16-byte Dubbo header (big-endian).
	// Layout:
	//   [0:2]   magic number (0xdabb)
	//   [2]     flag (serialization + twoway + event)
	//   [3]     status (0 = request)
	//   [4:12]  request ID
	//   [12:16] data length (body length)
	header := make([]byte, 16)

	binary.BigEndian.PutUint16(header[0:2], 0xdabb) // magic

	// flag: serialization=2 (Hessian2), twoway=true, event=false
	// bits 0-4: serialization id (2 = Hessian2 in Dubbo convention)
	// bit 5: twoway
	// bit 6: event
	header[2] = 0x22 // serialization=2, twoway=true

	header[3] = 0 // status=0 → request

	binary.BigEndian.PutUint64(header[4:12], 1) // requestID=1

	binary.BigEndian.PutUint32(header[12:16], dataLength)

	return header
}

// buildDubboBody constructs a Hessian2-encoded Dubbo request body.
//
// Dubbo request body format:
//
//	Hessian2 version byte (0x02)
//	dubbo_version  (string)
//	service_name   (string)
//	service_version(string)
//	method_name    (string)
//	param_types    (string)
//	arguments...   (values matching param_types)
//	attachments    (map)
func buildDubboBody() []byte {
	var b []byte

	// Hessian2 version
	b = append(b, 0x02)

	// dubbo_version: "2.7.0" (5 bytes) — short string tag = length
	b = append(b, 0x05)
	b = append(b, []byte("2.7.0")...)

	// service_name: "com.example.HelloService" (24 bytes)
	b = append(b, 0x18) // short string, 24 chars
	b = append(b, []byte("com.example.HelloService")...)

	// service_version: "1.0.0" (5 bytes)
	b = append(b, 0x05)
	b = append(b, []byte("1.0.0")...)

	// method_name: "sayHello" (8 bytes)
	b = append(b, 0x08)
	b = append(b, []byte("sayHello")...)

	// param_types: "Ljava/lang/String;" (21 bytes)
	b = append(b, 0x15) // 0x15 = 21
	b = append(b, []byte("Ljava/lang/String;")...)

	// arguments: one String value "world" (5 bytes)
	b = append(b, 0x05)
	b = append(b, []byte("world")...)

	// attachments: empty untyped map ('H' tag + 'Z' terminator)
	b = append(b, 'H', 'Z')

	return b
}

// ---------------------------------------------------------------------------
// RocketMQ Remoting protocol
// ---------------------------------------------------------------------------

func sendRocketMQ() {
	const addr = "127.0.0.1:9876"

	packet := buildRocketMQPacket()

	fmt.Printf("Sending RocketMQ request (%d bytes) to %s ...\n", len(packet), addr)
	sendPacket("rocketmq", "RocketMQ", addr, packet)
}

// buildRocketMQPacket constructs a RocketMQ RemotingCommand frame.
//
// Frame format (big-endian):
//
//	frame length  (4 bytes) — total length including this field
//	header length (4 bytes) — includes this 4-byte field itself
//	header JSON   (variable)
//	body          (variable, optional)
func buildRocketMQPacket() []byte {
	headerMap := map[string]interface{}{
		"code":     102, // GET_ROUTEINTO_BY_TOPIC
		"language": "JAVA",
		"version":  1,
		"opaque":   1,
		"flag":     0,
		"remark":   "",
		"extFields": map[string]string{
			"topic": "DefaultCluster",
		},
	}

	headerJSON, err := json.Marshal(headerMap)
	if err != nil {
		panic(err)
	}

	// body: empty (nameserver lookup-like request)
	body := []byte{}

	// header length = 4 (this field) + len(headerJSON)
	headerLen := 4 + len(headerJSON)

	// frame length = 4 (this field) + headerLen + len(body)
	frameLen := 4 + headerLen + len(body)

	buf := make([]byte, 0, frameLen)

	// frame length
	buf = binary.BigEndian.AppendUint32(buf, uint32(frameLen))

	// header length (includes itself)
	buf = binary.BigEndian.AppendUint32(buf, uint32(headerLen))

	// header JSON
	buf = append(buf, headerJSON...)

	// body
	buf = append(buf, body...)

	return buf
}

// ---------------------------------------------------------------------------
// MongoDB wire protocol
// ---------------------------------------------------------------------------

func sendMongo() {
	const addr = "127.0.0.1:27017"

	packet := buildMongoPacket()

	fmt.Printf("Sending MongoDB OP_QUERY (%d bytes) to %s ...\n", len(packet), addr)
	sendPacket("mongo", "MongoDB", addr, packet)
}

// buildMongoPacket constructs a MongoDB OP_QUERY message.
//
// MsgHeader (16 bytes, little-endian):
//
//	messageLength  (int32)
//	requestID      (int32)
//	responseTo     (int32)
//	opCode         (int32) = 2004 (OP_QUERY)
//
// OP_QUERY body:
//
//	flags              (int32)
//	fullCollectionName (null-terminated string)
//	numberToSkip       (int32)
//	numberToReturn     (int32)
//	query              (BSON document)
func buildMongoPacket() []byte {
	// Build OP_QUERY body first so we know the total length.
	queryBody := buildMongoQueryBody()

	// MsgHeader
	msgLen := 16 + len(queryBody) // header + body

	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(msgLen))   // messageLength
	binary.LittleEndian.PutUint32(hdr[4:8], 1)                 // requestID
	binary.LittleEndian.PutUint32(hdr[8:12], 0)                // responseTo
	binary.LittleEndian.PutUint32(hdr[12:16], 2004)            // opCode: OP_QUERY

	return append(hdr, queryBody...)
}

// buildMongoQueryBody constructs an OP_QUERY body with a BSON "isMaster" query.
func buildMongoQueryBody() []byte {
	var b []byte

	// Flags: 0
	b = binary.LittleEndian.AppendUint32(b, 0)

	// FullCollectionName: "admin.$cmd" + null terminator
	b = append(b, []byte("admin.$cmd")...)
	b = append(b, 0x00)

	// NumberToSkip: 0
	b = binary.LittleEndian.AppendUint32(b, 0)

	// NumberToReturn: -1 (first batch, returns all matching)
	b = binary.LittleEndian.AppendUint32(b, uint32(0xFFFFFFFF))

	// Query: BSON document {"isMaster": 1}
	bson := buildBSON(map[string]interface{}{"isMaster": int32(1)})
	b = append(b, bson...)

	return b
}

// buildBSON encodes a simple flat document with int32 and string values.
func buildBSON(doc map[string]interface{}) []byte {
	var b []byte

	// Placeholder for total length (4 bytes) — filled after.
	b = append(b, 0, 0, 0, 0)

	for key, val := range doc {
		switch v := val.(type) {
		case int32:
			b = append(b, 0x10) // type: int32
			b = append(b, []byte(key)...)
			b = append(b, 0x00) // key null terminator
			b = binary.LittleEndian.AppendUint32(b, uint32(v))
		case string:
			b = append(b, 0x02) // type: string
			b = append(b, []byte(key)...)
			b = append(b, 0x00) // key null terminator
			// BSON string: length(int32) + data + null
			strLen := len(v) + 1 // +1 for null terminator
			b = binary.LittleEndian.AppendUint32(b, uint32(strLen))
			b = append(b, []byte(v)...)
			b = append(b, 0x00)
		case int:
			b = append(b, 0x10) // type: int32
			b = append(b, []byte(key)...)
			b = append(b, 0x00) // key null terminator
			b = binary.LittleEndian.AppendUint32(b, uint32(v))
		}
	}

	// Document terminator
	b = append(b, 0x00)

	// Fill in total length
	binary.LittleEndian.PutUint32(b[0:4], uint32(len(b)))

	return b
}

// ---------------------------------------------------------------------------
// shared helper
// ---------------------------------------------------------------------------

func sendPacket(tag, name, addr string, packet []byte) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Printf("[%s] Connection to %s failed: %v\n", tag, addr, err)
		fmt.Printf("[%s] (Packet prepared but target is not listening. %s would capture the SYN attempt.)\n", tag, name)
		return
	}
	defer conn.Close()

	n, err := conn.Write(packet)
	if err != nil {
		fmt.Printf("[%s] Write error: %v\n", tag, err)
		return
	}

	fmt.Printf("[%s] Sent %d bytes successfully to %s\n", tag, n, addr)

	// Try to read a response (best effort, may fail if server closes immediately)
	resp := make([]byte, 4096)
	nr, err := conn.Read(resp)
	if err != nil {
		fmt.Printf("[%s] No response (or read error): %v\n", tag, err)
	} else if nr > 0 {
		fmt.Printf("[%s] Received %d response bytes\n", tag, nr)
	}
}
