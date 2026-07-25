package dubboport

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestParseDubboHeader tests the 16-byte dubbo header parsing
func TestParseDubboHeader(t *testing.T) {
	// Build a valid dubbo header
	header := make([]byte, DubboHeaderSize)
	binary.BigEndian.PutUint16(header[0:2], DubboMagicNumber)
	header[2] = 0x26 // serialization=6 (kryo), twoway=true, event=false
	header[3] = 0x00 // status=0 (request)
	binary.BigEndian.PutUint64(header[4:12], 12345)
	binary.BigEndian.PutUint32(header[12:16], 256)

	h, err := ParseDubboHeader(header)
	if err != nil {
		t.Fatalf("ParseDubboHeader failed: %v", err)
	}

	if h.Magic != DubboMagicNumber {
		t.Errorf("Magic = %04x, want %04x", h.Magic, DubboMagicNumber)
	}
	if h.SerializationID != SerializationKryo {
		t.Errorf("Serialization = %d, want %d", h.SerializationID, SerializationKryo)
	}
	if !h.IsTwoway {
		t.Error("IsTwoway = false, want true")
	}
	if h.IsEvent {
		t.Error("IsEvent = true, want false")
	}
	if !h.IsRequest {
		t.Error("IsRequest = false, want true")
	}
	if h.RequestID != 12345 {
		t.Errorf("RequestID = %d, want 12345", h.RequestID)
	}
	if h.DataLength != 256 {
		t.Errorf("DataLength = %d, want 256", h.DataLength)
	}
}

// TestParseDubboHeaderResponse tests parsing a response header
func TestParseDubboHeaderResponse(t *testing.T) {
	header := make([]byte, DubboHeaderSize)
	binary.BigEndian.PutUint16(header[0:2], DubboMagicNumber)
	header[2] = 0x00 // serialization=hessian2, twoway=false
	header[3] = StatusOK
	binary.BigEndian.PutUint64(header[4:12], 54321)
	binary.BigEndian.PutUint32(header[12:16], 100)

	h, err := ParseDubboHeader(header)
	if err != nil {
		t.Fatalf("ParseDubboHeader failed: %v", err)
	}

	if h.IsRequest {
		t.Error("IsRequest = true, want false (response)")
	}
	if h.Status != StatusOK {
		t.Errorf("Status = %d, want %d", h.Status, StatusOK)
	}
	if h.SerializationID != SerializationHessian2 {
		t.Errorf("Serialization = %d, want %d", h.SerializationID, SerializationHessian2)
	}
}

// TestParseDubboHeaderBadMagic tests handling of non-dubbo data
func TestParseDubboHeaderBadMagic(t *testing.T) {
	header := make([]byte, DubboHeaderSize)
	binary.BigEndian.PutUint16(header[0:2], 0x1234) // not dubbo

	_, err := ParseDubboHeader(header)
	if err == nil {
		t.Error("Expected error for bad magic, got nil")
	}
}

// TestParseDubboHeaderTooShort tests handling of truncated data
func TestParseDubboHeaderTooShort(t *testing.T) {
	_, err := ParseDubboHeader([]byte{0xda, 0xbb}) // only 2 bytes
	if err == nil {
		t.Error("Expected error for short header, got nil")
	}
}

// TestDetectDubbo tests protocol detection
func TestDetectDubbo(t *testing.T) {
	tests := []struct {
		data    []byte
		want    bool
	}{
		{[]byte{0xda, 0xbb}, true},
		{[]byte{0xda, 0xbb, 0x00, 0x00}, true},
		{[]byte{0x00, 0x00}, false},
		{[]byte{0x12, 0x34}, false},
		{[]byte{}, false},
		{[]byte{0xda}, false},
	}

	for _, tt := range tests {
		got := DetectDubbo(tt.data)
		if got != tt.want {
			t.Errorf("DetectDubbo(%x) = %v, want %v", tt.data, got, tt.want)
		}
	}
}

// TestSerializationTypeString tests serialization type names
func TestSerializationTypeString(t *testing.T) {
	tests := []struct {
		id   SerializationType
		want string
	}{
		{SerializationHessian2, "hessian2"},
		{SerializationJava, "java"},
		{SerializationKryo, "kryo"},
		{SerializationFastJson, "fastjson"},
		{SerializationProtobuf, "protobuf"},
		{SerializationType(99), "unknown(99)"},
	}

	for _, tt := range tests {
		got := tt.id.String()
		if got != tt.want {
			t.Errorf("SerializationType(%d).String() = %s, want %s", tt.id, got, tt.want)
		}
	}
}

// TestStatusString tests status code names
func TestStatusString(t *testing.T) {
	tests := []struct {
		status byte
		want   string
	}{
		{StatusOK, "OK"},
		{StatusClientTimeout, "CLIENT_TIMEOUT"},
		{StatusServerTimeout, "SERVER_TIMEOUT"},
		{StatusServiceNotFound, "SERVICE_NOT_FOUND"},
		{StatusServerError, "SERVER_ERROR"},
		{StatusServerThreadpoolExhausted, "SERVER_THREADPOOL_EXHAUSTED"},
		{255, "UNKNOWN(255)"},
	}

	for _, tt := range tests {
		got := StatusString(tt.status)
		if got != tt.want {
			t.Errorf("StatusString(%d) = %s, want %s", tt.status, got, tt.want)
		}
	}
}

// TestParseDubboBodyRequest tests heuristic body parsing for request metadata
func TestParseDubboBodyRequest(t *testing.T) {
	// Build a valid dubbo header
	header := make([]byte, DubboHeaderSize)
	binary.BigEndian.PutUint16(header[0:2], DubboMagicNumber)
	header[2] = 0x20 // serialization=hessian2, twoway=true
	header[3] = 0x00  // request
	binary.BigEndian.PutUint64(header[4:12], 1)

	// Build a minimal Hessian2 body: version + 4 strings
	// Hessian2 format: tag 0x02 (version), then strings
	body := []byte{
		0x02, // Hessian2 version
	}
	// String "2.7.0" (dubbo version) — 5 chars, short string tag=0x05
	body = append(body, 0x05)
	body = append(body, []byte("2.7.0")...)
	// String "com.example.DemoService" — 23 chars, long string tag=0x30, len=23
	body = append(body, 0x30, 23)
	body = append(body, []byte("com.example.DemoService")...)
	// String "1.0.0" (service version) — 5 chars
	body = append(body, 0x05)
	body = append(body, []byte("1.0.0")...)
	// String "sayHello" (method name) — 8 chars
	body = append(body, 0x08)
	body = append(body, []byte("sayHello")...)
	// String "Ljava/lang/String;" (param types) — 18 chars, long string tag=0x30
	body = append(body, 0x30, 18)
	body = append(body, []byte("Ljava/lang/String;")...)

	binary.BigEndian.PutUint32(header[12:16], uint32(len(body)))

	// Parse with ReadDubboMessage
	fullMsg := append(header, body...)
	h, err := ParseDubboHeader(header)
	if err != nil {
		t.Fatalf("ParseDubboHeader failed: %v", err)
	}

	msg := &DubboMessage{
		Header: h,
		Body:   body,
	}
	msg.ParseDubboBody()

	if msg.ServiceName != "com.example.DemoService" {
		t.Errorf("ServiceName = %s, want com.example.DemoService", msg.ServiceName)
	}
	if msg.ServiceVersion != "1.0.0" {
		t.Errorf("ServiceVersion = %s, want 1.0.0", msg.ServiceVersion)
	}
	if msg.MethodName != "sayHello" {
		t.Errorf("MethodName = %s, want sayHello", msg.MethodName)
	}
	if msg.ParamTypes != "Ljava/lang/String;" {
		t.Errorf("ParamTypes = %s, want Ljava/lang/String;", msg.ParamTypes)
	}

	_ = fullMsg
}

// TestReadDubboMessage tests full message reading
func TestReadDubboMessage(t *testing.T) {
	header := make([]byte, DubboHeaderSize)
	binary.BigEndian.PutUint16(header[0:2], DubboMagicNumber)
	header[2] = 0x20 // hessian2, twoway
	header[3] = 0x00
	binary.BigEndian.PutUint64(header[4:12], 42)

	// Build body with Hessian2 strings
	body := []byte{0x02} // version
	body = append(body, 0x01, 'd') // dubbo version "d"
	body = append(body, 0x01, 'S') // service "S"
	body = append(body, 0x01, 'v') // version "v"
	body = append(body, 0x01, 'm') // method "m"
	body = append(body, 0x01, 'p') // param "p"

	binary.BigEndian.PutUint32(header[12:16], uint32(len(body)))

	buf := bytes.NewBuffer(append(header, body...))
	msg, err := ReadDubboMessage(buf)
	if err != nil {
		t.Fatalf("ReadDubboMessage failed: %v", err)
	}

	if msg.Header.RequestID != 42 {
		t.Errorf("RequestID = %d, want 42", msg.Header.RequestID)
	}
	if msg.ServiceName != "S" {
		t.Errorf("ServiceName = %s, want S", msg.ServiceName)
	}
	if msg.ServiceVersion != "v" {
		t.Errorf("ServiceVersion = %s, want v", msg.ServiceVersion)
	}
	if msg.MethodName != "m" {
		t.Errorf("MethodName = %s, want m", msg.MethodName)
	}
	if msg.ParamTypes != "p" {
		t.Errorf("ParamTypes = %s, want p", msg.ParamTypes)
	}
}

// TestReadHessian2String tests hessian2 string parsing
func TestReadHessian2String(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantStr string
		wantPos int
	}{
		{
			name:    "short string",
			data:    []byte{0x05, 'h', 'e', 'l', 'l', 'o'},
			wantStr: "hello",
			wantPos: 6,
		},
		{
			name:    "1-byte length string",
			data:    []byte{0x30, 5, 'w', 'o', 'r', 'l', 'd'},
			wantStr: "world",
			wantPos: 7,
		},
		{
			name:    "non-string tag",
			data:    []byte{0xFF, 'x', 'y', 'z'},
			wantStr: "",
			wantPos: -1,
		},
		{
			name:    "empty data",
			data:    []byte{},
			wantStr: "",
			wantPos: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStr, gotPos := readHessian2String(tt.data, 0)
			if gotStr != tt.wantStr {
				t.Errorf("readHessian2String() string = %q, want %q", gotStr, tt.wantStr)
			}
			if gotPos != tt.wantPos {
				t.Errorf("readHessian2String() pos = %d, want %d", gotPos, tt.wantPos)
			}
		})
	}
}

// TestFixupFlagsApacheDubbo tests that Apache Dubbo flag layout
// (Twoway=0x40, Event=0x20) is auto-detected and corrected.
func TestFixupFlagsApacheDubbo(t *testing.T) {
	// Simulate Apache Dubbo layout:
	// Flag = serialization(hessian2=0) | Twoway(0x40) | Event(0x00) = 0x40
	// Current code initially parses: IsTwoway=false(0x20), IsEvent=true(0x40)
	// After fixup: IsTwoway=true, IsEvent=false
	h := &DubboHeader{
		Flag:       0x40, // Apache: twoway=true, event=false, serialization=0
		Status:     0x00, // request
		DataLength: 200,  // large body — not a heartbeat
		IsRequest:  true,
	}
	// Simulate initial (Alibaba) parsing
	h.IsTwoway = (h.Flag & FlagTwoway) != 0 // 0x40 & 0x20 = 0 → false
	h.IsEvent = (h.Flag & FlagEvent) != 0   // 0x40 & 0x40 = 1 → true

	h.fixupFlags()

	if !h.IsTwoway {
		t.Error("IsTwoway should be true after fixup (Apache layout)")
	}
	if h.IsEvent {
		t.Error("IsEvent should be false after fixup (Apache layout)")
	}
}

// TestFixupFlagsApacheDubboCompactedJava tests Apache layout with
// compactedjava serialization (mimics the user's reported scenario).
func TestFixupFlagsApacheDubboCompactedJava(t *testing.T) {
	h := &DubboHeader{
		Flag:       0x42, // serialization=2(compactedjava) | Twoway=0x40(Apache)
		Status:     0x00,
		DataLength: 1382, // user's reported body size
		IsRequest:  true,
	}
	h.IsTwoway = (h.Flag & FlagTwoway) != 0 // 0x42 & 0x20 = 0 → false (WRONG)
	h.IsEvent = (h.Flag & FlagEvent) != 0   // 0x42 & 0x40 = 1 → true (WRONG)

	h.fixupFlags()

	if !h.IsTwoway {
		t.Error("IsTwoway should be true after fixup (Apache layout with compactedjava)")
	}
	if h.IsEvent {
		t.Error("IsEvent should be false after fixup (Apache layout with compactedjava)")
	}
}

// TestFixupFlagsAlibabaDubbo tests that valid Alibaba Dubbo layout is NOT changed.
func TestFixupFlagsAlibabaDubbo(t *testing.T) {
	h := &DubboHeader{
		Flag:       0x22, // serialization=2 | Alibaba:Twoway=0x20, event=false
		Status:     0x00,
		DataLength: 300,
		IsRequest:  true,
	}
	h.IsTwoway = (h.Flag & FlagTwoway) != 0 // true
	h.IsEvent = (h.Flag & FlagEvent) != 0   // false

	h.fixupFlags()

	if !h.IsTwoway {
		t.Error("IsTwoway should remain true (Alibaba layout)")
	}
	if h.IsEvent {
		t.Error("IsEvent should remain false (Alibaba layout)")
	}
}

// TestFixupFlagsRealHeartbeat tests that real heartbeats are NOT fixed up.
func TestFixupFlagsRealHeartbeat(t *testing.T) {
	h := &DubboHeader{
		Flag:       0x62, // serialization=2 | Event=0x40, twoway=false
		Status:     0x00,
		DataLength: 1, // real heartbeat: 1-byte body
		IsRequest:  true,
	}
	h.IsTwoway = (h.Flag & FlagTwoway) != 0
	h.IsEvent = (h.Flag & FlagEvent) != 0

	origTwoway := h.IsTwoway
	origEvent := h.IsEvent

	h.fixupFlags()

	if h.IsTwoway != origTwoway {
		t.Error("Real heartbeat: IsTwoway should not change")
	}
	if h.IsEvent != origEvent {
		t.Error("Real heartbeat: IsEvent should not change")
	}
}

// TestParseCompactedJavaDirect tests direct parsing of compactedjava body.
func TestParseCompactedJavaDirect(t *testing.T) {
	var body []byte
	writeCJString := func(s string) {
		length := len(s)
		body = append(body, byte(length>>8), byte(length))
		body = append(body, []byte(s)...)
	}

	writeCJString("2.0.2")                    // dubbo version
	writeCJString("com.example.DemoService")   // service name
	writeCJString("1.0.0")                     // service version
	writeCJString("sayHello")                   // method name
	writeCJString("Ljava/lang/String;")         // param types

	header := &DubboHeader{
		SerializationID: SerializationCompactedJava,
		IsRequest:       true,
	}
	msg := &DubboMessage{
		Header: header,
		Body:   body,
	}
	msg.parseCompactedJavaDirect()

	if msg.ServiceName != "com.example.DemoService" {
		t.Errorf("ServiceName = %q, want %q", msg.ServiceName, "com.example.DemoService")
	}
	if msg.ServiceVersion != "1.0.0" {
		t.Errorf("ServiceVersion = %q, want %q", msg.ServiceVersion, "1.0.0")
	}
	if msg.MethodName != "sayHello" {
		t.Errorf("MethodName = %q, want %q", msg.MethodName, "sayHello")
	}
}

// TestIsReadableString tests the printable ASCII helper.
func TestIsReadableString(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"hello", true},
		{"com.example.DemoService", true},
		{"sayHello", true},
		{"2.0.2", true},
		{"Ljava/lang/String;", true},
		{"", false},
		{"hello\x00world", false},
		{"hello\xffworld", false},
	}
	for _, tt := range tests {
		got := isReadableString(tt.input)
		if got != tt.want {
			t.Errorf("isReadableString(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

// TestParseDubboBodyApacheCompactJava tests end-to-end:
// Apache Dubbo layout + compactedjava + large body → correct parsing.
func TestParseDubboBodyApacheCompactJava(t *testing.T) {
	var body []byte
	writeCJString := func(s string) {
		length := len(s)
		body = append(body, byte(length>>8), byte(length))
		body = append(body, []byte(s)...)
	}
	writeCJString("2.0.2")
	writeCJString("com.example.OrderService")
	writeCJString("1.0.0")
	writeCJString("createOrder")
	writeCJString("Lcom/example/Order;")

	header := &DubboHeader{
		Flag:             0x42, // Apache: twoway=0x40, event=false, serialization=2
		Status:           0x00,
		DataLength:       uint32(len(body)),
		SerializationID: SerializationCompactedJava,
		IsTwoway:        false, // initially mis-parsed
		IsEvent:         true,  // initially mis-parsed
		IsRequest:       true,
	}

	msg := &DubboMessage{
		Header: header,
		Body:   body,
	}
	msg.ParseDubboBody()

	// After fixup: IsTwoway should be true, IsEvent false
	if !msg.Header.IsTwoway {
		t.Error("IsTwoway should be corrected to true")
	}
	if msg.Header.IsEvent {
		t.Error("IsEvent should be corrected to false")
	}

	// Service/method should be parsed
	if msg.ServiceName != "com.example.OrderService" {
		t.Errorf("ServiceName = %q, want %q", msg.ServiceName, "com.example.OrderService")
	}
	if msg.MethodName != "createOrder" {
		t.Errorf("MethodName = %q, want %q", msg.MethodName, "createOrder")
	}
	if msg.ServiceVersion != "1.0.0" {
		t.Errorf("ServiceVersion = %q, want %q", msg.ServiceVersion, "1.0.0")
	}
}
