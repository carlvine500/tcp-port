package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/hsiafan/vlog"

	"github.com/carlvine500/tcp-port/dubboport"
	"github.com/carlvine500/tcp-port/httpport"
	"github.com/carlvine500/tcp-port/mongoport"
	"github.com/carlvine500/tcp-port/mysqlport"
	"github.com/carlvine500/tcp-port/redisport"
	"github.com/carlvine500/tcp-port/rocketmqport"
	"github.com/carlvine500/tcp-port/tcpport"
)

var logger = vlog.CurrentPackageLogger()

func init() { logger.SetAppenders(vlog.NewConsole2Appender()) }

// Config holds all CLI flags.
type Config struct {
	Level    string
	IP       string
	Port     uint16
	Device   string
	File     string
	Output   string
	Protocol string // dubbo, redis, rocketmq, mysql, mongo, auto

	// Protocol-specific filters
	DubboService string
	DubboMethod  string
	RedisCommand string
	RedisKey     string
	RMQCode      int
	MySQLCommand string
	MySQLQuery   string
	MongoOpCode  int
}

// ProtocolHandler is a factory for creating traffic handlers for a protocol.
type ProtocolHandler struct {
	Name     string
	Detector tcpport.ProtocolDetector
	Handler  func(ck ConnectionKey, cfg *Config, printer *tcpport.Printer) TrafficHandler
}

// ConnectionKey identifies a connection.
type ConnectionKey struct {
	Src tcpport.Endpoint
	Dst tcpport.Endpoint
}

func (ck ConnectionKey) SrcString() string { return ck.Src.String() }
func (ck ConnectionKey) DstString() string { return ck.Dst.String() }

// TrafficHandler processes protocol traffic on a connection.
type TrafficHandler interface {
	Handle(conn *tcpport.TCPConnection)
}

// ---- Base handler with common helpers ----

type baseHandler struct {
	Key     ConnectionKey
	Config  *Config
	Printer *tcpport.Printer
	Buf     *bytes.Buffer
}

func (h *baseHandler) writeLine(a ...interface{}) {
	fmt.Fprintln(h.Buf, a...)
}

func (h *baseHandler) initBuf() { h.Buf = new(bytes.Buffer) }

func (h *baseHandler) filterService(service string) bool {
	if h.Config.DubboService != "" && !tcpport.WildcardMatch(service, h.Config.DubboService) {
		return true
	}
	return false
}

func (h *baseHandler) filterMethod(method string) bool {
	if h.Config.DubboMethod != "" && !tcpport.WildcardMatch(method, h.Config.DubboMethod) {
		return true
	}
	return false
}

// ---- Dubbo Handler ----

type dubboHandler struct{ baseHandler }

func (h *dubboHandler) Handle(conn *tcpport.TCPConnection) {
	defer conn.UpStream.Close()
	defer conn.DownStream.Close()

	reqR := bufio.NewReader(conn.UpStream)
	defer tcpport.DiscardAll(reqR)
	respR := bufio.NewReader(conn.DownStream)
	defer tcpport.DiscardAll(respR)

	// Detect dubbo vs triple
	peek, _ := reqR.Peek(24)
	if dubboport.DetectDubbo(peek) {
		h.handleDubbo(reqR, respR)
	} else if dubboport.DetectTriple(peek) {
		h.handleTriple(reqR, respR)
	}
}

func (h *dubboHandler) handleDubbo(reqR, respR *bufio.Reader) {
	for {
		h.initBuf()
		req, err := dubboport.ReadDubboMessage(reqR)
		if err != nil {
			break
		}
		if h.filterService(req.ServiceName) || h.filterMethod(req.MethodName) {
			continue
		}
		if h.Config.Level == "url" {
			h.writeLine(dubboport.FormatDubboURL(req, h.Key.SrcString(), h.Key.DstString()))
		} else {
			h.writeLine(dubboport.FormatDubbo(req, h.Key.SrcString(), h.Key.DstString()))
		}
		if !req.Header.IsTwoway || req.Header.IsEvent {
			h.Printer.Send(h.Buf.String())
			continue
		}
		resp, err := dubboport.ReadDubboMessage(respR)
		if err != nil {
			break
		}
		if h.Config.Level != "url" {
			h.writeLine("")
			h.writeLine(dubboport.FormatDubbo(resp, h.Key.DstString(), h.Key.SrcString()))
		}
		h.writeLine("")
		h.Printer.Send(h.Buf.String())
	}
	h.Printer.Send(h.Buf.String())
}

func (h *dubboHandler) handleTriple(reqR, respR *bufio.Reader) {
	h.initBuf()
	msgs, _, _ := dubboport.ReadTripleMessages(reqR)
	for _, msg := range msgs {
		if h.filterService(msg.ServiceName) || h.filterMethod(msg.MethodName) {
			continue
		}
		if h.Config.Level == "url" {
			h.writeLine(dubboport.FormatTripleURL(&msg, h.Key.SrcString(), h.Key.DstString()))
		} else {
			h.writeLine(dubboport.FormatTriple(&msg, h.Key.SrcString(), h.Key.DstString()))
		}
		h.writeLine("")
	}
	h.Printer.Send(h.Buf.String())
}

// ---- Redis Handler ----

type redisHandler struct {
	baseHandler
	keyRe *regexp.Regexp
}

func (h *redisHandler) Handle(conn *tcpport.TCPConnection) {
	defer conn.UpStream.Close()
	defer conn.DownStream.Close()
	reqR := bufio.NewReader(conn.UpStream)
	defer tcpport.DiscardAll(reqR)
	respR := bufio.NewReader(conn.DownStream)
	defer tcpport.DiscardAll(respR)

	if h.Config.RedisKey != "" {
		h.keyRe = regexp.MustCompile(h.Config.RedisKey)
	}

	for {
		h.initBuf()
		cmd, err := redisport.ReadRESPCommand(reqR)
		if err != nil {
			break
		}
		if h.Config.RedisCommand != "" && !tcpport.WildcardMatch(strings.ToUpper(cmd.Command), strings.ToUpper(h.Config.RedisCommand)) {
			continue
		}
		// Filter by key regex
		if h.keyRe != nil {
			key := ""
			if len(cmd.Args) > 1 {
				key = cmd.Args[1]
			}
			if !h.keyRe.MatchString(key) {
				continue
			}
		}
		if h.Config.Level == "url" {
			h.writeLine(redisport.FormatRESPURL(cmd, h.Key.SrcString(), h.Key.DstString()))
		} else {
			h.writeLine(redisport.FormatRESPCommand(cmd, h.Key.SrcString(), h.Key.DstString()))
		}
		resp, err := redisport.ReadRESPResponse(respR)
		if err != nil {
			h.Printer.Send(h.Buf.String())
			break
		}
		if h.Config.Level != "url" {
			h.writeLine(redisport.FormatRESPResponse(resp, h.Key.DstString(), h.Key.SrcString()))
		}
		h.writeLine("")
		h.Printer.Send(h.Buf.String())
	}
	h.Printer.Send(h.Buf.String())
}

// ---- RocketMQ Handler ----

type rocketmqHandler struct{ baseHandler }

func (h *rocketmqHandler) Handle(conn *tcpport.TCPConnection) {
	defer conn.UpStream.Close()
	defer conn.DownStream.Close()
	reqR := bufio.NewReader(conn.UpStream)
	defer tcpport.DiscardAll(reqR)
	respR := bufio.NewReader(conn.DownStream)
	defer tcpport.DiscardAll(respR)

	for {
		h.initBuf()
		req, err := rocketmqport.ReadRemotingCommand(reqR)
		if err != nil {
			break
		}
		if h.Config.RMQCode != 0 && req.Code != h.Config.RMQCode {
			continue
		}
		if h.Config.Level == "url" {
			h.writeLine(rocketmqport.FormatRemotingURL(req, h.Key.SrcString(), h.Key.DstString()))
		} else {
			h.writeLine(rocketmqport.FormatRemotingCommand(req, h.Key.SrcString(), h.Key.DstString()))
		}
		resp, err := rocketmqport.ReadRemotingCommand(respR)
		if err != nil {
			h.Printer.Send(h.Buf.String())
			break
		}
		if h.Config.Level != "url" {
			h.writeLine(rocketmqport.FormatRemotingResponse(resp, h.Key.DstString(), h.Key.SrcString()))
		}
		h.writeLine("")
		h.Printer.Send(h.Buf.String())
	}
	h.Printer.Send(h.Buf.String())
}

// ---- MySQL Handler ----

type mysqlHandler struct{ baseHandler }

func (h *mysqlHandler) Handle(conn *tcpport.TCPConnection) {
	defer conn.UpStream.Close()
	defer conn.DownStream.Close()
	clientR := bufio.NewReader(conn.UpStream)
	defer tcpport.DiscardAll(clientR)
	serverR := bufio.NewReader(conn.DownStream)
	defer tcpport.DiscardAll(serverR)

	// Handshake
	h.initBuf()
	if msg, err := mysqlport.ReadMySQLMessage(serverR, "S->C"); err == nil {
		if h.Config.Level == "url" {
			h.writeLine(mysqlport.FormatMySQLURL(msg, h.Key.SrcString(), h.Key.DstString()))
		} else if msg.Type == "handshake" {
			h.writeLine(mysqlport.FormatMySQLMessage(msg, h.Key.SrcString(), h.Key.DstString()))
		}
		h.writeLine("")
		h.Printer.Send(h.Buf.String())
	}

	for {
		h.initBuf()
		cmd, err := mysqlport.ReadMySQLMessage(clientR, "C->S")
		if err != nil {
			break
		}
		if h.Config.MySQLCommand != "" && !tcpport.WildcardMatch(strings.ToUpper(cmd.CommandName), strings.ToUpper(h.Config.MySQLCommand)) {
			continue
		}
		if h.Config.MySQLQuery != "" && !strings.Contains(cmd.Query, h.Config.MySQLQuery) {
			continue
		}
		if h.Config.Level == "url" {
			h.writeLine(mysqlport.FormatMySQLURL(cmd, h.Key.SrcString(), h.Key.DstString()))
		} else {
			h.writeLine(mysqlport.FormatMySQLMessage(cmd, h.Key.SrcString(), h.Key.DstString()))
		}
		for i := 0; i < 10; i++ {
			resp, err := mysqlport.ReadMySQLMessage(serverR, "S->C")
			if err != nil {
				break
			}
			if h.Config.Level != "url" {
				h.writeLine(mysqlport.FormatMySQLMessage(resp, h.Key.DstString(), h.Key.SrcString()))
			}
			if resp.Type == "ok" || resp.Type == "eof" || resp.Type == "error" {
				break
			}
		}
		h.writeLine("")
		h.Printer.Send(h.Buf.String())
	}
	h.Printer.Send(h.Buf.String())
}

// ---- MongoDB Handler ----

type mongoHandler struct{ baseHandler }

func (h *mongoHandler) Handle(conn *tcpport.TCPConnection) {
	defer conn.UpStream.Close()
	defer conn.DownStream.Close()
	reqR := bufio.NewReader(conn.UpStream)
	defer tcpport.DiscardAll(reqR)
	respR := bufio.NewReader(conn.DownStream)
	defer tcpport.DiscardAll(respR)

	for {
		h.initBuf()
		req, err := mongoport.ReadMongoMessage(reqR, "C->S")
		if err != nil {
			break
		}
		if h.Config.MongoOpCode != 0 && req.Header.OpCode != int32(h.Config.MongoOpCode) {
			continue
		}
		if h.Config.Level == "url" {
			h.writeLine(mongoport.FormatMongoURL(req, h.Key.SrcString(), h.Key.DstString()))
		} else {
			h.writeLine(mongoport.FormatMongoMessage(req, h.Key.SrcString(), h.Key.DstString()))
		}
		for i := 0; i < 5; i++ {
			resp, err := mongoport.ReadMongoMessage(respR, "S->C")
			if err != nil {
				break
			}
			if h.Config.Level != "url" {
				h.writeLine(mongoport.FormatMongoResponse(resp, h.Key.DstString(), h.Key.SrcString()))
			}
		}
		h.writeLine("")
		h.Printer.Send(h.Buf.String())
	}
	h.Printer.Send(h.Buf.String())
}

// ---- HTTP Handler ----

type httpHandler struct{ baseHandler }

func (h *httpHandler) Handle(conn *tcpport.TCPConnection) {
	defer conn.UpStream.Close()
	defer conn.DownStream.Close()
	reqR := bufio.NewReader(conn.UpStream)
	defer tcpport.DiscardAll(reqR)
	respR := bufio.NewReader(conn.DownStream)
	defer tcpport.DiscardAll(respR)

	for {
		h.initBuf()
		req, err := httpport.ReadHTTPMessage(reqR)
		if err != nil {
			break
		}
		if h.Config.Level == "url" {
			h.writeLine(httpport.FormatHTTPURL(req, h.Key.SrcString(), h.Key.DstString()))
		} else {
			h.writeLine(httpport.FormatHTTP(req, h.Key.SrcString(), h.Key.DstString()))
		}
		resp, err := httpport.ReadHTTPMessage(respR)
		if err != nil {
			h.Printer.Send(h.Buf.String())
			break
		}
		if h.Config.Level != "url" {
			h.writeLine(httpport.FormatHTTP(resp, h.Key.DstString(), h.Key.SrcString()))
		}
		h.writeLine("")
		h.Printer.Send(h.Buf.String())
	}
	h.Printer.Send(h.Buf.String())
}

// ---- Auto-detect multi-handler ----

type autoHandler struct {
	baseHandler
	detected    string
	subHandler  TrafficHandler
	conn        *tcpport.TCPConnection
	setup       sync.Once
	peekResult  []byte
	peekErr     error
}

func (h *autoHandler) Handle(conn *tcpport.TCPConnection) {
	h.conn = conn
	// Peek at first bytes
	peek, err := bufio.NewReader(conn.UpStream).Peek(24)
	h.peekResult = peek
	h.peekErr = err
	// Now run the real handler
	h.run()
}

func (h *autoHandler) run() {
	// Try detectors in order
	detectors := []struct {
		name string
		fn   tcpport.ProtocolDetector
		make func() TrafficHandler
	}{
		{"dubbo", dubboport.DetectDubbo, func() TrafficHandler { return &dubboHandler{baseHandler: h.baseHandler} }},
		{"triple", dubboport.DetectTriple, func() TrafficHandler { return &dubboHandler{baseHandler: h.baseHandler} }},
		{"redis", redisport.DetectRESP, func() TrafficHandler { return &redisHandler{baseHandler: h.baseHandler} }},
		{"rocketmq", rocketmqport.DetectRocketMQ, func() TrafficHandler { return &rocketmqHandler{baseHandler: h.baseHandler} }},
		{"mysql", mysqlport.DetectMySQL, func() TrafficHandler { return &mysqlHandler{baseHandler: h.baseHandler} }},
		{"mongo", mongoport.DetectMongo, func() TrafficHandler { return &mongoHandler{baseHandler: h.baseHandler} }},
		{"http", httpport.DetectHTTP, func() TrafficHandler { return &httpHandler{baseHandler: h.baseHandler} }},
	}

	for _, d := range detectors {
		if len(h.peekResult) > 0 && d.fn(h.peekResult) {
			logger.Info("auto-detected protocol:", d.name)
			h.detected = d.name
			h.subHandler = d.make()
			h.subHandler.Handle(h.conn)
			return
		}
	}
	logger.Debug("unknown protocol, skipping connection", h.Key)
	h.conn.UpStream.Close()
	h.conn.DownStream.Close()
}

// ---- ConnectionHandler adapter ----

type connHandlerAdapter struct {
	cfg     *Config
	printer *tcpport.Printer
	proto   *ProtocolHandler
}

func (a *connHandlerAdapter) Handle(src, dst tcpport.Endpoint, conn *tcpport.TCPConnection) {
	ck := ConnectionKey{Src: src, Dst: dst}
	handler := a.proto.Handler(ck, a.cfg, a.printer)
	handler.Handle(conn)
}

func (a *connHandlerAdapter) Finish() {}

// ---- Main ----

func main() {
	cfg := parseFlags()

	// Build protocol handlers registry
	protocols := map[string]ProtocolHandler{
		"dubbo": {
			Name:     "dubbo",
			Detector: dubboport.DetectDubbo,
			Handler: func(ck ConnectionKey, cfg *Config, p *tcpport.Printer) TrafficHandler {
				return &dubboHandler{baseHandler{Key: ck, Config: cfg, Printer: p}}
			},
		},
		"redis": {
			Name:     "redis",
			Detector: redisport.DetectRESP,
			Handler: func(ck ConnectionKey, cfg *Config, p *tcpport.Printer) TrafficHandler {
				return &redisHandler{baseHandler: baseHandler{Key: ck, Config: cfg, Printer: p}}
			},
		},
		"rocketmq": {
			Name:     "rocketmq",
			Detector: rocketmqport.DetectRocketMQ,
			Handler: func(ck ConnectionKey, cfg *Config, p *tcpport.Printer) TrafficHandler {
				return &rocketmqHandler{baseHandler{Key: ck, Config: cfg, Printer: p}}
			},
		},
		"mysql": {
			Name:     "mysql",
			Detector: mysqlport.DetectMySQL,
			Handler: func(ck ConnectionKey, cfg *Config, p *tcpport.Printer) TrafficHandler {
				return &mysqlHandler{baseHandler{Key: ck, Config: cfg, Printer: p}}
			},
		},
		"mongo": {
			Name:     "mongo",
			Detector: mongoport.DetectMongo,
			Handler: func(ck ConnectionKey, cfg *Config, p *tcpport.Printer) TrafficHandler {
				return &mongoHandler{baseHandler{Key: ck, Config: cfg, Printer: p}}
			},
		},
		"http": {
			Name:     "http",
			Detector: httpport.DetectHTTP,
			Handler: func(ck ConnectionKey, cfg *Config, p *tcpport.Printer) TrafficHandler {
				return &httpHandler{baseHandler{Key: ck, Config: cfg, Printer: p}}
			},
		},
	}

	// Select protocol
	var proto *ProtocolHandler
	if cfg.Protocol == "auto" || cfg.Protocol == "" {
		// Use a multi-detector
		autoPH := &ProtocolHandler{
			Name: "auto",
			Detector: func(data []byte) bool {
				for _, p := range protocols {
					if p.Detector(data) {
						return true
					}
				}
				return false
			},
			Handler: func(ck ConnectionKey, cfg *Config, p *tcpport.Printer) TrafficHandler {
				return &autoHandler{baseHandler: baseHandler{Key: ck, Config: cfg, Printer: p}}
			},
		}
		proto = autoPH
	} else {
		if ph, ok := protocols[cfg.Protocol]; ok {
			proto = &ph
		} else {
			fmt.Fprintf(os.Stderr, "Unknown protocol: %s. Supported: %s\n", cfg.Protocol, protocolNames(protocols))
			os.Exit(1)
		}
	}

	printer := tcpport.NewPrinter(cfg.Output)
	adapter := &connHandlerAdapter{cfg: cfg, printer: printer, proto: proto}
	assembler := tcpport.NewTCPAssembler(adapter, proto.Detector)
	assembler.FilterIP = cfg.IP
	assembler.FilterPort = cfg.Port

	packets := openPackets(cfg)
	if packets == nil {
		return
	}

	ticker := time.Tick(time.Second * 30)
outer:
	for {
		select {
		case pkt := <-packets:
			if pkt == nil {
				break outer
			}
			if pkt.NetworkLayer() == nil || pkt.TransportLayer() == nil ||
				pkt.TransportLayer().LayerType() != layers.LayerTypeTCP {
				continue
			}
			tcp := pkt.TransportLayer().(*layers.TCP)
			assembler.Assemble(pkt.NetworkLayer().NetworkFlow(), tcp, pkt.Metadata().Timestamp)
		case <-ticker:
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}

	assembler.FinishAll()
	printer.Finish()
}

func protocolNames(m map[string]ProtocolHandler) string {
	names := []string{"auto"}
	for k := range m {
		names = append(names, k)
	}
	return strings.Join(names, ", ")
}

func parseFlags() *Config {
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	cfg := &Config{}

	fs.StringVar(&cfg.Level, "level", "header", "Output level: url | header | all")
	fs.StringVar(&cfg.IP, "ip", "", "Filter by ip")
	var port uint
	fs.UintVar(&port, "port", 0, "Filter by port (default: any)")
	fs.StringVar(&cfg.Device, "device", "any", "Capture from network device")
	fs.StringVar(&cfg.File, "file", "", "Read from pcap file")
	fs.StringVar(&cfg.Output, "output", "", "Write to file instead of stdout")
	fs.StringVar(&cfg.Protocol, "protocol", "auto", "Protocol: auto, dubbo, redis, rocketmq, mysql, mongo")

	fs.StringVar(&cfg.DubboService, "dubbo-service", "", "Dubbo: filter by service name (wildcard)")
	fs.StringVar(&cfg.DubboMethod, "dubbo-method", "", "Dubbo: filter by method name (wildcard)")
	fs.StringVar(&cfg.RedisCommand, "redis-command", "", "Redis: filter by command (SET, GET, etc.)")
	fs.StringVar(&cfg.RedisKey, "redis-key", "", "Redis: filter by key (regex pattern)")
	fs.IntVar(&cfg.RMQCode, "rmq-code", 0, "RocketMQ: filter by request code")
	fs.StringVar(&cfg.MySQLCommand, "mysql-command", "", "MySQL: filter by command (Query, Ping, etc.)")
	fs.StringVar(&cfg.MySQLQuery, "mysql-query", "", "MySQL: filter by query substring")
	fs.IntVar(&cfg.MongoOpCode, "mongo-opcode", 0, "MongoDB: filter by opcode")

	fs.Parse(os.Args[1:])
	cfg.Port = uint16(port)
	return cfg
}

func openPackets(cfg *Config) chan gopacket.Packet {
	if cfg.File != "" {
		handle, err := pcap.OpenOffline(cfg.File)
		if err != nil {
			logger.Error("Open file", cfg.File, "error:", err)
			return nil
		}
		return gopacket.NewPacketSource(handle, handle.LinkType()).Packets()
	}

	if cfg.Device == "any" && runtime.GOOS != "linux" {
		interfaces, err := pcap.FindAllDevs()
		if err != nil {
			logger.Error("find device error:", err)
			return nil
		}
		var chs []chan gopacket.Packet
		for _, itf := range interfaces {
			ch := openDevice(itf.Name, cfg.IP, cfg.Port)
			if ch != nil {
				chs = append(chs, ch)
			}
		}
		return mergeChannels(chs)
	}

	return openDevice(cfg.Device, cfg.IP, cfg.Port)
}

func openDevice(device, ip string, port uint16) chan gopacket.Packet {
	defer func() { _ = recover() }()
	handle, err := pcap.OpenLive(device, 65536, false, pcap.BlockForever)
	if err != nil {
		logger.Warn("open device", device, "error:", err)
		return nil
	}
	bpf := "tcp"
	if port != 0 {
		bpf += " port " + strconv.Itoa(int(port))
	}
	if ip != "" {
		bpf += " ip host " + ip
	}
	if err := handle.SetBPFFilter(bpf); err != nil {
		logger.Warn("set filter failed:", err)
	}
	return gopacket.NewPacketSource(handle, handle.LinkType()).Packets()
}

func mergeChannels(chs []chan gopacket.Packet) chan gopacket.Packet {
	ch := make(chan gopacket.Packet)
	for _, c := range chs {
		go func(c chan gopacket.Packet) {
			for p := range c {
				ch <- p
			}
		}(c)
	}
	return ch
}

var _ = errors.New
