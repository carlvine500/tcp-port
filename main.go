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

	"github.com/carlvine500/tcpshow/dubboport"
	"github.com/carlvine500/tcpshow/httpport"
	"github.com/carlvine500/tcpshow/mongoport"
	"github.com/carlvine500/tcpshow/mysqlport"
	"github.com/carlvine500/tcpshow/nacosport"
	"github.com/carlvine500/tcpshow/redisport"
	"github.com/carlvine500/tcpshow/rocketmqport"
	"github.com/carlvine500/tcpshow/tcpport"
	"github.com/carlvine500/tcpshow/websocketport"
	"github.com/carlvine500/tcpshow/zookeeperport"
)

var logger = vlog.CurrentPackageLogger()
var version = "0.2.0"

func init() { logger.SetAppenders(vlog.NewConsole2Appender()) }

// ---- Config ----

// GlobalConfig holds global CLI flags (before subcommand).
type GlobalConfig struct {
	Interface string
	IP        string
	Port      uint16
	OutputDir string
	Level     string
	PcapFile  string
	Cost      string // global cost filter
}

// ProtoConfig holds protocol-specific flags.
type ProtoConfig struct {
	Protocol string // dubbo, redis, mysql, mongo, rocketmq, http

	DubboService string
	DubboMethod  string
	RedisKey     string
	RedisCommand string
	RMQCode      int
	MySQLCommand string
	MySQLQuery   string
	MongoOpCode  int
	Cost         string

	// Compiled
	keyRe *regexp.Regexp
}

// ---- Types for handlers ----

type ConnectionKey struct {
	Src tcpport.Endpoint
	Dst tcpport.Endpoint
}

func (ck ConnectionKey) SrcString() string { return ck.Src.String() }
func (ck ConnectionKey) DstString() string { return ck.Dst.String() }

type TrafficHandler interface {
	Handle(conn *tcpport.TCPConnection)
}

type baseHandler struct {
	Key      ConnectionKey
	Global   *GlobalConfig
	Proto    *ProtoConfig
	Printer  *tcpport.MultiPrinter
	Buf      *bytes.Buffer
	reqTime  time.Time
	protocol string
}

func (h *baseHandler) initBuf() { h.Buf = new(bytes.Buffer) }

func (h *baseHandler) startReq() { h.reqTime = time.Now() }

func (h *baseHandler) writeReqLine(src, dst string) {
	ts := h.reqTime.Format("2006-01-02 15:04:05.000")
	fmt.Fprintf(h.Buf, "%s [%s -----> %s]\n", ts, src, dst)
}

func (h *baseHandler) writeRespLine(src, dst string) {
	ts := h.reqTime.Format("2006-01-02 15:04:05.000")
	fmt.Fprintf(h.Buf, "%s [%s <----- %s] (%dms)\n", ts, dst, src, time.Since(h.reqTime).Milliseconds())
}

func (h *baseHandler) hasContent() bool { return h.Buf.Len() > 0 }

func (h *baseHandler) send() { h.Printer.Send(h.protocol, h.Buf.String()) }

func (h *baseHandler) writeLine(a ...interface{}) { fmt.Fprintln(h.Buf, a...) }

func (h *baseHandler) elapsed() time.Duration { return time.Since(h.reqTime) }

func (h *baseHandler) elapsedMs() int64 { return h.elapsed().Milliseconds() }

// checkCost returns true if the response should be shown based on cost filter.
func (h *baseHandler) checkCost() bool {
	if h.Proto.Cost == "" {
		return true
	}
	ms := h.elapsedMs()
	return matchCost(ms, h.Proto.Cost)
}

// matchCost parses cost filter expressions:
//
//	"100+"  → >= 100ms
//	"100-"  → <= 100ms
//	"50-200" → 50ms <= t <= 200ms
func matchCost(ms int64, filter string) bool {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return true
	}
	// "100+" or "+100"
	if strings.HasSuffix(filter, "+") {
		threshold, err := strconv.ParseInt(strings.TrimSuffix(filter, "+"), 10, 64)
		if err == nil {
			return ms >= threshold
		}
	}
	if strings.HasPrefix(filter, "+") {
		threshold, err := strconv.ParseInt(strings.TrimPrefix(filter, "+"), 10, 64)
		if err == nil {
			return ms >= threshold
		}
	}
	// "100-" or "-100"
	if strings.HasSuffix(filter, "-") {
		threshold, err := strconv.ParseInt(strings.TrimSuffix(filter, "-"), 10, 64)
		if err == nil {
			return ms <= threshold
		}
	}
	if strings.HasPrefix(filter, "-") && !strings.Contains(filter[1:], "-") {
		threshold, err := strconv.ParseInt(filter[1:], 10, 64)
		if err == nil {
			return ms <= threshold
		}
	}
	// "50-200"
	if strings.Contains(filter, "-") {
		parts := strings.SplitN(filter, "-", 2)
		minVal, err1 := strconv.ParseInt(parts[0], 10, 64)
		maxVal, err2 := strconv.ParseInt(parts[1], 10, 64)
		if err1 == nil && err2 == nil {
			return ms >= minVal && ms <= maxVal
		}
	}
	// Exact match
	threshold, err := strconv.ParseInt(filter, 10, 64)
	if err == nil {
		return ms == threshold
	}
	return true
}

// ---- Dubbo Handler ----

type dubboHandler struct {
	baseHandler
	seen map[uint64]bool
}

func (h *dubboHandler) Handle(conn *tcpport.TCPConnection) {
	defer conn.UpStream.Close()
	defer conn.DownStream.Close()
	h.protocol = "dubbo"

	reqR := bufio.NewReader(conn.UpStream)
	defer tcpport.DiscardAll(reqR)
	respR := bufio.NewReader(conn.DownStream)
	defer tcpport.DiscardAll(respR)

	peek, _ := reqR.Peek(24)
	if dubboport.DetectDubbo(peek) {
		h.handleDubbo(reqR, respR)
	} else if dubboport.DetectTriple(peek) {
		h.handleTriple(reqR, respR)
	}
}

func (h *dubboHandler) handleDubbo(reqR, respR *bufio.Reader) {
	filterService := func(s string) bool {
		return h.Proto.DubboService != "" && !tcpport.WildcardMatch(s, h.Proto.DubboService)
	}
	filterMethod := func(s string) bool {
		return h.Proto.DubboMethod != "" && !tcpport.WildcardMatch(s, h.Proto.DubboMethod)
	}

	for {
		h.initBuf()
		h.startReq()
		req, err := dubboport.ReadDubboMessage(reqR)
		if err != nil {
			break
		}
		dedupKey := uint64(h.Key.Dst.Port)<<48 | uint64(req.Header.RequestID)
		if h.seen[dedupKey] {
			continue
		}
		h.seen[dedupKey] = true
		if filterService(req.ServiceName) || filterMethod(req.MethodName) {
			continue
		}
		h.writeReqLine(h.Key.SrcString(), h.Key.DstString())
		if h.Global.Level == "url" {
			h.writeLine(dubboport.FormatDubboURL(req))
		} else {
			h.writeLine(dubboport.FormatDubbo(req))
		}
		if !req.Header.IsTwoway || req.Header.IsEvent {
			h.send()
			continue
		}
		resp, err := dubboport.ReadDubboMessage(respR)
		if err != nil {
			break
		}
		if !h.checkCost() {
			h.send() // flush empty to reset buf
			continue
		}
		if h.Global.Level != "url" {
			h.writeRespLine(h.Key.DstString(), h.Key.SrcString())
			h.writeLine(dubboport.FormatDubbo(resp))
		}
		h.send()
	}
	if h.hasContent() {
		h.send()
	}
}

func (h *dubboHandler) handleTriple(reqR, respR *bufio.Reader) {
	filterService := func(s string) bool {
		return h.Proto.DubboService != "" && !tcpport.WildcardMatch(s, h.Proto.DubboService)
	}
	filterMethod := func(s string) bool {
		return h.Proto.DubboMethod != "" && !tcpport.WildcardMatch(s, h.Proto.DubboMethod)
	}

	h.initBuf()
	h.startReq()
	msgs, _, _ := dubboport.ReadTripleMessages(reqR)
	for _, msg := range msgs {
		if filterService(msg.ServiceName) || filterMethod(msg.MethodName) {
			continue
		}
		h.writeReqLine(h.Key.SrcString(), h.Key.DstString())
		if h.Global.Level == "url" {
			h.writeLine(dubboport.FormatTripleURL(&msg))
		} else {
			h.writeLine(dubboport.FormatTriple(&msg))
		}
	}
	if h.hasContent() {
		h.send()
	}
}

// ---- Redis Handler ----

type redisHandler struct {
	baseHandler
}

func (h *redisHandler) Handle(conn *tcpport.TCPConnection) {
	defer conn.UpStream.Close()
	defer conn.DownStream.Close()
	h.protocol = "redis"
	reqR := bufio.NewReader(conn.UpStream)
	defer tcpport.DiscardAll(reqR)
	respR := bufio.NewReader(conn.DownStream)
	defer tcpport.DiscardAll(respR)

	if h.Proto.RedisKey != "" {
		h.Proto.keyRe = regexp.MustCompile(h.Proto.RedisKey)
	}

	for {
		h.initBuf()
		h.startReq()
		cmd, err := redisport.ReadRESPCommand(reqR)
		if err != nil {
			break
		}
		if h.Proto.RedisCommand != "" && !tcpport.WildcardMatch(strings.ToUpper(cmd.Command), strings.ToUpper(h.Proto.RedisCommand)) {
			redisport.ReadRESPResponse(respR)
			continue
		}
		if h.Proto.keyRe != nil {
			key := ""
			if len(cmd.Args) > 1 {
				key = cmd.Args[1]
			}
			if !h.Proto.keyRe.MatchString(key) {
				redisport.ReadRESPResponse(respR)
				continue
			}
		}
		h.writeReqLine(h.Key.SrcString(), h.Key.DstString())
		if h.Global.Level == "url" {
			h.writeLine(redisport.FormatRESPURL(cmd))
		} else {
			h.writeLine(redisport.FormatRESPCommand(cmd))
		}
		resp, err := redisport.ReadRESPResponse(respR)
		if err != nil {
			h.send()
			break
		}
		if !h.checkCost() {
			continue
		}
		if h.Global.Level != "url" {
			h.writeRespLine(h.Key.DstString(), h.Key.SrcString())
			h.writeLine(redisport.FormatRESPResponse(resp))
		}
		h.send()
	}
	if h.hasContent() {
		h.send()
	}
}

// ---- RocketMQ Handler ----

type rocketmqHandler struct{ baseHandler }

func (h *rocketmqHandler) Handle(conn *tcpport.TCPConnection) {
	defer conn.UpStream.Close()
	defer conn.DownStream.Close()
	h.protocol = "rocketmq"
	reqR := bufio.NewReader(conn.UpStream)
	defer tcpport.DiscardAll(reqR)
	respR := bufio.NewReader(conn.DownStream)
	defer tcpport.DiscardAll(respR)

	for {
		h.initBuf()
		h.startReq()
		req, err := rocketmqport.ReadRemotingCommand(reqR)
		if err != nil {
			break
		}
		if h.Proto.RMQCode != 0 && req.Code != h.Proto.RMQCode {
			continue
		}
		h.writeReqLine(h.Key.SrcString(), h.Key.DstString())
		if h.Global.Level == "url" {
			h.writeLine(rocketmqport.FormatRemotingURL(req))
		} else {
			h.writeLine(rocketmqport.FormatRemotingCommand(req))
		}
		resp, err := rocketmqport.ReadRemotingCommand(respR)
		if err != nil {
			h.send()
			break
		}
		if !h.checkCost() {
			continue
		}
		if h.Global.Level != "url" {
			h.writeRespLine(h.Key.DstString(), h.Key.SrcString())
			h.writeLine(rocketmqport.FormatRemotingResponse(resp))
		}
		h.send()
	}
	if h.hasContent() {
		h.send()
	}
}

// ---- MySQL Handler ----

type mysqlHandler struct{ baseHandler }

func (h *mysqlHandler) Handle(conn *tcpport.TCPConnection) {
	defer conn.UpStream.Close()
	defer conn.DownStream.Close()
	h.protocol = "mysql"
	clientR := bufio.NewReader(conn.UpStream)
	defer tcpport.DiscardAll(clientR)
	serverR := bufio.NewReader(conn.DownStream)
	defer tcpport.DiscardAll(serverR)

	// Handshake
	h.initBuf()
	h.startReq()
	if msg, err := mysqlport.ReadMySQLMessage(serverR, "S->C"); err == nil {
		if h.Global.Level == "url" {
			h.writeRespLine(h.Key.DstString(), h.Key.SrcString())
			h.writeLine(mysqlport.FormatMySQLURL(msg))
		} else if msg.Type == "handshake" {
			h.writeRespLine(h.Key.DstString(), h.Key.SrcString())
			h.writeLine(mysqlport.FormatMySQLMessage(msg))
		}
		h.send()
	}

	for {
		h.initBuf()
		h.startReq()
		cmd, err := mysqlport.ReadMySQLMessage(clientR, "C->S")
		if err != nil {
			break
		}
		if h.Proto.MySQLCommand != "" && !tcpport.WildcardMatch(strings.ToUpper(cmd.CommandName), strings.ToUpper(h.Proto.MySQLCommand)) {
			continue
		}
		if h.Proto.MySQLQuery != "" && !strings.Contains(cmd.Query, h.Proto.MySQLQuery) {
			continue
		}
		h.writeReqLine(h.Key.SrcString(), h.Key.DstString())
		if h.Global.Level == "url" {
			h.writeLine(mysqlport.FormatMySQLURL(cmd))
		} else {
			h.writeLine(mysqlport.FormatMySQLMessage(cmd))
		}
		for i := 0; i < 10; i++ {
			resp, err := mysqlport.ReadMySQLMessage(serverR, "S->C")
			if err != nil {
				break
			}
			if h.Global.Level != "url" && h.checkCost() {
				h.writeRespLine(h.Key.DstString(), h.Key.SrcString())
				h.writeLine(mysqlport.FormatMySQLMessage(resp))
			}
			if resp.Type == "ok" || resp.Type == "eof" || resp.Type == "error" {
				break
			}
		}
		h.send()
	}
	if h.hasContent() {
		h.send()
	}
}

// ---- MongoDB Handler ----

type mongoHandler struct{ baseHandler }

func (h *mongoHandler) Handle(conn *tcpport.TCPConnection) {
	defer conn.UpStream.Close()
	defer conn.DownStream.Close()
	h.protocol = "mongo"
	reqR := bufio.NewReader(conn.UpStream)
	defer tcpport.DiscardAll(reqR)
	respR := bufio.NewReader(conn.DownStream)
	defer tcpport.DiscardAll(respR)

	for {
		h.initBuf()
		h.startReq()
		req, err := mongoport.ReadMongoMessage(reqR, "C->S")
		if err != nil {
			break
		}
		if h.Proto.MongoOpCode != 0 && req.Header.OpCode != int32(h.Proto.MongoOpCode) {
			continue
		}
		h.writeReqLine(h.Key.SrcString(), h.Key.DstString())
		if h.Global.Level == "url" {
			h.writeLine(mongoport.FormatMongoURL(req))
		} else {
			h.writeLine(mongoport.FormatMongoMessage(req))
		}
		for i := 0; i < 5; i++ {
			resp, err := mongoport.ReadMongoMessage(respR, "S->C")
			if err != nil {
				break
			}
			if h.Global.Level != "url" {
				h.writeRespLine(h.Key.DstString(), h.Key.SrcString())
				h.writeLine(mongoport.FormatMongoResponse(resp))
			}
		}
		h.send()
	}
	if h.hasContent() {
		h.send()
	}
}

// ---- HTTP Handler ----

type httpHandler struct{ baseHandler }

func (h *httpHandler) Handle(conn *tcpport.TCPConnection) {
	defer conn.UpStream.Close()
	defer conn.DownStream.Close()
	h.protocol = "http"
	reqR := bufio.NewReader(conn.UpStream)
	defer tcpport.DiscardAll(reqR)
	respR := bufio.NewReader(conn.DownStream)
	defer tcpport.DiscardAll(respR)

	for {
		h.initBuf()
		h.startReq()
		req, err := httpport.ReadHTTPMessage(reqR)
		if err != nil {
			break
		}
		h.writeReqLine(h.Key.SrcString(), h.Key.DstString())
		if h.Global.Level == "url" {
			h.writeLine(httpport.FormatHTTPURL(req))
		} else {
			h.writeLine(httpport.FormatHTTP(req))
		}
		resp, err := httpport.ReadHTTPMessage(respR)
		if err != nil {
			h.send()
			break
		}
		if h.checkCost() && h.Global.Level != "url" {
			h.writeRespLine(h.Key.DstString(), h.Key.SrcString())
			h.writeLine(httpport.FormatHTTP(resp))
		}
		h.send()
	}
	if h.hasContent() {
		h.send()
	}
}

// ---- WebSocket Handler ----

type websocketHandler struct{ baseHandler }

func (h *websocketHandler) Handle(conn *tcpport.TCPConnection) {
	defer conn.UpStream.Close()
	defer conn.DownStream.Close()
	h.protocol = "websocket"
	reqR := bufio.NewReader(conn.UpStream)
	defer tcpport.DiscardAll(reqR)
	respR := bufio.NewReader(conn.DownStream)
	defer tcpport.DiscardAll(respR)

	for {
		h.initBuf()
		h.startReq()
		msg, err := websocketport.ReadWebSocketMessage(reqR, "C->S")
		if err != nil {
			break
		}
		h.writeReqLine(h.Key.SrcString(), h.Key.DstString())
		if h.Global.Level == "url" {
			h.writeLine(websocketport.FormatWebSocketURL(msg))
		} else {
			h.writeLine(websocketport.FormatWebSocketMessage(msg))
		}
		h.send()
	}
	if h.hasContent() {
		h.send()
	}
}

// ---- ZooKeeper Handler ----

type zookeeperHandler struct{ baseHandler }

func (h *zookeeperHandler) Handle(conn *tcpport.TCPConnection) {
	defer conn.UpStream.Close()
	defer conn.DownStream.Close()
	h.protocol = "zookeeper"
	reqR := bufio.NewReader(conn.UpStream)
	defer tcpport.DiscardAll(reqR)
	respR := bufio.NewReader(conn.DownStream)
	defer tcpport.DiscardAll(respR)

	for {
		h.initBuf()
		h.startReq()
		msg, err := zookeeperport.ReadZKMessage(reqR, "C->S")
		if err != nil {
			break
		}
		req, ok := msg.(*zookeeperport.ZKRequest)
		if !ok {
			continue
		}
		h.writeReqLine(h.Key.SrcString(), h.Key.DstString())
		if h.Global.Level == "url" {
			h.writeLine(zookeeperport.FormatZKURL(req))
		} else {
			h.writeLine(zookeeperport.FormatZKRequest(req))
		}
		resp, err := zookeeperport.ReadZKMessage(respR, "S->C")
		if err != nil {
			h.send()
			break
		}
		if !h.checkCost() {
			continue
		}
		h.writeRespLine(h.Key.DstString(), h.Key.SrcString())
		if respMsg, ok := resp.(*zookeeperport.ZKResponse); ok {
			h.writeLine(zookeeperport.FormatZKResponse(respMsg))
		}
		h.send()
	}
	if h.hasContent() {
		h.send()
	}
}

// ---- Nacos Handler ----

type nacosHandler struct{ baseHandler }

func (h *nacosHandler) Handle(conn *tcpport.TCPConnection) {
	defer conn.UpStream.Close()
	defer conn.DownStream.Close()
	h.protocol = "nacos"
	reqR := bufio.NewReader(conn.UpStream)
	defer tcpport.DiscardAll(reqR)
	respR := bufio.NewReader(conn.DownStream)
	defer tcpport.DiscardAll(respR)

	for {
		h.initBuf()
		h.startReq()
		msg, err := nacosport.ReadNacosMessage(reqR, "C->S")
		if err != nil {
			break
		}
		h.writeReqLine(h.Key.SrcString(), h.Key.DstString())
		if h.Global.Level == "url" {
			h.writeLine(nacosport.FormatNacosURL(msg))
		} else {
			h.writeLine(nacosport.FormatNacosMessage(msg))
		}
		resp, err := nacosport.ReadNacosMessage(respR, "S->C")
		if err != nil {
			h.send()
			break
		}
		if !h.checkCost() {
			continue
		}
		if h.Global.Level != "url" {
			h.writeRespLine(h.Key.DstString(), h.Key.SrcString())
			h.writeLine(nacosport.FormatNacosMessage(resp))
		}
		h.send()
	}
	if h.hasContent() {
		h.send()
	}
}

// ---- Auto-detect handler ----

type autoHandler struct {
	baseHandler
	detected   string
	subHandler TrafficHandler
	conn       *tcpport.TCPConnection
	setup      sync.Once
	peekResult []byte
	peekErr    error
}

func (h *autoHandler) Handle(conn *tcpport.TCPConnection) {
	h.conn = conn
	buf := make([]byte, 24)
	n, err := conn.UpStream.Read(buf)
	h.peekResult = buf[:max(n, 0)]
	h.peekErr = err
	if n > 0 {
		conn.UpStream.Prepend(h.peekResult)
	}
	h.run()
}

func (h *autoHandler) run() {
	detectors := []struct {
		name string
		fn   tcpport.ProtocolDetector
		make func() TrafficHandler
	}{
		{"dubbo", dubboport.DetectDubbo, func() TrafficHandler { return &dubboHandler{baseHandler: h.baseHandler, seen: make(map[uint64]bool)} }},
		{"triple", dubboport.DetectTriple, func() TrafficHandler { return &dubboHandler{baseHandler: h.baseHandler, seen: make(map[uint64]bool)} }},
		{"rocketmq", rocketmqport.DetectRocketMQ, func() TrafficHandler { return &rocketmqHandler{baseHandler: h.baseHandler} }},
		{"mongo", mongoport.DetectMongo, func() TrafficHandler { return &mongoHandler{baseHandler: h.baseHandler} }},
		{"mysql", mysqlport.DetectMySQL, func() TrafficHandler { return &mysqlHandler{baseHandler: h.baseHandler} }},
		{"redis", redisport.DetectRESP, func() TrafficHandler { return &redisHandler{baseHandler: h.baseHandler} }},
		{"zookeeper", zookeeperport.DetectZK, func() TrafficHandler { return &zookeeperHandler{baseHandler: h.baseHandler} }},
		{"websocket", websocketport.DetectWebSocket, func() TrafficHandler { return &websocketHandler{baseHandler: h.baseHandler} }},
		{"nacos", nacosport.DetectNacos, func() TrafficHandler { return &nacosHandler{baseHandler: h.baseHandler} }},
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
	global  *GlobalConfig
	proto   *ProtoConfig
	printer *tcpport.MultiPrinter
	makeH   func(ck ConnectionKey) TrafficHandler
}

func (a *connHandlerAdapter) Handle(src, dst tcpport.Endpoint, conn *tcpport.TCPConnection) {
	ck := ConnectionKey{Src: src, Dst: dst}
	handler := a.makeH(ck)
	handler.Handle(conn)
}

func (a *connHandlerAdapter) Finish() {}

// ---- Subcommand definitions ----

type subcommand struct {
	Name        string
	Description string
	Aliases     []string
	Setup       func(fs *flag.FlagSet, proto *ProtoConfig)
	Examples    []string
}

var subcommands = []subcommand{
	{
		Name: "dubbo", Description: "Capture Dubbo/Triple RPC traffic",
		Aliases: []string{"d"},
		Setup: func(fs *flag.FlagSet, p *ProtoConfig) {
			fs.StringVar(&p.DubboService, "s", "", "Filter by service name (wildcard)")
			fs.StringVar(&p.DubboService, "service", "", "Filter by service name (wildcard)")
			fs.StringVar(&p.DubboMethod, "m", "", "Filter by method name (wildcard)")
			fs.StringVar(&p.DubboMethod, "method", "", "Filter by method name (wildcard)")
			fs.StringVar(&p.Cost, "C", "", "Cost filter: 100+, 50-200, -50")
			fs.StringVar(&p.Cost, "cost", "", "Cost filter: 100+, 50-200, -50")
		},
		Examples: []string{
			"  tcpshow dubbo",
			"  tcpshow dubbo -s com.example.* -m getUser",
			"  tcpshow dubbo -C 100+",
		},
	},
	{
		Name: "redis", Description: "Capture Redis RESP traffic",
		Aliases: []string{"r"},
		Setup: func(fs *flag.FlagSet, p *ProtoConfig) {
			fs.StringVar(&p.RedisKey, "k", "", "Filter by key (regex)")
			fs.StringVar(&p.RedisKey, "key", "", "Filter by key (regex)")
			fs.StringVar(&p.RedisCommand, "c", "", "Filter by command: SET, GET, ...")
			fs.StringVar(&p.RedisCommand, "cmd", "", "Filter by command: SET, GET, ...")
			fs.StringVar(&p.Cost, "C", "", "Cost filter: 100+, 50-200, -50")
			fs.StringVar(&p.Cost, "cost", "", "Cost filter: 100+, 50-200, -50")
		},
		Examples: []string{
			"  tcpshow redis",
			"  tcpshow redis -k 'user:session:*'",
			"  tcpshow redis -c GET -C 50+",
		},
	},
	{
		Name: "mysql", Description: "Capture MySQL traffic",
		Aliases: []string{"m"},
		Setup: func(fs *flag.FlagSet, p *ProtoConfig) {
			fs.StringVar(&p.MySQLCommand, "c", "", "Filter by command: Query, Ping, ...")
			fs.StringVar(&p.MySQLCommand, "cmd", "", "Filter by command: Query, Ping, ...")
			fs.StringVar(&p.MySQLQuery, "q", "", "Filter by SQL substring")
			fs.StringVar(&p.MySQLQuery, "query", "", "Filter by SQL substring")
			fs.StringVar(&p.Cost, "C", "", "Cost filter: 100+, 50-200, -50")
			fs.StringVar(&p.Cost, "cost", "", "Cost filter: 100+, 50-200, -50")
		},
		Examples: []string{
			"  tcpshow mysql",
			"  tcpshow mysql -q tableName -C 100+",
			"  tcpshow mysql -q 'SELECT.*FROM users'",
		},
	},
	{
		Name: "mongo", Description: "Capture MongoDB wire protocol traffic",
		Setup: func(fs *flag.FlagSet, p *ProtoConfig) {
			fs.IntVar(&p.MongoOpCode, "opcode", 0, "Filter by opcode (2013=OP_MSG, 2004=OP_QUERY)")
			fs.StringVar(&p.Cost, "C", "", "Cost filter: 100+, 50-200, -50")
			fs.StringVar(&p.Cost, "cost", "", "Cost filter: 100+, 50-200, -50")
		},
		Examples: []string{
			"  tcpshow mongo",
			"  tcpshow mongo -C 200+",
		},
	},
	{
		Name: "rocketmq", Description: "Capture RocketMQ Remoting traffic",
		Aliases: []string{"rmq"},
		Setup: func(fs *flag.FlagSet, p *ProtoConfig) {
			fs.IntVar(&p.RMQCode, "code", 0, "Filter by request code")
			fs.StringVar(&p.Cost, "C", "", "Cost filter: 100+, 50-200, -50")
			fs.StringVar(&p.Cost, "cost", "", "Cost filter: 100+, 50-200, -50")
		},
		Examples: []string{
			"  tcpshow rocketmq",
			"  tcpshow rocketmq --code 10 -C 50+",
		},
	},
	{
		Name: "http", Description: "Capture HTTP/1.x traffic",
		Setup: func(fs *flag.FlagSet, p *ProtoConfig) {
			fs.StringVar(&p.Cost, "C", "", "Cost filter: 100+, 50-200, -50")
			fs.StringVar(&p.Cost, "cost", "", "Cost filter: 100+, 50-200, -50")
		},
		Examples: []string{
			"  tcpshow http",
			"  tcpshow http -C 500+",
		},
	},
	{
		Name: "websocket", Description: "Capture WebSocket traffic",
		Aliases: []string{"ws"},
		Setup: func(fs *flag.FlagSet, p *ProtoConfig) {
			fs.StringVar(&p.Cost, "C", "", "Cost filter: 100+, 50-200, -50")
			fs.StringVar(&p.Cost, "cost", "", "Cost filter: 100+, 50-200, -50")
		},
		Examples: []string{
			"  tcpshow websocket",
			"  tcpshow ws -C 100+",
		},
	},
	{
		Name: "zookeeper", Description: "Capture ZooKeeper traffic",
		Aliases: []string{"zk"},
		Setup: func(fs *flag.FlagSet, p *ProtoConfig) {
			fs.StringVar(&p.Cost, "C", "", "Cost filter: 100+, 50-200, -50")
			fs.StringVar(&p.Cost, "cost", "", "Cost filter: 100+, 50-200, -50")
		},
		Examples: []string{
			"  tcpshow zookeeper",
			"  tcpshow zk -C 50+",
		},
	},
	{
		Name: "nacos", Description: "Capture Nacos HTTP API traffic",
		Setup: func(fs *flag.FlagSet, p *ProtoConfig) {
			fs.StringVar(&p.Cost, "C", "", "Cost filter: 100+, 50-200, -50")
			fs.StringVar(&p.Cost, "cost", "", "Cost filter: 100+, 50-200, -50")
		},
		Examples: []string{
			"  tcpshow nacos",
			"  tcpshow nacos -C 200+",
		},
	},
}

// ---- CLI Framework ----

func findSubcommand(args []string) (subIndex int) {
	for i, a := range args {
		if !strings.HasPrefix(a, "-") {
			return i
		}
		if a == "-h" || a == "--help" {
			return -1 // help flag, no subcommand search
		}
	}
	return len(args) // no subcommand
}

func subcommandByName(name string) *subcommand {
	for i := range subcommands {
		if subcommands[i].Name == name {
			return &subcommands[i]
		}
		for _, alias := range subcommands[i].Aliases {
			if alias == name {
				return &subcommands[i]
			}
		}
	}
	return nil
}

func printGlobalHelp() {
	fmt.Printf(`tcpshow - TCP traffic sniffer for Dubbo, Redis, MySQL, MongoDB, RocketMQ, HTTP, WebSocket, ZooKeeper, Nacos

USAGE:
  tcpshow [global-flags] [protocol] [protocol-flags]
  tcpshow -h

GLOBAL FLAGS:
  -i <iface>      Network interface (default: any)
  -r <file>       Read from pcap file
  --ip <ip>       Filter by IP address
  --port <port>   Filter by port
  -o <dir>        Output per-protocol files to directory
  -l <level>      Output level: url (compact) | all (default)
  -h, --help      Show this help
  -v, --version   Print version

PROTOCOLS:
`)
	for _, sc := range subcommands {
		aliases := ""
		if len(sc.Aliases) > 0 {
			aliases = " (alias: " + strings.Join(sc.Aliases, ", ") + ")"
		}
		fmt.Printf("  %-10s %s%s\n", sc.Name, sc.Description, aliases)
	}
	fmt.Println()
	fmt.Println("Run 'tcpshow <protocol> -h' for protocol-specific flags.")
	fmt.Println()
	fmt.Println("EXAMPLES:")
	fmt.Println("  tcpshow                         # auto-detect all protocols")
	fmt.Println("  tcpshow -i eth0 redis -k 'user:*'")
	fmt.Println("  tcpshow mysql -q tableName -C 100+")
	fmt.Println("  tcpshow -r capture.pcap dubbo -s 'com.example.*'")
}

func printAllHelp() {
	printGlobalHelp()
	fmt.Println("---")
	fmt.Println()
	for _, sc := range subcommands {
		fmt.Printf("PROTOCOL: %s — %s\n", sc.Name, sc.Description)
		fs := flag.NewFlagSet(sc.Name, flag.ExitOnError)
		p := &ProtoConfig{}
		sc.Setup(fs, p)
		fs.SetOutput(os.Stdout)
		fs.PrintDefaults()
		if len(sc.Examples) > 0 {
			fmt.Println("\nExamples:")
			for _, ex := range sc.Examples {
				fmt.Println(ex)
			}
		}
		fmt.Println()
	}
}

func printProtoHelp(sc *subcommand) {
	fmt.Printf("tcpshow %s — %s\n\n", sc.Name, sc.Description)
	fmt.Println("USAGE: tcpshow [global-flags] " + sc.Name + " [flags]")
	fmt.Println()
	fmt.Println("FLAGS:")
	fs := flag.NewFlagSet(sc.Name, flag.ExitOnError)
	p := &ProtoConfig{}
	sc.Setup(fs, p)
	fs.SetOutput(os.Stdout)
	fs.PrintDefaults()
	if len(sc.Examples) > 0 {
		fmt.Println("\nEXAMPLES:")
		for _, ex := range sc.Examples {
			fmt.Println(ex)
		}
	}
}

// ---- Version ----

func printVersion() {
	fmt.Printf("tcpshow v%s\n", version)
}

// ---- Main ----

func main() {
	args := os.Args[1:]

	// Handle help/version before anything else
	for _, a := range args {
		if a == "-v" || a == "--version" {
			printVersion()
			return
		}
	}

	// Find subcommand position
	subIdx := findSubcommand(args)

	// Handle help
	for _, a := range args {
		if (a == "-h" || a == "--help") && subIdx == -1 {
			printGlobalHelp()
			return
		}
	}

	// Check for --all flag
	showAll := false
	for _, a := range args {
		if a == "--all" {
			showAll = true
			break
		}
	}
	if showAll {
		printAllHelp()
		return
	}

	// Parse global flags
	global := &GlobalConfig{Level: "all"}
	globalFS := flag.NewFlagSet("tcpshow", flag.ExitOnError)
	globalFS.StringVar(&global.Interface, "i", "any", "Network interface")
	globalFS.StringVar(&global.IP, "ip", "", "Filter by IP")
	var port uint
	globalFS.UintVar(&port, "port", 0, "Filter by port")
	globalFS.StringVar(&global.OutputDir, "o", "", "Output per-protocol files to directory")
	globalFS.StringVar(&global.Level, "l", "all", "Output level: url|all")
	globalFS.StringVar(&global.PcapFile, "r", "", "Read from pcap file")
	globalFS.Bool("h", false, "Show help")

	globalArgs := args
	if subIdx < len(args) {
		globalArgs = args[:subIdx]
	}
	globalFS.Parse(globalArgs)
	global.Port = uint16(port)

	// Determine protocol
	proto := &ProtoConfig{}
	var sc *subcommand

	if subIdx < len(args) {
		protoName := args[subIdx]
		sc = subcommandByName(protoName)
		if sc == nil {
			fmt.Fprintf(os.Stderr, "Unknown protocol: %s\n", protoName)
			fmt.Fprintf(os.Stderr, "Supported: ")
			names := []string{}
			for _, s := range subcommands {
				names = append(names, s.Name)
			}
			fmt.Fprintln(os.Stderr, strings.Join(names, ", "))
			os.Exit(1)
		}
		proto.Protocol = sc.Name

		// Parse protocol flags
		protoFS := flag.NewFlagSet(sc.Name, flag.ExitOnError)
		sc.Setup(protoFS, proto)

		protoArgs := args[subIdx+1:]
		// Check for -h within proto args
		for _, a := range protoArgs {
			if a == "-h" || a == "--help" {
				printProtoHelp(sc)
				return
			}
		}
		protoFS.Parse(protoArgs)
	} else {
		proto.Protocol = "auto"
	}

	// Build handler factory
	printer := tcpport.NewMultiPrinter(global.OutputDir)

	var makeHandler func(ck ConnectionKey) TrafficHandler

	if proto.Protocol == "auto" {
		// Auto-detect
		detectOrder := []tcpport.ProtocolDetector{
			dubboport.DetectDubbo,
			dubboport.DetectTriple,
			rocketmqport.DetectRocketMQ,
			mongoport.DetectMongo,
			mysqlport.DetectMySQL,
			redisport.DetectRESP,
			httpport.DetectHTTP,
		}
		_ = detectOrder
		makeHandler = func(ck ConnectionKey) TrafficHandler {
			return &autoHandler{baseHandler: baseHandler{Key: ck, Global: global, Proto: proto, Printer: printer}}
		}
	} else {
		switch proto.Protocol {
		case "dubbo":
			makeHandler = func(ck ConnectionKey) TrafficHandler {
				return &dubboHandler{baseHandler: baseHandler{Key: ck, Global: global, Proto: proto, Printer: printer}, seen: make(map[uint64]bool)}
			}
		case "redis":
			makeHandler = func(ck ConnectionKey) TrafficHandler {
				return &redisHandler{baseHandler: baseHandler{Key: ck, Global: global, Proto: proto, Printer: printer}}
			}
		case "rocketmq":
			makeHandler = func(ck ConnectionKey) TrafficHandler {
				return &rocketmqHandler{baseHandler: baseHandler{Key: ck, Global: global, Proto: proto, Printer: printer}}
			}
		case "mysql":
			makeHandler = func(ck ConnectionKey) TrafficHandler {
				return &mysqlHandler{baseHandler: baseHandler{Key: ck, Global: global, Proto: proto, Printer: printer}}
			}
		case "mongo":
			makeHandler = func(ck ConnectionKey) TrafficHandler {
				return &mongoHandler{baseHandler: baseHandler{Key: ck, Global: global, Proto: proto, Printer: printer}}
			}
		case "http":
			makeHandler = func(ck ConnectionKey) TrafficHandler {
				return &httpHandler{baseHandler: baseHandler{Key: ck, Global: global, Proto: proto, Printer: printer}}
			}
		case "websocket":
			makeHandler = func(ck ConnectionKey) TrafficHandler {
				return &websocketHandler{baseHandler: baseHandler{Key: ck, Global: global, Proto: proto, Printer: printer}}
			}
		case "zookeeper":
			makeHandler = func(ck ConnectionKey) TrafficHandler {
				return &zookeeperHandler{baseHandler: baseHandler{Key: ck, Global: global, Proto: proto, Printer: printer}}
			}
		case "nacos":
			makeHandler = func(ck ConnectionKey) TrafficHandler {
				return &nacosHandler{baseHandler: baseHandler{Key: ck, Global: global, Proto: proto, Printer: printer}}
			}
		}
	}

	// Build detector for auto mode
	var detector tcpport.ProtocolDetector
	if proto.Protocol == "auto" {
		detectOrder := []tcpport.ProtocolDetector{
			dubboport.DetectDubbo, dubboport.DetectTriple,
			rocketmqport.DetectRocketMQ, mongoport.DetectMongo,
			mysqlport.DetectMySQL, redisport.DetectRESP,
			zookeeperport.DetectZK, websocketport.DetectWebSocket,
			nacosport.DetectNacos, httpport.DetectHTTP,
		}
		detector = func(data []byte) bool {
			for _, d := range detectOrder {
				if d(data) {
					return true
				}
			}
			return false
		}
	} else {
		detector = func(data []byte) bool { return true }
	}

	adapter := &connHandlerAdapter{global: global, proto: proto, printer: printer, makeH: makeHandler}
	assembler := tcpport.NewTCPAssembler(adapter, detector)
	assembler.FilterIP = global.IP
	assembler.FilterPort = global.Port

	packets := openPackets(global)
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

// ---- Packet capture ----

func openPackets(global *GlobalConfig) chan gopacket.Packet {
	if global.PcapFile != "" {
		handle, err := pcap.OpenOffline(global.PcapFile)
		if err != nil {
			logger.Error("Open file", global.PcapFile, "error:", err)
			return nil
		}
		return gopacket.NewPacketSource(handle, handle.LinkType()).Packets()
	}

	if global.Interface == "any" && runtime.GOOS != "linux" {
		interfaces, err := pcap.FindAllDevs()
		if err != nil {
			logger.Error("find device error:", err)
			return nil
		}
		var chs []chan gopacket.Packet
		for _, itf := range interfaces {
			ch := openDevice(itf.Name, global.IP, global.Port)
			if ch != nil {
				chs = append(chs, ch)
			}
		}
		return mergeChannels(chs)
	}

	return openDevice(global.Interface, global.IP, global.Port)
}

func openDevice(device, ip string, port uint16) chan gopacket.Packet {
	defer func() { _ = recover() }()
	handle, err := pcap.OpenLive(device, 65536, true, pcap.BlockForever)
	if err != nil {
		logger.Warn("open device", device, "error:", err)
		return nil
	}
	bpf := "tcp"
	if port != 0 {
		bpf += " and port " + strconv.Itoa(int(port))
	}
	if ip != "" {
		bpf += " and host " + ip
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
