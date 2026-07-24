// Package tcpport provides shared TCP assembly, printing, and text utilities
// used by all protocol-parsers in tcp-port.
package tcpport

import (
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ---- TCP Assembler ----

const maxTCPSeq uint32 = 0xFFFFFFFF
const tcpSeqWindow = 0x0000FFFF

// ProtocolDetector is a function that detects if data belongs to a protocol.
type ProtocolDetector func([]byte) bool

// TCPAssembler does TCP packet assembly.
type TCPAssembler struct {
	connectionDict    map[string]*TCPConnection
	lock              sync.Mutex
	connectionHandler ConnectionHandler
	FilterIP          string
	FilterPort        uint16
	Detector          ProtocolDetector
}

func NewTCPAssembler(handler ConnectionHandler, detector ProtocolDetector) *TCPAssembler {
	return &TCPAssembler{
		connectionDict:    map[string]*TCPConnection{},
		connectionHandler: handler,
		Detector:          detector,
	}
}

func (a *TCPAssembler) Assemble(flow gopacket.Flow, tcp *layers.TCP, timestamp time.Time) {
	src := Endpoint{IP: flow.Src().String(), Port: uint16(tcp.SrcPort)}
	dst := Endpoint{IP: flow.Dst().String(), Port: uint16(tcp.DstPort)}

	if a.FilterIP != "" && src.IP != a.FilterIP && dst.IP != a.FilterIP {
		return
	}
	if a.FilterPort != 0 && src.Port != a.FilterPort && dst.Port != a.FilterPort {
		return
	}

	srcStr := src.String()
	dstStr := dst.String()
	var key string
	if srcStr < dstStr {
		key = srcStr + "-" + dstStr
	} else {
		key = dstStr + "-" + srcStr
	}

	createNewConn := tcp.SYN && !tcp.ACK || a.Detector != nil && a.Detector(tcp.Payload)
	conn := a.retrieveConnection(src, dst, key, createNewConn)
	if conn == nil {
		return
	}
	conn.onReceive(src, dst, tcp, timestamp)

	if conn.closed() {
		a.deleteConnection(key)
		conn.finish()
	}
}

func (a *TCPAssembler) retrieveConnection(src, dst Endpoint, key string, init bool) *TCPConnection {
	a.lock.Lock()
	defer a.lock.Unlock()
	conn := a.connectionDict[key]
	if conn == nil && init {
		conn = newTCPConnection(key)
		a.connectionDict[key] = conn
		a.connectionHandler.Handle(src, dst, conn)
	}
	return conn
}

func (a *TCPAssembler) deleteConnection(key string) {
	a.lock.Lock()
	defer a.lock.Unlock()
	delete(a.connectionDict, key)
}

func (a *TCPAssembler) FlushOlderThan(t time.Time) {
	var conns []*TCPConnection
	a.lock.Lock()
	for _, c := range a.connectionDict {
		if c.lastTimestamp.Before(t) {
			conns = append(conns, c)
		}
	}
	for _, c := range conns {
		delete(a.connectionDict, c.key)
	}
	a.lock.Unlock()
	for _, c := range conns {
		c.flushOlderThan()
	}
}

func (a *TCPAssembler) FinishAll() {
	a.lock.Lock()
	defer a.lock.Unlock()
	for _, c := range a.connectionDict {
		c.finish()
	}
	a.connectionDict = nil
	a.connectionHandler.Finish()
}

// ConnectionHandler is interface for handling TCP connections.
type ConnectionHandler interface {
	Handle(src Endpoint, dst Endpoint, conn *TCPConnection)
	Finish()
}

// Endpoint is one endpoint of a TCP connection.
type Endpoint struct {
	IP   string
	Port uint16
}

func (p Endpoint) Equals(p2 Endpoint) bool { return p.IP == p2.IP && p.Port == p2.Port }
func (p Endpoint) String() string           { return p.IP + ":" + strconv.Itoa(int(p.Port)) }

// TCPConnection holds info for one TCP connection.
type TCPConnection struct {
	UpStream      *netStream
	DownStream    *netStream
	ClientID      Endpoint
	lastTimestamp time.Time
	isRPC         bool
	key           string
}

func newTCPConnection(key string) *TCPConnection {
	return &TCPConnection{
		UpStream:   newNetStream(),
		DownStream: newNetStream(),
		key:        key,
	}
}

func (c *TCPConnection) onReceive(src, dst Endpoint, tcp *layers.TCP, timestamp time.Time) {
	c.lastTimestamp = timestamp
	if !c.isRPC {
		c.ClientID = src
		c.isRPC = true
	}
	var sendStream, confirmStream *netStream
	if c.ClientID.Equals(src) {
		sendStream = c.UpStream
		confirmStream = c.DownStream
	} else {
		sendStream = c.DownStream
		confirmStream = c.UpStream
	}
	sendStream.appendPacket(tcp)
	if tcp.ACK {
		confirmStream.confirmPacket(tcp.Ack)
	}
	if tcp.FIN || tcp.RST {
		sendStream.closed = true
	}
}

func (c *TCPConnection) flushOlderThan() {
	c.UpStream.closed = true
	c.DownStream.closed = true
	c.finish()
}

func (c *TCPConnection) closed() bool { return c.UpStream.closed && c.DownStream.closed }

func (c *TCPConnection) finish() {
	c.UpStream.finish()
	c.DownStream.finish()
}

// netStream treats one-direction TCP data as a stream.
type netStream struct {
	window *receiveWindow
	c      chan *layers.TCP
	remain []byte
	ignore bool
	closed bool
}

func newNetStream() *netStream {
	return &netStream{window: newReceiveWindow(64), c: make(chan *layers.TCP, 1024)}
}

func (s *netStream) appendPacket(tcp *layers.TCP) {
	if s.ignore { return }
	s.window.insert(tcp)
}
func (s *netStream) confirmPacket(ack uint32) {
	if s.ignore { return }
	s.window.confirm(ack, s.c)
}
func (s *netStream) finish() { close(s.c) }

func (s *netStream) Read(p []byte) (n int, err error) {
	for len(s.remain) == 0 {
		packet, ok := <-s.c
		if !ok { return 0, io.EOF }
		s.remain = packet.Payload
	}
	if len(s.remain) > len(p) {
		n = copy(p, s.remain[:len(p)])
		s.remain = s.remain[len(p):]
	} else {
		n = copy(p, s.remain)
		s.remain = nil
	}
	return
}

func (s *netStream) Close() error { s.ignore = true; return nil }

// receiveWindow simulates TCP receive window.
type receiveWindow struct {
	size        int
	start       int
	buffer      []*layers.TCP
	lastAck     uint32
	expectBegin uint32
}

func newReceiveWindow(initialSize int) *receiveWindow {
	return &receiveWindow{buffer: make([]*layers.TCP, initialSize)}
}

func (w *receiveWindow) insert(packet *layers.TCP) {
	if w.expectBegin != 0 && compareTCPSeq(w.expectBegin, packet.Seq+uint32(len(packet.Payload))) >= 0 {
		return
	}
	if len(packet.Payload) == 0 { return }
	idx := w.size
	for ; idx > 0; idx-- {
		index := (idx - 1 + w.start) % len(w.buffer)
		prev := w.buffer[index]
		result := compareTCPSeq(prev.Seq, packet.Seq)
		if result == 0 { return }
		if result < 0 { break }
	}
	if w.size == len(w.buffer) { w.expand() }
	if idx == w.size {
		index := (idx + w.start) % len(w.buffer)
		w.buffer[index] = packet
	} else {
		for i := w.size - 1; i >= idx; i-- {
			next := (i + w.start + 1) % len(w.buffer)
			current := (i + w.start) % len(w.buffer)
			w.buffer[next] = w.buffer[current]
		}
		index := (idx + w.start) % len(w.buffer)
		w.buffer[index] = packet
	}
	w.size++
}

func (w *receiveWindow) confirm(ack uint32, c chan *layers.TCP) {
	idx := 0
	for ; idx < w.size; idx++ {
		index := (idx + w.start) % len(w.buffer)
		packet := w.buffer[index]
		result := compareTCPSeq(packet.Seq, ack)
		if result >= 0 { break }
		w.buffer[index] = nil
		newExpect := packet.Seq + uint32(len(packet.Payload))
		if w.expectBegin != 0 {
			diff := compareTCPSeq(w.expectBegin, packet.Seq)
			if diff > 0 {
				dup := w.expectBegin - packet.Seq
				if dup < 0 { dup += maxTCPSeq }
				if dup >= uint32(len(packet.Payload)) { continue }
				packet.Payload = packet.Payload[dup:]
			}
		}
		c <- packet
		w.expectBegin = newExpect
	}
	w.start = (w.start + idx) % len(w.buffer)
	w.size -= idx
	if compareTCPSeq(w.lastAck, ack) < 0 || w.lastAck == 0 {
		w.lastAck = ack
	}
}

func (w *receiveWindow) expand() {
	buf := make([]*layers.TCP, len(w.buffer)*2)
	end := w.start + w.size
	if end < len(w.buffer) {
		copy(buf, w.buffer[w.start:w.start+w.size])
	} else {
		copy(buf, w.buffer[w.start:])
		copy(buf[len(w.buffer)-w.start:], w.buffer[:end-len(w.buffer)])
	}
	w.start = 0
	w.buffer = buf
}

func compareTCPSeq(seq1, seq2 uint32) int {
	if seq1 < tcpSeqWindow && seq2 > maxTCPSeq-tcpSeqWindow {
		return int(seq1 + maxTCPSeq - seq2)
	} else if seq2 < tcpSeqWindow && seq1 > maxTCPSeq-tcpSeqWindow {
		return int(seq1 - (maxTCPSeq + seq2))
	}
	return int(int32(seq1 - seq2))
}
