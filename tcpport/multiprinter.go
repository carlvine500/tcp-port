package tcpport

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// MultiPrinter writes output to stdout and optionally to per-protocol files.
type MultiPrinter struct {
	outputQueue chan printerMsg
	stdout      io.WriteCloser
	files       map[string]io.WriteCloser
	outputDir   string
	mu          sync.Mutex
}

type printerMsg struct {
	Protocol string
	Text     string
}

const maxQueueLen = 8192

// NewMultiPrinter creates a printer. If outputDir is set, creates per-protocol files.
func NewMultiPrinter(outputDir string) *MultiPrinter {
	p := &MultiPrinter{
		outputQueue: make(chan printerMsg, maxQueueLen),
		stdout:      os.Stdout,
		files:       make(map[string]io.WriteCloser),
		outputDir:   outputDir,
	}
	go p.run()
	return p
}

// Send queues a message for output. protocol is used for file routing.
func (p *MultiPrinter) Send(protocol, msg string) {
	if len(p.outputQueue) == maxQueueLen {
		return
	}
	p.outputQueue <- printerMsg{Protocol: protocol, Text: msg}
}

func (p *MultiPrinter) run() {
	defer p.stdout.Close()
	for m := range p.outputQueue {
		// Write to stdout
		p.stdout.Write([]byte(m.Text))

		// Write to per-protocol file if output dir is set
		if p.outputDir != "" && m.Protocol != "" {
			f := p.getFile(m.Protocol)
			if f != nil {
				f.Write([]byte(m.Text))
			}
		}
	}
	// Close all protocol files
	for _, f := range p.files {
		f.Close()
	}
}

func (p *MultiPrinter) getFile(protocol string) io.WriteCloser {
	p.mu.Lock()
	defer p.mu.Unlock()

	if f, ok := p.files[protocol]; ok {
		return f
	}

	path := filepath.Join(p.outputDir, protocol+".log")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tcpport: cannot create %s: %v\n", path, err)
		return nil
	}
	p.files[protocol] = f
	return f
}

// Finish closes the queue.
func (p *MultiPrinter) Finish() {
	close(p.outputQueue)
}
