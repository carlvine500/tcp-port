package tcpport

import (
	"io"
	"os"
)

// Printer outputs parsed messages asynchronously.
type Printer struct {
	outputQueue chan string
	outputFile  io.WriteCloser
}

const maxOutputQueueLen = 4096

// NewPrinter creates a new Printer. If outputPath is empty, writes to stdout.
func NewPrinter(outputPath string) *Printer {
	var f io.WriteCloser
	if outputPath == "" {
		f = os.Stdout
	} else {
		var err error
		f, err = os.OpenFile(outputPath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0666)
		if err != nil {
			panic(err)
		}
	}
	p := &Printer{outputQueue: make(chan string, maxOutputQueueLen), outputFile: f}
	go p.run()
	return p
}

// Send queues a message for output.
func (p *Printer) Send(msg string) {
	if len(p.outputQueue) == maxOutputQueueLen {
		return
	}
	p.outputQueue <- msg
}

func (p *Printer) run() {
	defer p.outputFile.Close()
	for msg := range p.outputQueue {
		p.outputFile.Write([]byte(msg))
	}
}

// Finish closes the queue and waits for all output to flush.
func (p *Printer) Finish() {
	close(p.outputQueue)
}
