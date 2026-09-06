package ipadecrypt

import (
	"io"
	"time"
)

const progressTick = 100 * time.Millisecond

type progressReader struct {
	r           io.Reader
	total, read int64
	last        time.Time
	onProgress  func(int64, int64)
}

func (p *progressReader) Read(buf []byte) (int, error) {
	n, err := p.r.Read(buf)
	p.read += int64(n)
	if n > 0 && time.Since(p.last) >= progressTick {
		p.last = time.Now()
		p.onProgress(p.read, p.total)
	}
	if err == io.EOF {
		p.onProgress(p.read, p.total)
	}
	return n, err
}

type countingWriter struct {
	w          io.Writer
	n          int64
	last       time.Time
	onProgress func(int64)
}

func (w *countingWriter) Write(buf []byte) (int, error) {
	n, err := w.w.Write(buf)
	w.n += int64(n)
	if n > 0 && w.onProgress != nil && time.Since(w.last) >= progressTick {
		w.last = time.Now()
		w.onProgress(w.n)
	}
	return n, err
}
