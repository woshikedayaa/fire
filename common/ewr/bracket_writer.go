package ewr

import (
	"bytes"
	"io"
)

type BracketWriter struct {
	count    int
	underlay io.Writer

	c1, c2 byte
}

func NewBracketWriter(w io.Writer, char1, char2 byte) *BracketWriter {
	return &BracketWriter{
		underlay: w,
		c1:       char1,
		c2:       char2,
	}
}

func (w *BracketWriter) WriteBracket() error {
	w.count++
	if bb, ok := w.underlay.(io.ByteWriter); ok {
		return bb.WriteByte(w.c1)
	}
	_, err := w.underlay.Write([]byte{w.c1})
	return err
}

func (w *BracketWriter) CloseBracket() (n int, err error) {
	w.count = 0
	return w.underlay.Write(bytes.Repeat([]byte{w.c2}, w.count))
}
