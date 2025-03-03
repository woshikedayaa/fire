package ewr

import "io"

var _ io.Reader = (*CachedReader)(nil)

type CachedReader struct {
	off  int
	data []byte
	r    io.Reader
}

func NewCachedReader(data []byte, r io.Reader) *CachedReader {
	return &CachedReader{
		data: data,
		r:    r,
	}
}

func (r *CachedReader) Read(p []byte) (n int, err error) {
	var nn int
	for r.off < len(r.data) {
		nn = copy(p[:], r.data[r.off:])
		r.off += nn
		n += nn
		if nn == len(p) {
			return
		}
	}
	nn, err = r.r.Read(p[n:])
	n += nn
	return
}

var _ io.Writer = (*CachedWriter)(nil)

type CachedWriter struct {
	data []byte
	w    io.Writer
	off  int
}

func NewCachedWriter(data []byte, w io.Writer) *CachedWriter {
	return &CachedWriter{
		data: data,
		w:    w,
	}
}
func (w *CachedWriter) Write(p []byte) (n int, err error) {
	var nn int
	for w.off < len(w.data) {
		nn, err = w.w.Write(w.data[w.off:])
		n += nn
		w.off += nn
		if err != nil {
			return
		}
		if n == len(p) {
			return
		}
	}
	nn, err = w.w.Write(p)
	n += nn
	return
}
