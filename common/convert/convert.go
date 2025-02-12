package convert

import "io"

type Convertor struct {
	sourceFormat SourceFormat
	// target //TODO
	in  io.Reader
	out io.Writer
}

func NewConvertor(format SourceFormat, in io.Reader) *Convertor {
	return &Convertor{sourceFormat: format, in: in}
}

func (c *Convertor) Convert() error {
	return nil
}
