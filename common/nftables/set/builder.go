package set

import (
	"github.com/woshikedayaa/fire/common"
	"strings"
)

const setDelimiter byte = ';'

type setBuilder struct {
	result *strings.Builder
}

func newSetBuilder() *setBuilder {
	return &setBuilder{result: common.GetStringBuilder()}
}

func (b *setBuilder) String() string {
	defer common.PutStringBuilder(b.result)
	b.result.WriteString("}")
	return b.result.String()
}

func (b *setBuilder) SetName(s string) *setBuilder {
	b.result.WriteString("set ")
	b.result.WriteString(s)
	b.result.WriteString("{")
	return b
}

func (b *setBuilder) AddBool(key string, val bool) *setBuilder {
	if val {
		b.result.WriteString(key)
		b.result.WriteByte(setDelimiter)
	}
	return b
}

func (b *setBuilder) AddString(key string, val string) *setBuilder {
	if val != "" {
		b.result.Grow(len(key) + len(val) + 2)
		b.result.WriteString(key)
		b.result.WriteByte(' ')
		b.result.WriteString(val)
		b.result.WriteByte(setDelimiter)
	}
	return b
}

func (b *setBuilder) AddSlice(key string, val []string, delim string) *setBuilder {
	if len(val) != 0 {
		if delim == "" {
			delim = ","
		}
		b.AddString(key, strings.Join(val, delim))
	}
	return b
}

func (b *setBuilder) AddElements(val []string) *setBuilder {
	if len(val) != 0 {
		b.result.WriteString("elements={")
		b.result.WriteString(strings.Join(val, ","))
		b.result.WriteString("};")
	}
	return b
}
