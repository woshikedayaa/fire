package common

import (
	"runtime"
	"strings"

	"github.com/woshikedayaa/fire/common/pool"
)

var (
	stringBuilderPool = pool.New(func() any {
		return &strings.Builder{}
	}, &pool.Options[*strings.Builder]{BeforePut: func(v *strings.Builder) {
		v.Reset()
	}})
)

func GetStringBuilder() *strings.Builder {
	return stringBuilderPool.Get()
}

func PutStringBuilder(s *strings.Builder) {
	stringBuilderPool.Put(s)
}

func HasMeta(s string) bool {
	magicChars := `*?[`
	if runtime.GOOS != "windows" {
		magicChars = `*?[\`
	}
	return strings.ContainsAny(s, magicChars)
}
