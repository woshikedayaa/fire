package common

import (
	"github.com/woshikedayaa/fire/common/pool"
	"strings"
)

var (
	stringBuilderPool = pool.New[*strings.Builder](func() any {
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
