package errors

import (
	"fmt"
	"github.com/woshikedayaa/fire/common"
)

type simpleError struct {
	msg string
}

func (e *simpleError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return e.msg
}

func New(v ...any) error {
	if len(v) == 0 {
		return nil
	}

	vv := common.NonNil(v...)
	if len(vv) == 0 {
		return nil
	}

	return &simpleError{msg: fmt.Sprint(vv...)}
}
