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

type whenError struct {
	e    error
	when string
}

func (e *whenError) Unwrap() error {
	return e.e
}

func (e *whenError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("when %s :%s", e.when, e.e.Error())
}

func When(work string, e error) error {
	if e == nil {
		return nil
	}
	return &whenError{when: work, e: e}
}
