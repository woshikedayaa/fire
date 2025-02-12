package internal

type Convertor interface {
	Convert(in []byte) ([]byte, error)
}

func NewConvertor(ft string) Convertor {
	return &convertor{}
}
