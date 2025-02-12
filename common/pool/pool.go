package pool

import "sync"

type Options[T any] struct {
	BeforePut func(v T)
}
type Pool[T any] struct {
	pool *sync.Pool
	opt  *Options[T]
}

func New[T any](nf func() any, opt *Options[T]) *Pool[T] {
	return &Pool[T]{
		&sync.Pool{New: nf}, opt,
	}
}

func (p *Pool[T]) Get() T {
	return p.pool.Get().(T)
}

func (p *Pool[T]) Put(v T) {
	p.opt.BeforePut(v)
	p.pool.Put(v)
}
