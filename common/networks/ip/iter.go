package ip

import (
	"iter"
	"net/netip"
)

func PrefixIter(prefix netip.Prefix) iter.Seq[netip.Addr] {
	if !prefix.IsValid() {
		panic("Invalid netip.Prefix")
	}
	prefix = prefix.Masked()
	return func(yield func(netip.Addr) bool) {
		addr := prefix.Addr().Next()
		for addr.IsValid() && prefix.Contains(addr) {
			if !yield(addr) {
				return
			}
			addr = addr.Next()
		}
	}
}
