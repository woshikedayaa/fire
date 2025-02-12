package set

import (
	"fmt"
	"strings"
	"unsafe"
)

type Type string

const (
	TypeIpv4Addr    Type = "ipv4_addr"
	TypeIpv6Addr    Type = "ipv6_addr"
	TypeEtherAddr   Type = "ether_addr"
	TypeInetProto   Type = "inet_proto"
	TypeInetService Type = "inet_service"
	TypeMark        Type = "mark"
	TypeIfname      Type = "ifname"
)

type Flag string

const (
	FlagConstant Flag = "constant"
	FlagInterval Flag = "interval"
	FlagTimeout  Flag = "timeout"
)

type Policy string

const (
	PolicyPerformance Policy = "performance"
	PolicyMemory      Policy = "memory"
)

// Set https://wiki.nftables.org/wiki-nftables/index.php/Sets
type Set struct {
	Type       Type     `json:"type,omitempty"`
	Name       string   `json:"name,omitempty"`
	Timeout    string   `json:"timeout,omitempty"`
	Flag       []Flag   `json:"flag,omitempty"`
	GCInterval string   `json:"gc_interval,omitempty"`
	Size       string   `json:"size,omitempty"`
	Policy     Policy   `json:"policy,omitempty"`
	Counter    bool     `json:"counter,omitempty"`
	AutoMerge  bool     `json:"auto_merge,omitempty"`
	Elements   []string `json:"elements,omitempty"`
}

func (s *Set) Valid() bool {
	switch s.Type {
	case TypeEtherAddr, TypeIfname, TypeInetProto, TypeInetService, TypeIpv4Addr, TypeIpv6Addr, TypeMark:
	default:
		return false
	}

	for _, v := range s.Flag {
		switch v {
		case FlagConstant, FlagInterval, FlagTimeout:
		default:
			return false
		}
	}

	switch s.Policy {
	case PolicyMemory, PolicyPerformance:
	default:
		return false
	}
	return true
}

func (s *Set) AsNamed() string {
	sb := newSetBuilder()

	return sb.SetName(s.Name).
		AddString("type", string(s.Type)).
		AddString("timeout", s.Timeout).
		AddString("gc-interval", s.GCInterval).
		AddString("size", s.Size).
		AddString("policy", string(s.Policy)).
		AddSlice("flags", s.flags2String(s.Flag), ",").
		AddBool("counter", s.Counter).
		AddBool("auto-merge", s.AutoMerge).
		AddElements(s.Elements).
		String()
}

func (s *Set) AsAnonymous() string {
	if len(s.Elements) == 0 {
		return "{}"
	}
	return fmt.Sprintf("{%s}", strings.Join(s.Elements, ","))
}

func (s *Set) flags2String(fs []Flag) []string {
	if fs == nil {
		return nil
	}

	if len(fs) == 0 {
		return []string{}
	}
	return unsafe.Slice((*string)(unsafe.Pointer(&fs[0])), len(fs))
}
