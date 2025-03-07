package wireguard

import (
	"bufio"
	"bytes"
	"encoding/json"
	E "github.com/woshikedayaa/fire/common/errors"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

type Interface struct {
	PrivateKey PrivateKey   `json:"private_key,omitempty"`
	Addresses  []netip.Addr `json:"addresses,omitempty"`
	ListenPort uint16       `json:"listen_port,omitempty"`

	// Optional
	DNS   []netip.Addr `json:"dns,omitempty"`
	MTU   int          `json:"mtu,omitempty"`
	Table int          `json:"table,omitempty"`

	// Hook
	PreUp    []string `json:"pre_up,omitempty"`
	PostUp   []string `json:"post_up,omitempty"`
	PreDown  []string `json:"pre_down,omitempty"`
	PostDown []string `json:"post_down,omitempty"`

	// Misc
	SaveConfig bool `json:"save_config,omitempty"`

	ready bool
}

func (c *Interface) MarshalJSON() (data []byte, err error) {
	type jsonAble Interface
	return json.Marshal((*jsonAble)(c))
}

func (c *Interface) UnmarshalJSON(data []byte) error {
	dupI := *c
	de := json.NewDecoder(bytes.NewReader(data))
	de.DisallowUnknownFields()
	e := de.Decode(&dupI)
	if e != nil {
		return e
	}
	*c = dupI
	return nil
}

func (c *Interface) MarshalText() (text []byte, err error) {
	var buf bytes.Buffer

	if c.PrivateKey.IsValid() {
		buf.WriteString("PrivateKey = " + c.PrivateKey.String() + "\n")
	} else {
		return nil, E.New("PrivateKey is required")
	}

	if len(c.Addresses) > 0 {
		addresses := make([]string, 0, len(c.Addresses))
		for _, addr := range c.Addresses {
			addresses = append(addresses, addr.String())
		}
		buf.WriteString("Address = " + strings.Join(addresses, ",") + "\n")
	}

	if c.ListenPort > 0 {
		buf.WriteString("ListenPort = " + strconv.FormatUint(uint64(c.ListenPort), 10) + "\n")
	}

	if len(c.DNS) > 0 {
		dnsAddresses := make([]string, 0, len(c.DNS))
		for _, dns := range c.DNS {
			dnsAddresses = append(dnsAddresses, dns.String())
		}
		buf.WriteString("DNS = " + strings.Join(dnsAddresses, ", ") + "\n")
	}

	if c.MTU > 0 {
		buf.WriteString("MTU = " + strconv.Itoa(c.MTU) + "\n")
	}

	if c.Table != 0 {
		buf.WriteString("Table = " + strconv.Itoa(c.Table) + "\n")
	}

	for _, hook := range c.PreUp {
		buf.WriteString("PreUp = " + hook + "\n")
	}
	for _, hook := range c.PostUp {
		buf.WriteString("PostUp = " + hook + "\n")
	}
	for _, hook := range c.PreDown {
		buf.WriteString("PreDown = " + hook + "\n")
	}
	for _, hook := range c.PostDown {
		buf.WriteString("PostDown = " + hook + "\n")
	}

	if c.SaveConfig {
		buf.WriteString("SaveConfig = true\n")
	}

	return buf.Bytes(), nil
}

func (c *Interface) UnmarshalText(text []byte) error {
	var newInterface Interface
	scanner := bufio.NewScanner(bytes.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") ||
			(strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]")) {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if e := c.parseInterfaceKeyValue(key, value); e != nil {
			return e
		}
	}

	if err := scanner.Err(); err != nil {
		return E.When("Scan", err)
	}

	if !newInterface.PrivateKey.IsValid() {
		return E.New("PrivateKey is not valid")
	}

	newInterface.ready = true

	*c = newInterface
	return nil
}

func (c *Interface) parseInterfaceKeyValue(key, value string) error {
	switch key {
	case "PrivateKey":
		return c.PrivateKey.UnmarshalText([]byte(value))
	case "Address":
		addresses := strings.Split(value, ",")
		for _, addrStr := range addresses {
			addrStr = strings.TrimSpace(addrStr)
			addr, parseErr := netip.ParseAddr(addrStr)
			if parseErr != nil {
				return parseErr
			}
			c.Addresses = append(c.Addresses, addr)
		}
	case "ListenPort":
		port, parseErr := strconv.ParseUint(value, 10, 16)
		if parseErr != nil {
			return parseErr
		}
		c.ListenPort = uint16(port)
	case "DNS":
		dnsAddresses := strings.Split(value, ",")
		for _, dnsStr := range dnsAddresses {
			dnsStr = strings.TrimSpace(dnsStr)
			dns, parseErr := netip.ParseAddr(dnsStr)
			if parseErr != nil {
				return parseErr
			}
			c.DNS = append(c.DNS, dns)
		}
	case "MTU":
		mtu, parseErr := strconv.Atoi(value)
		if parseErr != nil {
			return parseErr
		}
		c.MTU = mtu
	case "Table":
		table, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return err
		}
		c.Table = int(table)
	case "PreUp":
		c.PreUp = append(c.PreUp, value)
	case "PostUp":
		c.PostUp = append(c.PostUp, value)
	case "PreDown":
		c.PreDown = append(c.PreDown, value)
	case "PostDown":
		c.PostDown = append(c.PostDown, value)
	case "SaveConfig":
		if strings.ToLower(value) == "true" {
			c.SaveConfig = true
		}
	}
	return nil
}

type Peer struct {
	PublicKey           PublicKey      `json:"public_key,omitempty"`
	PresharedKey        PresharedKey   `json:"preshared_key,omitempty"`
	AllowedIPs          []netip.Prefix `json:"allowed_ips,omitempty"`
	Endpoint            string         `json:"endpoint,omitempty"`
	PersistentKeepalive int            `json:"persistent_keepalive,omitempty"`

	ready bool
}

func (p *Peer) MarshalJSON() (data []byte, err error) {
	type jsonAble Peer
	return json.Marshal((*jsonAble)(p))
}

func (p *Peer) UnmarshalJSON(data []byte) error {
	dupP := *p
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&dupP)
	if err != nil {
		return err
	}
	*p = dupP
	return nil
}

func (p *Peer) MarshalText() (text []byte, err error) {
	var buf bytes.Buffer

	if p.PublicKey.IsValid() {
		buf.WriteString("PublicKey = " + p.PublicKey.String() + "\n")
	} else {
		return nil, E.New("PublicKey is required")
	}

	if p.PresharedKey.IsValid() {
		buf.WriteString("PresharedKey = " + p.PresharedKey.String() + "\n")
	}

	if len(p.AllowedIPs) > 0 {
		allowedIPs := make([]string, 0, len(p.AllowedIPs))
		for _, prefix := range p.AllowedIPs {
			allowedIPs = append(allowedIPs, prefix.String())
		}
		buf.WriteString("AllowedIPs = " + strings.Join(allowedIPs, ", ") + "\n")
	} else {
		return nil, E.New("AllowedIPs is required")
	}

	if p.Endpoint != "" {
		buf.WriteString("Endpoint = " + p.Endpoint + "\n")
	}

	if p.PersistentKeepalive != 0 {
		buf.WriteString("PersistentKeepalive = " + strconv.FormatInt(int64(p.PersistentKeepalive), 10) + "\n")
	}

	return buf.Bytes(), nil
}

func (p *Peer) UnmarshalText(text []byte) error {
	var newPeer Peer

	scanner := bufio.NewScanner(bytes.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") ||
			(strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]")) {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if e := p.parsePeerKeyValue(key, value); e != nil {
			return e
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	if !newPeer.PublicKey.IsValid() {
		return E.New("PublicKey is not valid")
	}
	if len(newPeer.AllowedIPs) == 0 {
		return E.New("AllowedIPs is required")
	}

	newPeer.ready = true

	*p = newPeer
	return nil
}

func (p *Peer) parsePeerKeyValue(key, value string) error {
	switch key {
	case "PublicKey":
		return p.PublicKey.UnmarshalText([]byte(value))
	case "PresharedKey":
		return p.PresharedKey.UnmarshalText([]byte(value))
	case "AllowedIPs":
		allowedIPs := strings.Split(value, ",")
		for _, ipStr := range allowedIPs {
			ipStr = strings.TrimSpace(ipStr)
			prefix, parseErr := netip.ParsePrefix(ipStr)
			if parseErr != nil {
				return parseErr
			}
			p.AllowedIPs = append(p.AllowedIPs, prefix)
		}
	case "Endpoint":
		p.Endpoint = value
	case "PersistentKeepalive":
		keepalive, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return err
		}
		p.PersistentKeepalive = int(keepalive)
	}
	return nil
}

func ParseWireguardConf(in io.Reader) (iif Interface, peers []Peer, err error) {
	scanner := bufio.NewScanner(in)

	var currentSection string
	var currentPeerText bytes.Buffer
	var currentInterfaceText bytes.Buffer

	for scanner.Scan() {
		line := scanner.Text()
		tl := strings.TrimSpace(line)

		if tl == "" || strings.HasPrefix(tl, "#") || strings.HasPrefix(tl, ";") {
			continue
		}
		if strings.HasPrefix(tl, "[") && strings.HasSuffix(tl, "]") {
			sectionName := strings.TrimSuffix(strings.TrimPrefix(tl, "["), "]")

			if currentSection == "Peer" && currentPeerText.Len() > 0 {
				var peer Peer
				if err := peer.UnmarshalText(currentPeerText.Bytes()); err == nil && peer.ready {
					peers = append(peers, peer)
				}
				currentPeerText.Reset()
			}

			if sectionName == "Interface" {
				if currentSection == "Interface" {
					return Interface{}, nil, E.New("multiple [Interface] sections found")
				}
				currentSection = "Interface"
			} else if sectionName == "Peer" {
				currentSection = "Peer"
			} else {
				return Interface{}, nil, E.New("unknown section: ", sectionName)
			}
			continue
		}

		if currentSection == "Interface" {
			currentInterfaceText.WriteString(line + "\n")
		} else if currentSection == "Peer" {
			currentPeerText.WriteString(line + "\n")
		}
	}

	if err = scanner.Err(); err != nil {
		return Interface{}, nil, err
	}

	if currentSection == "Peer" && currentPeerText.Len() > 0 {
		var peer Peer
		if err := peer.UnmarshalText(currentPeerText.Bytes()); err == nil && peer.ready {
			peers = append(peers, peer)
		}
	}

	if currentInterfaceText.Len() > 0 {
		if err := iif.UnmarshalText(currentInterfaceText.Bytes()); err != nil {
			return Interface{}, nil, err
		}
	} else {
		return Interface{}, nil, E.New("missing Interface section")
	}

	return iif, peers, nil
}

func MarshalWireguardConf(iface Interface, peers []Peer) ([]byte, error) {
	var buf bytes.Buffer

	// [Interface]
	buf.WriteString("[Interface]\n")
	ifaceText, err := iface.MarshalText()
	if err != nil {
		return nil, err
	}
	buf.Write(ifaceText)
	buf.WriteString("\n")

	// [Peer]
	for _, peer := range peers {
		buf.WriteString("[Peer]\n")
		peerText, err := peer.MarshalText()
		if err != nil {
			return nil, err
		}
		buf.Write(peerText)
		buf.WriteString("\n")
	}

	return buf.Bytes(), nil
}
