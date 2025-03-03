package wireguard

import (
	"bufio"
	"bytes"
	E "github.com/woshikedayaa/fire/common/errors"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

type Interface struct {
	PrivateKey string       `json:"private_key"`
	Addresses  []netip.Addr `json:"addresses"`
	ListenPort uint16       `json:"listen_port"`

	// Optional
	DNS   []netip.Addr `json:"dns"`
	MTU   int          `json:"mtu"`
	Table string       `json:"table"`

	// Hook
	PreUp    []string `json:"pre_up"`
	PostUp   []string `json:"post_up"`
	PreDown  []string `json:"pre_down"`
	PostDown []string `json:"post_down"`

	// Misc
	SaveConfig bool `json:"save_config"`

	ready bool
}

func (c *Interface) MarshalText() (text []byte, err error) {
	var buf bytes.Buffer

	if c.PrivateKey != "" {
		buf.WriteString("PrivateKey = " + c.PrivateKey + "\n")
	} else {
		return nil, E.New("PrivateKey is required")
	}

	if len(c.Addresses) > 0 {
		addresses := make([]string, 0, len(c.Addresses))
		for _, addr := range c.Addresses {
			addresses = append(addresses, addr.String())
		}
		buf.WriteString("Address = " + strings.Join(addresses, ", ") + "\n")
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

	if c.Table != "" {
		buf.WriteString("Table = " + c.Table + "\n")
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

		c.parseInterfaceKeyValue(key, value)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	if newInterface.PrivateKey == "" {
		return E.New("PrivateKey is required")
	}

	newInterface.ready = true

	*c = newInterface
	return nil
}

func (c *Interface) parseInterfaceKeyValue(key, value string) {
	switch key {
	case "PrivateKey":
		c.PrivateKey = value
	case "Address":
		addresses := strings.Split(value, ",")
		for _, addrStr := range addresses {
			addrStr = strings.TrimSpace(addrStr)
			addr, parseErr := netip.ParseAddr(addrStr)
			if parseErr == nil {
				c.Addresses = append(c.Addresses, addr)
			}
		}
	case "ListenPort":
		port, parseErr := strconv.ParseUint(value, 10, 16)
		if parseErr == nil {
			c.ListenPort = uint16(port)
		}
	case "DNS":
		dnsAddresses := strings.Split(value, ",")
		for _, dnsStr := range dnsAddresses {
			dnsStr = strings.TrimSpace(dnsStr)
			dns, parseErr := netip.ParseAddr(dnsStr)
			if parseErr == nil {
				c.DNS = append(c.DNS, dns)
			}
		}
	case "MTU":
		mtu, parseErr := strconv.Atoi(value)
		if parseErr == nil {
			c.MTU = mtu
		}
	case "Table":
		c.Table = value
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
}

type Peer struct {
	PublicKey           string         `json:"public_key"`
	PresharedKey        string         `json:"preshared_key"`
	AllowedIPs          []netip.Prefix `json:"allowed_ips"`
	Endpoint            string         `json:"endpoint"`
	PersistentKeepalive string         `json:"persistent_keepalive"`

	ready bool
}

func (p *Peer) MarshalText() (text []byte, err error) {
	var buf bytes.Buffer

	if p.PublicKey != "" {
		buf.WriteString("PublicKey = " + p.PublicKey + "\n")
	} else {
		return nil, E.New("PublicKey is required")
	}

	if p.PresharedKey != "" {
		buf.WriteString("PresharedKey = " + p.PresharedKey + "\n")
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

	if p.PersistentKeepalive != "" {
		buf.WriteString("PersistentKeepalive = " + p.PersistentKeepalive + "\n")
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

		p.parsePeerKeyValue(key, value)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	if newPeer.PublicKey == "" {
		return E.New("PublicKey is required")
	}
	if len(newPeer.AllowedIPs) == 0 {
		return E.New("AllowedIPs is required")
	}

	newPeer.ready = true

	*p = newPeer
	return nil
}

func (p *Peer) parsePeerKeyValue(key, value string) {
	switch key {
	case "PublicKey":
		p.PublicKey = value
	case "PresharedKey":
		p.PresharedKey = value
	case "AllowedIPs":
		allowedIPs := strings.Split(value, ",")
		for _, ipStr := range allowedIPs {
			ipStr = strings.TrimSpace(ipStr)
			prefix, parseErr := netip.ParsePrefix(ipStr)
			if parseErr == nil {
				p.AllowedIPs = append(p.AllowedIPs, prefix)
			}
		}
	case "Endpoint":
		p.Endpoint = value
	case "PersistentKeepalive":
		p.PersistentKeepalive = value
	}
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
