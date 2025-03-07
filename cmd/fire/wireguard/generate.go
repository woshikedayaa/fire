package wireguard

import (
	"encoding/json"
	"github.com/spf13/cobra"
	"github.com/woshikedayaa/fire/common/networks/ip"
	"github.com/woshikedayaa/fire/common/wireguard"
	"io"
	"iter"
	"net"
	"net/netip"
	"os"
	"strconv"
)

const (
	MaxPeerCount = 1 << 12
)

type GenerateConfig struct {
	Count                  int  `json:"count"`
	SetupAllPeersInterface bool `json:"setup_all_peers_interface"`
	// common sections
	// dual stack supported
	IPv4Cidr        string   `json:"ipv4_cidr"`
	IPv6Cidr        string   `json:"ipv6_cidr"`
	IPv4            bool     `json:"ipv4"`
	IPv6            bool     `json:"ipv6"`
	DNS             []string `json:"dns"`
	EnablePreshared bool     `json:"enable_preshared"`

	// Interface section
	InterfaceListenPort uint16   `json:"interface_listen_port"`
	PreUp               []string `json:"pre_up"`
	PostUp              []string `json:"post_up"`
	PreDown             []string `json:"pre_down"`
	PostDown            []string `json:"post_down"`
	Table               int      `json:"table"`
	MTU                 int      `json:"mtu"`

	// Peer section
	AllowIPs            []string `json:"allow_ips"`
	PersistentKeepalive int      `json:"persistent_keepalive"`
	Endpoint            string   `json:"endpoint"`
	EndpointPort        uint16   `json:"endpoint_port"`

	// build
	v4Prefix netip.Prefix
	v6Prefix netip.Prefix

	allowIPs []netip.Prefix
	dns      []netip.Addr
}

func (c GenerateConfig) bindInterface(iif *wireguard.Interface) {
	iif.PreUp = c.PreUp
	iif.PreDown = c.PreDown
	iif.PostUp = c.PostUp
	iif.PostDown = c.PostDown
	iif.MTU = c.MTU
	iif.DNS = c.dns
	iif.ListenPort = c.InterfaceListenPort
	iif.Table = c.Table
}

func (c GenerateConfig) bindPeer(peer *wireguard.Peer) {
	peer.AllowedIPs = c.allowIPs
	if c.PersistentKeepalive > 0 {
		peer.PersistentKeepalive = c.PersistentKeepalive
	}
	if peer.Endpoint != "" {
		peer.Endpoint = net.JoinHostPort(c.Endpoint, strconv.FormatUint(uint64(c.EndpointPort), 10))
	}
}

func (c GenerateConfig) Build() (GenerateConfig, error) {
	if !c.IPv4 && !c.IPv6 {
		c.IPv4 = true // enable ipv4 as default
	}
	if c.PersistentKeepalive <= -1 {
		c.PersistentKeepalive = 0
	}
	if c.MTU <= 0 {
		c.MTU = 1420
	}
	if c.Table <= 0 {
		c.Table = 0
	}
	var err error
	if c.IPv4 {
		c.v4Prefix, err = netip.ParsePrefix(c.IPv4Cidr)
		if err != nil {
			return GenerateConfig{}, err
		}
		c.Count = min(c.Count, 1<<(32-c.v4Prefix.Bits())-1)
	}
	if c.IPv6 {
		c.v6Prefix, err = netip.ParsePrefix(c.IPv6Cidr)
		if err != nil {
			return GenerateConfig{}, err
		}
		c.Count = min(c.Count, 1<<min(128-c.v6Prefix.Bits(), 32)-1)
	}
	// use 32 instead of 128
	c.Count = min(c.Count, MaxPeerCount)

	if len(c.AllowIPs) == 0 {
		if c.IPv4 {
			c.AllowIPs = append(c.AllowIPs, c.v4Prefix.Masked().String())
		}
		if c.IPv6 {
			c.AllowIPs = append(c.AllowIPs, c.v6Prefix.Masked().String())
		}
	}
	for _, v := range c.AllowIPs {
		prefix, err := netip.ParsePrefix(v)
		if err != nil {
			return GenerateConfig{}, err
		}
		c.allowIPs = append(c.allowIPs, prefix)
	}
	for _, v := range c.DNS {
		addr, err := netip.ParseAddr(v)
		if err != nil {
			return GenerateConfig{}, err
		}
		c.dns = append(c.dns, addr)
	}
	return c, nil
}

var generateConfig GenerateConfig

var generateCommand = &cobra.Command{
	Use:   "generate",
	Short: "generate wireguard config",
	Long:  "generate wireguard config files,commands and so on",
	RunE:  Generate,
}

func init() {
	MainCommand.AddCommand(generateCommand)

	// flag
	generateCommand.Flags().IntVarP(&generateConfig.Count, "count", "c", MaxPeerCount, "Peer counts,Max=4096")
	generateCommand.Flags().StringVar(&generateConfig.IPv4Cidr, "ipv4-cidr", "10.13.13.0/24", "Set wireguard ipv4 cidr")
	generateCommand.Flags().StringVar(&generateConfig.IPv6Cidr, "ipv6-cidr", "fd82:9a37:b1c5:0e6f:2d18:4b93:7a50:c8/120", "Set wireguard ipv6 cidr")
	generateCommand.Flags().BoolVarP(&generateConfig.IPv4, "enable-ipv4", "4", false, "Enable ipv4(See --ip4-cidr)")
	generateCommand.Flags().BoolVarP(&generateConfig.IPv6, "enable-ipv6", "6", false, "Enable ipv6(See --ip6-cidr)")

	generateCommand.Flags().StringSliceVar(&generateConfig.DNS, "dns", []string{}, "Configure DNS, multi dns split by comma")
	generateCommand.Flags().BoolVarP(&generateConfig.EnablePreshared, "enable-preshard", "P", false, "Enable preshard key")
	generateCommand.Flags().Uint16Var(&generateConfig.InterfaceListenPort, "interface-listen-port", 51820, "Set interface listen port")

	generateCommand.Flags().StringArrayVar(&generateConfig.PreUp, "pre-up", []string{}, "Pre up hook")
	generateCommand.Flags().StringArrayVar(&generateConfig.PostUp, "post-up", []string{}, "Post up hook")
	generateCommand.Flags().StringArrayVar(&generateConfig.PreDown, "pre-down", []string{}, "Pre down hook")
	generateCommand.Flags().StringArrayVar(&generateConfig.PostDown, "post-down", []string{}, "Post down hook")
	generateCommand.Flags().IntVar(&generateConfig.Table, "table", -1, "ip2route table number")

	generateCommand.Flags().StringSliceVar(&generateConfig.AllowIPs, "allow-ips", []string{}, "Peer AllowIPs")
	generateCommand.Flags().IntVarP(&generateConfig.PersistentKeepalive, "keep-alive", "k", -1, "PersistentKeepalive")
	generateCommand.Flags().StringVarP(&generateConfig.Endpoint, "endpoint", "e", "", "Set peer endpoint address, use --endpoint-port to specified the endpoint port")
	generateCommand.Flags().Uint16Var(&generateConfig.EndpointPort, "endpoint-port", 0, "Set Peer Endpoint Port, default == --interface-listen-port")
	generateCommand.Flags().IntVar(&generateConfig.MTU, "mtu", 1420, "Set Interface MTU")

}

func Generate(cmd *cobra.Command, arg []string) error {
	gc, err := generateConfig.Build()
	if err != nil {
		return err
	}
	return generateRandom(gc, os.Stdout)
}

func generateRandom(gc GenerateConfig, out io.Writer) error {
	var (
		rootPriv = wireguard.GenPrivateKey()
		result   = wireguard.MeshPair{Root: wireguard.InterfaceWithPeers{
			Interface: wireguard.Interface{
				PrivateKey: rootPriv,
			},
			Peers: nil,
		}}
		v4Next, v6Next func() (netip.Addr, bool)
		v4Stop, v6Stop func()
	)
	if gc.IPv4 {
		v4Next, v4Stop = iter.Pull(ip.PrefixIter(gc.v4Prefix))
		defer v4Stop()
		addr, ok := v4Next()
		if ok {
			result.Root.Interface.Addresses = append(result.Root.Interface.Addresses, addr)
		}
	}
	if gc.IPv6 {
		v6Next, v6Stop = iter.Pull(ip.PrefixIter(gc.v6Prefix))
		defer v6Stop()
		addr, ok := v6Next()
		if ok {
			result.Root.Interface.Addresses = append(result.Root.Interface.Addresses, addr)
		}
	}
	for i := 0; i < gc.Count; i++ {
		extended, extendedIf, err := result.Root.Extend(gc.EnablePreshared)
		if err != nil {
			return err
		}
		// cofigure
		if gc.IPv4 {
			if addr, ok := v4Next(); ok {
				extendedIf.Interface.Addresses = append(extendedIf.Interface.Addresses, addr)
				extended.Peers[len(extended.Peers)-1].AllowedIPs = append(extended.Peers[len(extended.Peers)-1].AllowedIPs, netip.PrefixFrom(addr, addr.BitLen()))
			}
		}
		if gc.IPv6 {
			if addr, ok := v6Next(); ok {
				extendedIf.Interface.Addresses = append(extendedIf.Interface.Addresses, addr)
				extended.Peers[len(extended.Peers)-1].AllowedIPs = append(extended.Peers[len(extended.Peers)-1].AllowedIPs, netip.PrefixFrom(addr, addr.BitLen()))
			}
		}
		gc.bindPeer(&extendedIf.Peers[0])
		if gc.SetupAllPeersInterface {
			gc.bindInterface(&extendedIf.Interface)
		}
		// append
		result.Root = extended
		result.Peers = append(result.Peers, extendedIf)
	}
	gc.bindInterface(&result.Root.Interface)
	return json.NewEncoder(out).Encode(result)
}
