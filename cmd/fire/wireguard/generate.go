package wireguard

import (
	"github.com/spf13/cobra"
	"github.com/woshikedayaa/fire/common/networks/ip"
	"net/netip"
)

var generateCommand = &cobra.Command{
	Use:   "generate",
	Short: "generate wireguard config",
	Long:  "generate wireguard config files,commands and so on",
	RunE:  Generate,
}

var (
	count int

	ipCidr4, ipCidr6       string
	enableIpv4, enableIpv6 bool

	allowAllIps bool

	dns string
)

func init() {
	MainCommand.AddCommand(generateCommand)

	// flag
	generateCommand.Flags().IntVarP(&count, "count", "c", 1, "Peer counts")
	generateCommand.Flags().StringVar(&ipCidr4, "ip4-cidr", "10.13.13.0/24", "Set wireguard ipv6 cidr")
	generateCommand.Flags().StringVar(&ipCidr6, "ip6-cidr", "fd82:9a37:b1c5:0e6f:2d18:4b93:7a50:c8/120", "Set wireguard ipv6 cidr")
	generateCommand.Flags().BoolVarP(&enableIpv4, "ipv4", "4", false, "Enable ipv4(See --ip4-cidr)")
	generateCommand.Flags().BoolVarP(&enableIpv6, "ipv6", "6", false, "Enable ipv6(See --ip6-cidr)")
	generateCommand.Flags().BoolVar(&allowAllIps, "allow-all", false, "Allow all IPs in route , 0.0.0.0/0 and ::/0")
	generateCommand.Flags().StringVar(&dns, "dns", "", "Configure DNS, multi dns split by comma")
}

func Generate(cmd *cobra.Command, arg []string) error {
	pfx, err := netip.ParsePrefix("10.13.13.0/22")
	if err != nil {
		return err
	}

	for v := range ip.FromPrefix(pfx) {
		_ = v
	}
	return nil
}
