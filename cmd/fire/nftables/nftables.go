package nftables

import (
	"github.com/spf13/cobra"
)

var MainCommand = &cobra.Command{
	Use:   "nftables",
	Short: "nftables utility",
	Long:  `Manage and inspect nftables firewall system`,
	RunE:  nil,
}
