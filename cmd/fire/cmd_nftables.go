package main

import "github.com/spf13/cobra"

var commandNftables = &cobra.Command{
	Use:   "nftables",
	Short: "Manage and inspect nftables firewall",
	Long:  `Manage and inspect nftables firewall system`,
	RunE:  nil,
}

func init() {
	mainCommand.AddCommand(commandNftables)
}
