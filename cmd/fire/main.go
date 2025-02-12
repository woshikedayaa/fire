package main

import (
	"github.com/spf13/cobra"
	"os"
)

var (
	workDir string
)

var mainCommand = &cobra.Command{
	Use:   "fire",
	Short: "fire is a tool for managing your nft firewall rules better",
}

func init() {
	mainCommand.PersistentFlags().StringVarP(&workDir, "wd", "D", "/etc/nftables.d/", "Working directory")
}
func main() {
	if err := mainCommand.Execute(); err != nil {
		os.Exit(1)
	}
}
