package main

import (
	"github.com/spf13/cobra"
	"github.com/woshikedayaa/fire/cmd/fire"
	"os"
)

var mainCommand = &cobra.Command{
	Use:     "fire",
	Short:   "fire is a tool for managing your nft firewall rules better",
	Version: fire.Version,
}

func main() {
	if err := mainCommand.Execute(); err != nil {
		os.Exit(1)
	}
}
