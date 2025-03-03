package main

import (
	"github.com/spf13/cobra"
	"os"
)

var mainCommand = &cobra.Command{
	Use:   "fire",
	Short: "fire is a tool for managing your nft firewall rules better",
}

func main() {
	if err := mainCommand.Execute(); err != nil {
		os.Exit(1)
	}
}
