package main

import "github.com/spf13/cobra"

var commandNftables = &cobra.Command{
	Use:   "nftables",
	Short: "nftables utility",
	Long: `Converts a file from one format to target format.
Supported formats: geoip, mmdb, srs, mrs, txt`,
	Example: "fire convert -s [SourceFormat] [source] [output]",
	Args:    cobra.ExactArgs(2),
	RunE:    convertF,
}
