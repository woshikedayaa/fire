package main

import (
	"github.com/spf13/cobra"
	"github.com/woshikedayaa/fire/common/convert"
)

var (
	sourceFormat convert.SourceFormat
	outputPath   string
	inputPath    string

	targetFormat convert.TargetFormat
)

var (
	nftablesConvertCommand = &cobra.Command{
		Use:   "convert",
		Short: "Converts a file from one format to target format.",
		Long: `Converts a file from one format to target format.
Supported formats: geoip, mmdb, srs, mrs, txt`,
		Example: "fire convert -S [SourceFormat] -T [TargetFormat] -i [Source] -o [Output] ",
		RunE:    nftablesConvert,
	}
)

func init() {
	nftablesConvertCommand.Flags().StringVarP((*string)(&sourceFormat), "source-format", "S", "", "Source format")
	nftablesConvertCommand.Flags().StringVarP((*string)(&outputPath), "output", "o", "/dev/stdin", "input path")
	nftablesConvertCommand.Flags().StringVarP((*string)(&inputPath), "input", "i", "/dev/stdout", "output path")
	nftablesConvertCommand.Flags().StringVarP((*string)(&targetFormat), "target-format", "T", "set", "convert target format")

	commandNftables.AddCommand(nftablesConvertCommand)
}

func nftablesConvert(cmd *cobra.Command, args []string) error {
	return nil
}
