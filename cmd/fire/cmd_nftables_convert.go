package main

import (
	"github.com/spf13/cobra"
	"github.com/woshikedayaa/fire/common/convert"
	E "github.com/woshikedayaa/fire/common/errors"
	"path/filepath"
)

var (
	sourceFormat convert.SourceFormat
	outputPath   string
	inputPath    string
)

var (
	convertCommand = &cobra.Command{
		Use:   "convert",
		Short: "Converts a file from one format to target format.",
		Long: `Converts a file from one format to target format.
Supported formats: geoip, mmdb, srs, mrs, txt`,
		Example: "fire convert -s [SourceFormat] -i [Source] -o [Output]",
		Args:    cobra.ExactArgs(2),
		RunE:    convertF,
	}
)

func init() {
	convertCommand.Flags().StringVarP((*string)(&sourceFormat), "source", "s", "", "Source format")

	commandNftables.AddCommand(convertCommand)
}

func convertF(cmd *cobra.Command, args []string) error {
	if sourceFormat == "" {
		switch filepath.Ext(args[0]) {
		case ".mmdb":
			sourceFormat = convert.SourceFormatMMDB
		case ".srs":
			sourceFormat = convert.SourceFormatSRS
		case ".mrs":
			sourceFormat = convert.SourceFormatMRS
		case ".txt":
			sourceFormat = convert.SourceFormatTXT
		case "dat":
			sourceFormat = convert.SourceFormatGEOIP
		default:
			return E.New("Unknown source format")
		}
	}

	if !sourceFormat.Valid() {
		return E.New("Invalid source format")
	}
	return nil
}
