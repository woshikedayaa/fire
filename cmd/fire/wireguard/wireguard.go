package wireguard

import (
	"github.com/spf13/cobra"
)

var MainCommand = &cobra.Command{
	Use:   "wg",
	Short: "manage wireguard",
	Long:  "",
	RunE:  nil,
}
