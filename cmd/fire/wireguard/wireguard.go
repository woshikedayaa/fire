package wireguard

import (
	"github.com/spf13/cobra"
)

var MainCommand = &cobra.Command{
	Short: "manage wireguard",
	Long:  "",
	RunE:  nil,
}
