package main

import (
	"github.com/woshikedayaa/fire/cmd/fire/nftables"
	"github.com/woshikedayaa/fire/cmd/fire/wireguard"
)

func init() {
	mainCommand.AddCommand(
		nftables.MainCommand,
		wireguard.MainCommand,
	)
}
