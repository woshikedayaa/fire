package nftables

type Family string

const (
	FamilyIPv4        Family = "ip"
	FamilyIPv6        Family = "ip6"
	FamilyInet        Family = "inet"
	FamilyArp         Family = "arp"
	FamilyBridge      Family = "bridge"
	FamilyNetdev      Family = "netdev"
	FamilyUnspecified Family = ""
)
