package wireguard

type InterfaceWithPeers struct {
	Interface Interface `json:"interface"`
	Peers     []Peer    `json:"peers"`
}

func (ifp InterfaceWithPeers) Extend(enablePreshare bool) (extended InterfaceWithPeers, sub InterfaceWithPeers, err error) {
	pub, err := GenPublicKey(ifp.Interface.PrivateKey)
	if err != nil {
		return InterfaceWithPeers{}, InterfaceWithPeers{}, err
	}
	peerPriv, peerPub := GenKeyPair()
	root := Peer{}
	sub = InterfaceWithPeers{Interface: Interface{}, Peers: []Peer{{}}}
	root.PublicKey = peerPub
	sub.Interface.PrivateKey = peerPriv
	sub.Peers[0].PublicKey = pub
	if enablePreshare {
		preshare := GenPresharedKey()
		root.PresharedKey = preshare
		sub.Peers[0].PresharedKey = preshare
	}
	ifp.Peers = append(ifp.Peers, root)

	return ifp, sub, nil
}

type MeshPair struct {
	Root  InterfaceWithPeers   `json:"root"`
	Peers []InterfaceWithPeers `json:"peers"`
}
