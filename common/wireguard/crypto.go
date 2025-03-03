package wireguard

import (
	"crypto/rand"
	"encoding/base64"
	"golang.org/x/crypto/curve25519"
)

func GenPrivateKey() (priv []byte, err error) {
	key := make([]byte, 32)
	_, err = rand.Read(key)
	if err != nil {
		return nil, err
	}

	key[0] &= 248
	key[31] &= 127
	key[31] |= 64

	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(key)))
	base64.StdEncoding.Encode(encoded, key)

	return encoded, nil
}

func GenPublicKey(priv []byte) (pub []byte, err error) {
	privateKey := make([]byte, base64.StdEncoding.DecodedLen(len(priv)))
	n, err := base64.StdEncoding.Decode(privateKey, priv)
	if err != nil {
		return nil, err
	}
	privateKey = privateKey[:n]

	if len(privateKey) != 32 {
		return nil, err
	}

	var publicKey [32]byte
	var privateKeyArray [32]byte
	copy(privateKeyArray[:], privateKey)
	curve25519.ScalarBaseMult(&publicKey, &privateKeyArray)

	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(publicKey)))
	base64.StdEncoding.Encode(encoded, publicKey[:])

	return encoded, nil
}

func GenKeyPair() (priv, pub []byte, err error) {
	priv, err = GenPrivateKey()
	if err != nil {
		return nil, nil, err
	}

	pub, err = GenPublicKey(priv)
	if err != nil {
		return nil, nil, err
	}

	return priv, pub, nil
}
