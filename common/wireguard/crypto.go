package wireguard

import (
	"crypto/rand"
	"encoding/base64"
	E "github.com/woshikedayaa/fire/common/errors"
	"golang.org/x/crypto/curve25519"
)

type PrivateKey [32]byte

func (k PrivateKey) MarshalText() (text []byte, err error) {
	text = make([]byte, base64.StdEncoding.EncodedLen(len(k)))
	base64.StdEncoding.Encode(text, k[:])
	return text, nil
}

func (k *PrivateKey) UnmarshalText(data []byte) error {
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(decoded, data)
	if err != nil {
		return err
	}

	if n != 32 {
		return E.New("invalid private key length")
	}

	copy(k[:], decoded[:n])
	return nil
}

func (k PrivateKey) String() string {
	text, _ := k.MarshalText()
	return string(text)
}

func (k PrivateKey) IsValid() bool {
	return (k[0]&248) == k[0] &&
		(k[31]&127) == k[31] &&
		(k[31]&64) == 64
}

type PublicKey [32]byte

func (k PublicKey) MarshalText() (text []byte, err error) {
	text = make([]byte, base64.StdEncoding.EncodedLen(len(k)))
	base64.StdEncoding.Encode(text, k[:])
	return text, nil
}

func (k *PublicKey) UnmarshalText(data []byte) error {
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(decoded, data)
	if err != nil {
		return err
	}

	if n != 32 {
		return E.New("invalid public key length")
	}

	copy(k[:], decoded[:n])
	return nil
}

func (k PublicKey) String() string {
	text, _ := k.MarshalText()
	return string(text)
}

func (k PublicKey) IsValid() bool {
	return !zeroKey(k)
}

type PresharedKey [32]byte

func (k PresharedKey) MarshalText() (text []byte, err error) {
	text = make([]byte, base64.StdEncoding.EncodedLen(len(k)))
	base64.StdEncoding.Encode(text, k[:])
	return text, nil
}

func (k *PresharedKey) UnmarshalText(data []byte) error {
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(decoded, data)
	if err != nil {
		return err
	}

	if n != 32 {
		return E.New("invalid preshared key length")
	}

	copy(k[:], decoded[:n])
	return nil
}

func (k PresharedKey) String() string {
	text, _ := k.MarshalText()
	return string(text)
}

func (k PresharedKey) IsValid() bool {
	return !zeroKey(k)
}

func GenPrivateKey() (priv PrivateKey) {
	_, _ = rand.Read(priv[:])
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	return priv
}

func GenPublicKey(priv PrivateKey) (pub PublicKey, err error) {
	if !priv.IsValid() {
		return [32]byte{}, E.New("illegal private key")
	}
	curve25519.ScalarBaseMult((*[32]byte)(&pub), (*[32]byte)(&priv))
	return pub, nil
}

func GenKeyPair() (priv PrivateKey, pub PublicKey, err error) {
	priv = GenPrivateKey()
	pub, err = GenPublicKey(priv)
	if err != nil {
		return PrivateKey{}, PublicKey{}, err
	}

	return priv, pub, nil
}

func GenPresharedKey() (key PresharedKey) {
	_, _ = rand.Read(key[:])
	return key
}

func zeroKey(k [32]byte) bool {
	for _, v := range k {
		if v != 0x00 {
			return false
		}
	}
	return true
}
