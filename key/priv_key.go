package key

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/itchyny/base58-go"
	"math/big"
)

var (
	secp256k1N, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
)

type PrivKey struct {
	data []byte
}

func PrivateKeyFromWIF(encoded string) (*PrivKey, error) {
	if encoded == "" {
		return nil, errors.New("invalid priv key")
	}
	decoded, err := base58.BitcoinEncoding.Decode([]byte(encoded))
	if err != nil {
		return nil, err
	}

	x, ok := new(big.Int).SetString(string(decoded), 10)
	if !ok {
		return nil, errors.New("set string error")
	}

	buf := x.Bytes()
	length := len(buf)
	if length <= 4 {
		return nil, errors.New("invalid priv key length")
	}

	data := buf[:length-4]

	checksum := sha256.Sum256(sha256.Sum256(data)[:])

	if !bytes.Equal(checksum[0:4], buf[length-4:]) {
		return nil, errors.New("checksum unmatched")
	}

	return &PrivKey{data: data}, nil
}

func (m *PrivKey) PubKey() (*PubKey, error) {
	priv := ecdsa.PrivateKey{}
	priv.PublicKey.Curve = secp256k1.S256()
	if 8*len(m.data) != priv.Params().BitSize {
		return nil, fmt.Errorf("invalid length, need %d bits", priv.Params().BitSize)
	}
	priv.D = new(big.Int).SetBytes(m.data)
	if priv.D.Cmp(secp256k1N) >= 0 {
		return nil, fmt.Errorf("invalid private key, >=N")
	}
	// The priv.D must not be zero or negative.
	if priv.D.Sign() <= 0 {
		return nil, fmt.Errorf("invalid private key, zero or negative")
	}

	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(m.data)
	if priv.PublicKey.X == nil {
		return nil, errors.New("invalid private key")
	}
	buf := secp256k1.CompressPubkey(priv.PublicKey.X, priv.PublicKey.Y)
	return &PubKey{data: buf}, nil
}

func (m *PrivKey) ToWIF() string {
	data := m.data
	temp := sha256.Sum256(data)
	temps := sha256.Sum256(temp[:])
	data = append(data, temps[0:4]...)

	bi := new(big.Int).SetBytes(data).String()
	encoded, _ := base58.BitcoinEncoding.Encode([]byte(bi))
	return string(encoded)
}
