package key

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

func generateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
}

func GenerateKey() (*PrivKey, error) {
	sigKey, err := generateKey()
	if err != nil {
		return nil, errors.New("generate key failed")
	}
	r := &PrivKey{data: math.PaddedBigBytes(sigKey.D, sigKey.Params().BitSize/8)}
	return r, nil
}
