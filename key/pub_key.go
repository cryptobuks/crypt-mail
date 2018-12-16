package key

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"github.com/itchyny/base58-go"
	"math/big"
	"strings"
)

const (
	SYMBOL string = "CM"
)

type PubKey struct {
	data []byte
}

func PubKeyFromWIF(encoded string) (*PubKey, error) {
	if encoded == "" {
		return nil, errors.New("invalid pub key")
	}

	if len(encoded) < len(SYMBOL) {
		return nil, errors.New("pub key too short")
	}

	if !strings.HasPrefix(encoded, SYMBOL) {
		return nil, errors.New("not a crypt mail pub key")
	}
	buffer := []byte(encoded)[2:]
	encoding := base58.BitcoinEncoding
	decoded, err := encoding.Decode(buffer)
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
		return nil, errors.New("invalid pub key length")
	}

	realKey := buf[:length-4]

	checksum := sha256.Sum256(sha256.Sum256(realKey)[:])

	if !bytes.Equal(checksum[0:4], buf[length-4:]) {
		return nil, errors.New("checksum unmatched")
	}

	return &PubKey{data: realKey}, nil
}
