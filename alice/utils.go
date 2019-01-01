package alice

import (
	"math/rand"
	"time"
)

func GenerateUUID() uint64 {
	return uint64(time.Now().Unix()*1e9) + uint64(rand.Intn(1e6))
}

func selectAESAlgorithm(length int) string {
	switch length {
	case 16:
		return "AES-128"
	case 24:
		return "AES-192"
	case 32:
		return "AES-256"
	default:
		break
	}
	return "UNKNOWN"
}
