package hash

import (
	"crypto/sha512"
	"hash"
)

func New() hash.Hash {
	return sha512.New()
}

// Of calculates the hash of data
func Of(data []byte) (h Hash) {
	raw := sha512.Sum512(data)
	copy(h[:], raw[:ByteLen])
	return h
}
