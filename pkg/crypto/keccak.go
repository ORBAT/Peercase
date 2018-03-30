package crypto

import (
	"hash"

	"github.com/ORBAT/Peerdoc/pkg/common"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/sha3"
)

func NewHash() hash.Hash {
	return sha3.New256()
}

func Hash(msg []byte) common.Hash {
	return common.BytesToHash(ecrypto.Keccak256(msg))
}

// TODO: don't return a raw byte slice, but something like go-ethereum's common.Hash
