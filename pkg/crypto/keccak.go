package crypto

import (
	"github.com/ORBAT/Peerdoc/pkg/common"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
)

func Hash(msg []byte) common.Hash {
	return common.BytesToHash(ecrypto.Keccak256(msg))
}

// TODO: don't return a raw byte slice, but something like go-ethereum's common.Hash
