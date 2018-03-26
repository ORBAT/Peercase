package crypto

import ecrypto "github.com/ethereum/go-ethereum/crypto"

func Hash(msg []byte) []byte {
	return ecrypto.Keccak256(msg)
}

// TODO: don't return a raw byte slice, but something like go-ethereum's common.Hash
