package storage

import "github.com/attic-labs/noms/go/datas"

// Pubkey provides a public key store
type Pubkey struct {
	ds datas.Dataset
}
