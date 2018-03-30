package common

// A Hashable can produce a hash of itself
type Hashable interface {
	Hash() []byte
}

// TODO: hash type
