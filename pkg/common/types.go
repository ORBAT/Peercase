package common

// Digestables produce digests of themselves
type Digestable interface {
	Digest() []byte
}
