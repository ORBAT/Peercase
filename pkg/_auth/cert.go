package auth

import (
	"bytes"
	"encoding"
	"sort"

	"github.com/ORBAT/Peerdoc/pkg/common"
	"github.com/ORBAT/Peerdoc/pkg/crypto/sign"
)

type Certificate interface {
	common.Hashable
	PublicKey() sign.PublicKey
	Attributes() Attrs
	// Subject returns the subject this certificate covers. Must be a / separated path. Example:
	//  /identity/
	// Subject() string // TODO: get everything from Attributes?
	Fingerprint() sign.Fingerprint
	encoding.TextMarshaler
	encoding.TextUnmarshaler
}

type certDigest struct {
}

type Attrs map[string][]byte

// Bytes turns a into a byte slice of "key1=value,key2=value2,...", sorted by the key
func (a Attrs) Bytes() []byte {
	kvs := make([][]byte, len(a))

	i := 0
	for k, v := range a {
		kvs[i] = append([]byte(k+"="), v...)
		i++
	}

	sort.Slice(kvs, func(i, j int) bool {
		cmp := bytes.Compare(kvs[i], kvs[j])
		if cmp == 0 {
			panic("this should never happen")
		}
		return cmp == -1
	})

	return bytes.Join(kvs, []byte(","))
}

type certificate struct {
}

func (certificate) Digest() []byte {
	panic("implement me")
}

func (certificate) PublicKey() sign.PublicKey {
	panic("implement me")
}

func (certificate) Attributes() map[string][]byte {
	panic("implement me")
}

func (certificate) Fingerprint() sign.Fingerprint {
	panic("implement me")
}

func (certificate) MarshalText() (text []byte, err error) {
	panic("implement me")
}

func (certificate) UnmarshalText(text []byte) error {
	panic("implement me")
}
