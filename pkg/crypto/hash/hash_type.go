package hash

import (
	"encoding/base32"
	"fmt"
	"regexp"
	"strconv"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/pkg/errors"
)

const (
	// ByteLen is the length of a Hash in bytes. It should be the same as noms's hash.ByteLen.
	ByteLen = 20

	// StringLen is the number of characters a Hash takes when turned into a string
	StringLen = 32
)

// TODO(ORBAT): support different hash lengths and formats? Ethereum's crypto stuff expects 32 bytes, and Noms wants 20
// bytes.

// A Hashable can either produce a hash of itself, or is already a hash
type Hashable interface {
	Hash() Hash
}

// A Hash represents a hash with ByteLen bytes
type Hash [ByteLen]byte

// From turns b into a Hash. If len(b) != ByteLen, From will panic
func From(b []byte) Hash {
	bl := len(b)
	if bl != ByteLen {
		panic(errors.Errorf("can't convert %d bytes to a Hash, need %d", bl, ByteLen))
	}
	var h Hash
	copy(h[:], b)
	return h
}

func (h Hash) Bytes() []byte { return h[:] }

// Hash implements Hashable since it's already a hash
func (h Hash) Hash() Hash { return h }

var (
	encoding = base32.NewEncoding("0123456789abcdefghijklmnopqrstuv")
	pattern  = regexp.MustCompile("^([0-9a-v]{" + strconv.Itoa(StringLen) + "})$")
)

// String turns the Hash into a string representation
func (h Hash) String() string {
	return encoding.EncodeToString(h[:])
}

// Format implements fmt.Formatter, forcing the byte slice to be formatted as is,
// without going through the stringer interface used for logging.
func (h Hash) Format(s fmt.State, c rune) {
	fmt.Fprintf(s, "%"+string(c), h[:])
}

// UnmarshalText parses a string hash
func (h *Hash) UnmarshalText(input []byte) error {
	str := string(input)
	match := pattern.FindStringSubmatch(str)
	if match == nil {
		return errors.Errorf(`"%s" is not a valid hash string`, str)
	}
	bs, err := encoding.DecodeString(str)
	if err != nil {
		return errors.Wrap(err, "error decoding input")
	}
	*h = From(bs)
	return nil
}

// MarshalText returns the hex representation of h.
func (h Hash) MarshalText() ([]byte, error) {
	return hexutil.Bytes(h[:]).MarshalText()
}

// Sets h to other
func (h *Hash) Set(other Hash) {
	for i, v := range other {
		h[i] = v
	}
}
func NilHash() Hash {
	return Hash{}
}

func EmptyHash(h Hash) bool {
	return h == Hash{}
}
