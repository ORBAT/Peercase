package hash

import (
	"encoding/base32"
	"fmt"
	"regexp"
	"strconv"

	"github.com/pkg/errors"
)

const (
	// ByteLen is the length of a Hash in bytes. It should be the same as noms's hash.ByteLen.
	ByteLen = 20

	// StringLen is the number of characters a Hash takes when turned into a string
	StringLen = 32
)

// TODO(ORBAT): support different hash lengths and formats?
// Ethereum's crypto stuff expects 32 bytes, and Noms wants 20 bytes.

// A Hashable can either produce a hash of itself, or is already a hash
type Hashable interface {
	Hash() Hash
}

// A Hash represents a hash with ByteLen bytes
type Hash [ByteLen]byte

// From turns b into a Hash. If len(b) != ByteLen, From will return an error
func From(b []byte) (h Hash, err error) {
	bl := len(b)
	if bl != ByteLen {
		return h, errors.Errorf("can't convert %d bytes to a Hash, need %d", bl, ByteLen)
	}
	copy(h[:], b)
	return
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

func IsHash(str string) bool {
	return pattern.FindString(str) != ""
}

// UnmarshalText parses a string hash
func (h *Hash) UnmarshalText(input []byte) error {
	str := string(input)
	match := pattern.FindString(str)
	if match == "" {
		return errors.Errorf(`"%s" is not a valid hash string`, str)
	}
	bs, err := encoding.DecodeString(str)
	if err != nil {
		return errors.Wrap(err, "error decoding input")
	}
	*h, err = From(bs)
	return err
}

// Parse a string as a Hash. Same as UnmarshalText
func Parse(str string) (h Hash, err error) {
	err = h.UnmarshalText([]byte(str))
	return
}

// MarshalText returns the string representation of h. Same as h.String()
func (h Hash) MarshalText() ([]byte, error) {
	return []byte(h.String()), nil
}

// Sets h to other
func (h *Hash) Set(other Hash) {
	for i, v := range other {
		h[i] = v
	}
}
