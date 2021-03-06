// package extended implements hierarchical deterministic key generation, i.e. extended keys.
//
// Based on btcsuite's hdkeychain, copyright (c) 2014-2016 The btcsuite developers.
// Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby
// granted, provided that the above copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
// INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
// AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
// PERFORMANCE OF THIS SOFTWARE.
package extended

// References:
//   [BIP32]: BIP0032 - Hierarchical Deterministic Wallets
//   https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ORBAT/Peerdoc/pkg/crypto/sign"
	"github.com/ORBAT/Peerdoc/pkg/crypto/sign/extended/internal"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcutil/base58"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

const (
	// RecommendedSeedLen is the recommended length in bytes for a seed
	// to a master node.
	RecommendedSeedLen = 64 // 512 bits

	// HardenedKeyStart is the index at which a hardended key starts.  Each
	// extended key has 2^31 normal child keys and 2^31 hardned child keys.
	// Thus the range for normal child keys is [0, 2^31 - 1] and the range
	// for hardened child keys is [2^31, 2^32 - 1].
	HardenedKeyStart = 0x80000000 // 2^31

	// MinSeedBytes is the minimum number of bytes allowed for a seed to
	// a master node.
	MinSeedBytes = 16 // 128 bits

	// MaxSeedBytes is the maximum number of bytes allowed for a seed to
	// a master node.
	MaxSeedBytes = 64 // 512 bits

	// serializedKeyLen is the length of a serialized public or private
	// extended key.  It consists of 4 bytes version, 1 byte depth, 20 bytes
	// fingerprint, 4 bytes child number, 32 bytes chain code, and 33 bytes
	// public/private key data.
	serializedKeyLen = 4 + 1 + 20 + 4 + 32 + 33 // 94 bytes

	// maxUint8 is the max positive integer which can be serialized in a uint8
	maxUint8 = 1<<8 - 1
)

// PrivateKeyVer returns private key version bytes. When base58-encoded, each private key starts with PPRV
func PrivateKeyVer() [4]byte {
	// Prefix PPRV, bs [193 122 176 214] (3246043351)
	return [...]byte{0xc1, 0x7a, 0xb0, 0xd6}
}

// PublicKeyVer returns public key version bytes. When base58-encoded, each public key starts with PPUB
func PublicKeyVer() [4]byte {
	// Prefix PPUB, bs [193 124 117 179] (3246159284)
	return [...]byte{0xc1, 0x7c, 0x75, 0xb3}
}

var (
	// ErrDeriveHardFromPublic describes an error in which the caller
	// attempted to derive a hardened extended key from a public key.
	ErrDeriveHardFromPublic = errors.New("cannot derive a hardened key " +
		"from a public key")

	// ErrDeriveBeyondMaxDepth describes an error in which the caller
	// has attempted to derive more than 255 keys from a root key.
	ErrDeriveBeyondMaxDepth = errors.New("cannot derive a key with more than " +
		"255 indices in its path")

	// ErrNotPrivExtKey describes an error in which the caller attempted
	// to extract a private key from a public extended key.
	ErrNotPrivExtKey = errors.New("unable to create private keys from a " +
		"public extended key")

	// ErrInvalidChild describes an error in which the child at a specific
	// index is invalid due to the derived key falling outside of the valid
	// range for secp256k1 private keys.  This error indicates the caller
	// should simply ignore the invalid child extended key at this index and
	// increment to the next index.
	ErrInvalidChild = errors.New("the extended key at this index is invalid")

	// ErrUnusableSeed describes an error in which the provided seed is not
	// usable due to the derived key falling outside of the valid range for
	// secp256k1 private keys.  This error indicates the caller must choose
	// another seed.
	ErrUnusableSeed = errors.New("unusable seed")

	// ErrInvalidSeedLen describes an error in which the provided seed or
	// seed length is not in the allowed range.
	ErrInvalidSeedLen = fmt.Errorf("seed length must be between %d and %d "+
		"bits", MinSeedBytes*8, MaxSeedBytes*8)

	// ErrBadChecksum describes an error in which the checksum encoded with
	// a serialized extended key does not match the calculated value.

	// ErrInvalidKeyLen describes an error in which the provided serialized
	// key is not the expected length.
	ErrInvalidKeyLen = errors.New("the provided serialized extended key " +
		"length is invalid")
)

// masterKey is the master key used along with a random seed used to generate
// the master node in the hierarchical tree.
var masterKey = []byte("Peerdoc seed")

// Key houses all the information needed to support a hierarchical
// deterministic extended key.  See the package overview documentation for
// more details on how to use extended keys.
type Key struct {
	key       []byte // This will be the pubkey for extended pub keys
	pubKey    []byte // This will only be set for extended priv keys
	chainCode []byte
	depth     uint8
	parentFP  sign.Fingerprint
	childNum  uint32
	version   [4]byte
	isPrivate bool
}

// NewKey returns a new instance of an extended key with the given
// fields.  No error checking is performed here as it's only intended to be a
// convenience method used to create a populated struct. This function should
// only by used by applications that need to create custom ExtendedKeys. All
// other applications should just use NewMaster, Child, or Neuter.
func NewKey(version [4]byte, key, chainCode []byte, parentFP sign.Fingerprint, depth uint8,
	childNum uint32, isPrivate bool) *Key {

	// NOTE: The pubKey field is intentionally left nil so it is only
	// computed and memoized as required.
	return &Key{
		key:       key,
		chainCode: chainCode,
		depth:     depth,
		parentFP:  parentFP,
		childNum:  childNum,
		version:   version,
		isPrivate: isPrivate,
	}
}

// pubKeyBytes returns bytes for the serialized compressed public key associated
// with this extended key in an efficient manner including memoization as
// necessary.
//
// When the extended key is already a public key, the key is simply returned as
// is since it's already in the correct form.  However, when the extended key is
// a private key, the public key will be calculated and memoized so future
// accesses can simply return the cached result.
func (k *Key) pubKeyBytes() []byte {
	// Just return the key if it's already an extended public key.
	if !k.isPrivate {
		return k.key
	}

	// This is a private extended key, so calculate and memoize the public
	// key if needed.
	if len(k.pubKey) == 0 {
		pkx, pky := ecrypto.S256().ScalarBaseMult(k.key)
		pubKey := sign.PubFromECDSA(&ecdsa.PublicKey{Curve: ecrypto.S256(), X: pkx, Y: pky})
		// TODO(ORBAT): right now MarshalBinary never fails, so this is safe-ish, but this should probably be handled
		k.pubKey, _ = pubKey.MarshalBinary()
	}

	return k.pubKey
}

// IsPrivate returns whether or not the extended key is a private extended key.
//
// A private extended key can be used to derive both hardened and non-hardened
// child private and public extended keys.  A public extended key can only be
// used to derive non-hardened child public extended keys.
func (k *Key) IsPrivate() bool {
	return k.isPrivate
}

// Depth returns the current derivation level with respect to the root.
//
// The root key has depth zero, and the field has a maximum of 255 due to
// how depth is serialized.
func (k *Key) Depth() uint8 {
	return k.depth
}

// ParentFingerprint returns a fingerprint of the parent extended key from which
// this one was derived.
func (k *Key) ParentFingerprint() sign.Fingerprint {
	return k.parentFP
}

// Child returns a derived child extended key at the given index.  When this
// extended key is a private extended key (as determined by the IsPrivate
// function), a private extended key will be derived.  Otherwise, the derived
// extended key will be also be a public extended key.
//
// When the index is greater to or equal than the HardenedKeyStart constant, the
// derived extended key will be a hardened extended key.  It is only possible to
// derive a hardended extended key from a private extended key.  Consequently,
// this function will return ErrDeriveHardFromPublic if a hardened child
// extended key is requested from a public extended key.
//
// A hardened extended key is useful since, as previously mentioned, it requires
// a parent private extended key to derive.  In other words, normal child
// extended public keys can be derived from a parent public extended key (no
// knowledge of the parent private key) whereas hardened extended keys may not
// be.
//
// NOTE: There is an extremely small chance (< 1 in 2^127) the specific child
// index does not derive to a usable child.  The ErrInvalidChild error will be
// returned if this should occur, and the caller is expected to ignore the
// invalid child and simply increment to the next index.
func (k *Key) Child(i uint32) (*Key, error) {
	// Prevent derivation of children beyond the max allowed depth.
	if k.depth == maxUint8 {
		return nil, ErrDeriveBeyondMaxDepth
	}

	// There are four scenarios that could happen here:
	// 1) Private extended key -> Hardened child private extended key
	// 2) Private extended key -> Non-hardened child private extended key
	// 3) Public extended key -> Non-hardened child public extended key
	// 4) Public extended key -> Hardened child public extended key (INVALID!)

	// Case #4 is invalid, so error out early.
	// A hardened child extended key may not be created from a public
	// extended key.
	isChildHardened := i >= HardenedKeyStart
	if !k.isPrivate && isChildHardened {
		return nil, ErrDeriveHardFromPublic
	}

	// The data used to derive the child key depends on whether or not the
	// child is hardened per [BIP32].
	//
	// For hardened children:
	//   0x00 || ser256(parentKey) || ser32(i)
	//
	// For normal children:
	//   serP(parentPubKey) || ser32(i)
	keyLen := 33
	data := make([]byte, keyLen+4)
	if isChildHardened {
		// Case #1.
		// When the child is a hardened child, the key is known to be a
		// private key due to the above early return.  Pad it with a
		// leading zero as required by [BIP32] for deriving the child.
		copy(data[1:], k.key)
	} else {
		// Case #2 or #3.
		// This is either a public or private extended key, but in
		// either case, the data which is used to derive the child key
		// starts with the secp256k1 compressed public key bytes.
		copy(data, k.pubKeyBytes())
	}
	binary.BigEndian.PutUint32(data[keyLen:], i)

	// Take the HMAC-SHA512 of the current key's chain code and the derived
	// data:
	//   I = HMAC-SHA512(Key = chainCode, Data = data)
	hmac512 := hmac.New(sha512.New, k.chainCode)
	hmac512.Write(data)
	ilr := hmac512.Sum(nil)

	// Split "I" into two 32-byte sequences Il and Ir where:
	//   Il = intermediate key used to derive the child
	//   Ir = child chain code
	il := ilr[:len(ilr)/2]
	childChainCode := ilr[len(ilr)/2:]

	// Both derived public or private keys rely on treating the left 32-byte
	// sequence calculated above (Il) as a 256-bit integer that must be
	// within the valid range for a secp256k1 private key.  There is a small
	// chance (< 1 in 2^127) this condition will not hold, and in that case,
	// a child extended key can't be created for this index and the caller
	// should simply increment to the next index.
	ilNum := new(big.Int).SetBytes(il)
	if ilNum.Cmp(ecrypto.S256().Params().N) >= 0 || ilNum.Sign() == 0 {
		return nil, ErrInvalidChild
	}

	// The algorithm used to derive the child key depends on whether or not
	// a private or public child is being derived.
	//
	// For private children:
	//   childKey = parse256(Il) + parentKey
	//
	// For public children:
	//   childKey = serP(point(parse256(Il)) + parentKey)
	var isPrivate bool
	var childKey []byte
	if k.isPrivate {
		// Case #1 or #2.
		// Add the parent private key to the intermediate private key to
		// derive the final child key.
		//
		// childKey = parse256(Il) + parenKey
		keyNum := new(big.Int).SetBytes(k.key)
		ilNum.Add(ilNum, keyNum)
		ilNum.Mod(ilNum, ecrypto.S256().Params().N)
		childKey = ilNum.Bytes()
		isPrivate = true
	} else {
		// Case #3.
		// Calculate the corresponding intermediate public key for
		// intermediate private key.
		ilx, ily := ecrypto.S256().ScalarBaseMult(il)
		if ilx.Sign() == 0 || ily.Sign() == 0 {
			return nil, ErrInvalidChild
		}

		// Convert the serialized compressed parent public key into X
		// and Y coordinates so it can be added to the intermediate
		// public key.
		var pubKey sign.ECDSAPublicKey
		err := pubKey.UnmarshalBinary(k.key)
		if err != nil {
			return nil, err
		}

		// Add the intermediate public key to the parent public key to
		// derive the final child key.
		//
		// childKey = serP(point(parse256(Il)) + parentKey)
		childX, childY := ecrypto.S256().Add(ilx, ily, pubKey.X, pubKey.Y)
		pk := sign.PubFromECDSA(&ecdsa.PublicKey{Curve: ecrypto.S256(), X: childX, Y: childY})

		// TODO(ORBAT): right now MarshalBinary never fails, so this is safe-ish, but this should probably be handled
		childKey, _ = pk.MarshalBinary()
	}

	// The fingerprint of the parent for the derived child is the first 4
	// bytes of the RIPEMD160(SHA256(parentPubKey)).
	pk, err := k.ECPubKey()
	if err != nil {
		return nil, errors.Wrap(err, "error getting parent signature")
	}
	return NewKey(k.version, childKey, childChainCode, pk.Fingerprint(),
		k.depth+1, i, isPrivate), nil
}

// Neuter returns a new extended public key from this extended private key.  The
// same extended key will be returned unaltered if it is already an extended
// public key.
//
// As the name implies, an extended public key does not have access to the
// private key, so it is not capable of signing transactions or deriving
// child extended private keys.  However, it is capable of deriving further
// child extended public keys.
func (k *Key) Neuter() (*Key, error) {
	// Already an extended public key.
	if !k.isPrivate {
		return k, nil
	}

	// Get the associated public extended key version bytes.
	// Convert it to an extended public key.  The key for the new extended
	// key will simply be the pubkey of the current extended private key.
	//
	// This is the function N((k,c)) -> (K, c) from [BIP32].
	return NewKey(PublicKeyVer(), k.pubKeyBytes(), k.chainCode, k.parentFP,
		k.depth, k.childNum, false), nil
}

// ECPubKey converts the extended key to a public signature key and returns it.
func (k *Key) ECPubKey() (sign.PublicKey, error) {
	// TODO(ORBAT): memoize!
	pk := new(sign.ECDSAPublicKey)
	err := pk.UnmarshalBinary(k.pubKeyBytes())
	return pk, err
}

// ECPrivKey converts the extended key to a private signature key and returns it. As you might imagine this is only
// possible if the extended key is a private extended key (as determined by the IsPrivate function).  The
// ErrNotPrivExtKey error will be returned if this function is called on a public extended key.
func (k *Key) ECPrivKey() (sign.PrivateKey, error) {
	if !k.isPrivate {
		return nil, ErrNotPrivExtKey
	}
	pr := new(sign.ECDSAPrivateKey)
	err := pr.UnmarshalBinary(k.key)
	return pr, err
}

// MaybeFingerprint returns the fingerprint for this key, or an error if unsuccessful.
func (k *Key) MaybeFingerprint() (sign.Fingerprint, error) {
	// TODO(ORBAT): memoize!
	pk, err := k.ECPubKey()
	if err != nil {
		return sign.NilFingerprint(), errors.Wrap(err, "error getting public key from extended key")
	}
	return pk.Fingerprint(), nil
}

// Fingerprint returns this key's fingerprint. If it fails, it will panic. See MaybeFingerprint.
func (k *Key) Fingerprint() sign.Fingerprint {
	fp, err := k.MaybeFingerprint()
	if err != nil {
		panic(err)
	}
	return fp
}

// paddedAppend appends the src byte slice to dst, returning the new slice.
// If the length of the source is smaller than the passed size, leading zero
// bytes are appended to the dst slice before appending src.
func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}

// String returns the extended key as a human-readable base58-encoded string.
func (k *Key) String() string {
	if len(k.key) == 0 {
		return "zeroed extended key"
	}
	return base58.Encode(k.Bytes())
}

// zero sets all bytes in the passed slice to zero.  This is used to
// explicitly clear private key material from memory.
func zero(b []byte) {
	lenb := len(b)
	for i := 0; i < lenb; i++ {
		b[i] = 0
	}
}

// Zero manually clears all fields and bytes in the extended key.  This can be
// used to explicitly clear key material from memory for enhanced security
// against memory scraping.  This function only clears this particular key and
// not any children that have already been derived.
func (k *Key) Zero() {
	zero(k.key)
	zero(k.pubKey)
	zero(k.chainCode)
	k.parentFP.Zero()
	k.version = [4]byte{}
	k.key = nil
	k.depth = 0
	k.childNum = 0
	k.isPrivate = false
}

// Bytes returns a binary representation of the Key
func (k *Key) Bytes() []byte {
	var childNumBytes [4]byte
	binary.BigEndian.PutUint32(childNumBytes[:], k.childNum)

	// The serialized format is:
	//   version (4) || depth (1) || parent fingerprint (20)) ||
	//   child num (4) || chain code (32) || key data (33) || checksum (4)
	serializedBytes := make([]byte, 0, serializedKeyLen+4)
	serializedBytes = append(serializedBytes, k.version[:]...)
	serializedBytes = append(serializedBytes, k.depth)
	serializedBytes = append(serializedBytes, k.parentFP.Bytes()...)
	serializedBytes = append(serializedBytes, childNumBytes[:]...)
	serializedBytes = append(serializedBytes, k.chainCode...)
	if k.isPrivate {
		serializedBytes = append(serializedBytes, 0x00)
		serializedBytes = paddedAppend(32, serializedBytes, k.key)
	} else {
		serializedBytes = append(serializedBytes, k.pubKeyBytes()...)
	}

	checkSum := chainhash.DoubleHashB(serializedBytes)[:4]
	return append(serializedBytes, checkSum...)
}

func (k *Key) toWire() *internal.WireFmt {
	w := &internal.WireFmt{
		Version:  k.version,
		Depth:    k.depth,
		ParentFP: k.parentFP,
	}
	// childnum, chainCode, keydata
	binary.BigEndian.PutUint32(w.ChildNum[:], k.childNum)
	copy(w.ChainCode[:], k.chainCode)
	panic("WIP")
	if k.isPrivate {
		// TODO: priv key + padding
	} else {
		// TODO: pubKeyBytes
	}
	return w
}

// NewMaster creates a new master node for use in creating a hierarchical
// deterministic key chain.  The seed must be between 128 and 512 bits and
// should be generated by a cryptographically secure random generation source.
//
// NOTE: There is an extremely small chance (< 1 in 2^127) the provided seed
// will derive to an unusable secret key.  The ErrUnusable error will be
// returned if this should occur, so the caller must check for it and generate a
// new seed accordingly.
func NewMaster(seed []byte) (*Key, error) {
	// Per [BIP32], the seed must be in range [MinSeedBytes, MaxSeedBytes].
	if len(seed) < MinSeedBytes || len(seed) > MaxSeedBytes {
		return nil, ErrInvalidSeedLen
	}

	// First take the HMAC-SHA512 of the master key and the seed data:
	//   I = HMAC-SHA512(Key = "Peerdoc seed", Data = S)
	hmac512 := hmac.New(sha512.New, masterKey)
	hmac512.Write(seed)
	lr := hmac512.Sum(nil)

	// Split "I" into two 32-byte sequences Il and Ir where:
	//   Il = master secret key
	//   Ir = master chain code
	secretKey := lr[:len(lr)/2]
	chainCode := lr[len(lr)/2:]

	// Ensure the key in usable.
	secretKeyNum := new(big.Int).SetBytes(secretKey)
	if secretKeyNum.Cmp(ecrypto.S256().Params().N) >= 0 || secretKeyNum.Sign() == 0 {
		return nil, ErrUnusableSeed
	}

	parentFP := sign.NilFingerprint()
	return NewKey(PrivateKeyVer(), secretKey, chainCode,
		parentFP, 0, 0, true), nil
}

func NewKeyFromBytes(bs []byte) (*Key, error) {
	if len(bs) != serializedKeyLen+4 {
		return nil, ErrInvalidKeyLen
	}

	//w := internal.WireFmt{}
	//if err := w.UnmarshalBinary(bs); err != nil {
	//	return nil, errors.Wrap(err, "error unmarshaling key bytes")
	//}

	// The serialized format is:
	//   version (4) || depth (1) || parent fingerprint (20)) ||
	//   child num (4) || chain code (32) || key data (33) || checksum (4)

	// Split the payload and checksum up and ensure the checksum matches.
	payload := bs[:len(bs)-4]
	checkSum := bs[len(bs)-4:]
	expectedCheckSum := chainhash.DoubleHashB(payload)[:4]
	if !bytes.Equal(checkSum, expectedCheckSum) {
		return nil, errors.New("bad extended key checksum")
	}

	// Deserialize each of the payload fields.
	var version [4]byte
	copy(version[:], payload[:4])
	depth := payload[4:5][0]
	parentFPbs := payload[5:25] // orig 5:9 == 4
	var parentFP sign.Fingerprint
	if err := parentFP.SetBytes(parentFPbs); err != nil {
		return nil, errors.Wrap(err, "parent sig malformed")
	}
	childNum := binary.BigEndian.Uint32(payload[25:29]) // orig 9:13 == 4
	chainCode := payload[29:61]                         // orig 13:45 == 32
	keyData := payload[61:94]                           // orig 45:78 == 33

	// The key data is a private key if it starts with 0x00.  Serialized
	// compressed pubkeys either start with 0x02 or 0x03.
	isPrivate := keyData[0] == 0x00
	if isPrivate {
		// Ensure the private key is valid.  It must be within the range
		// of the order of the secp256k1 curve and not be 0.
		keyData = keyData[1:]
		keyNum := new(big.Int).SetBytes(keyData)
		if keyNum.Cmp(ecrypto.S256().Params().N) >= 0 || keyNum.Sign() == 0 {
			return nil, ErrUnusableSeed
		}
	} else {
		// Ensure the public key parses correctly and is actually on the
		// secp256k1 curve.
		var pk sign.ECDSAPublicKey
		err := pk.UnmarshalBinary(keyData)
		if err != nil {
			return nil, err
		}
	}

	return NewKey(version, keyData, chainCode, parentFP, depth,
		childNum, isPrivate), nil
}

// TODO(ORBAT): UnmarshalText/MarshalText for Key

// NewKeyFromString returns a new extended key instance from a base58-encoded
// extended key.
func NewKeyFromString(key string) (*Key, error) {
	// The base58-decoded extended key must consist of a serialized payload
	// plus an additional 4 bytes for the checksum.
	return NewKeyFromBytes(base58.Decode(key))
}

// GenerateSeed returns a cryptographically secure random seed that can be used
// as the input for the NewMaster function to generate a new master node.
//
// The length is in bytes and it must be between 16 and 64 (128 to 512 bits).
// The recommended length is 32 (256 bits) as defined by the RecommendedSeedLen
// constant.
func GenerateSeed(length uint8) ([]byte, error) {
	// Per [BIP32], the seed must be in range [MinSeedBytes, MaxSeedBytes].
	if length < MinSeedBytes || length > MaxSeedBytes {
		return nil, ErrInvalidSeedLen
	}

	buf := make([]byte, length)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

// SeedToHex returns a hexadecimal representation of s
func SeedToHex(s []byte) string {
	return hex.EncodeToString(s)
}
