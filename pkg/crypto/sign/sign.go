// package sign provides a standardized interface for cryptographic signatures and a default implementation with ECDSA
// with the secp256k1 curve.
package sign

import (
	ec "crypto/ecdsa"
	"encoding"
	"encoding/hex"
	"fmt"
	"math/big"

	eco "github.com/ethereum/go-ethereum/common"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

var hash = ecrypto.Keccak256

type ErrBadSignature struct{}

func (e ErrBadSignature) Error() string {
	return "signature verification error"
}

// IsBadSignature returns true if err is about a bad signature (e.g. ErrBadSignature)
func IsBadSignature(err error) bool {
	type badsigger interface {
		BadSignature() bool
	}

	_, ok := err.(badsigger)
	return ok
}

// BadSignature always returns true for ErrBadSignature.
func (_ ErrBadSignature) BadSignature() bool {
	return true
}

/*
type ErrSignMismatch struct{ Pub, Recovered ethco.Address }

func (e ErrSignMismatch) Error() string {
	return fmt.Sprintf("signature mismatch: key is %s, got %s", e.Pub.String(), e.Recovered.String())
}

// IsSignMismatch returns true if err is about signature mismatch (e.g. ErrSignMismatch)
func IsSignMismatch(err error) bool {
	type mismatcher interface {
		SignMismatch() bool
	}

	_, ok := err.(mismatcher)
	return ok
}

// SignMismatch always returns true for ErrSignMismatch.
func (_ ErrSignMismatch) SignMismatch() bool {
	return true
}
*/

// A Fingerprint uniquely identifies a public signature key
type Fingerprint [eco.AddressLength]byte

func NilFingerprint() Fingerprint {
	return Fingerprint{}
}

func BytesToFingerprint(b []byte) Fingerprint {
	var a Fingerprint
	a.SetBytes(b)
	return a
}

func HexToFingerprint(s string) Fingerprint {
	return Fingerprint(eco.HexToAddress(s))
}

func (fp Fingerprint) IsZero() bool {
	return fp == Fingerprint{}
}

func (fp Fingerprint) String() string { return "0x" + hex.EncodeToString(fp[:]) }

// Sets the address to the value of b. If b is larger than len(a) it will panic
func (a *Fingerprint) SetBytes(b []byte) {
	if len(b) > len(a) {
		b = b[len(b)-eco.AddressLength:]
	}
	copy(a[eco.AddressLength-len(b):], b)
}
func (fp Fingerprint) Bytes() []byte { return fp[:] }
func (fp Fingerprint) Zero() {
	for i := range fp {
		fp[i] = 0
	}
}

// TODO: hash type
//func (fp Fingerprint) Hash() Hash    { return eco.BytesToHash(fp[:]) }

// A Signature represents a signature
type Signature interface {
}

// ECDSASignature is an ECDSA signature
type ECDSASignature []byte

// Values returns the r, s and v values of the ECDSA signature
func (ecSig ECDSASignature) Values() (r, s, v *big.Int) {
	if len(ecSig) != 65 {
		// TODO(ORBAT): error handling
		panic(fmt.Sprintf("wrong size for signature: got %d, want 65", len(ecSig)))
	}
	r = new(big.Int).SetBytes(ecSig[:32])
	s = new(big.Int).SetBytes(ecSig[32:64])
	v = new(big.Int).SetBytes([]byte{ecSig[64] + 27})
	return r, s, v
}

// PublicKey is implemented by public signature keys
type PublicKey interface {
	Fingerprint() Fingerprint
	Verify(sig Signature, message []byte) (err error)
	Compare(f Fingerprint) (ok bool, err error)
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

// ECDSAPublicKey is an ECDSA public key
type ECDSAPublicKey ec.PublicKey

func PubFromECDSA(pk *ec.PublicKey) *ECDSAPublicKey {
	return (*ECDSAPublicKey)(pk)
}

// UnmarshalBinary parses a public key in the 33-byte compressed format.
func (epubk *ECDSAPublicKey) UnmarshalBinary(data []byte) error {
	pub, err := ecrypto.DecompressPubkey(data)
	if err != nil {
		return errors.Wrap(err, "error decompressing public key")
	}

	if pub.X.Cmp(pub.Curve.Params().P) >= 0 {
		return errors.Errorf("decompressed pub key X parameter is >= P")
	}
	if pub.Y.Cmp(pub.Curve.Params().P) >= 0 {
		return errors.Errorf("decompressed pub key Y parameter is >= P")
	}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return errors.Errorf("decompressed pub key isn't on secp256k1 curve")
	}

	*epubk = (ECDSAPublicKey)(*pub)
	return nil
}

// MarshalBinary encodes a public key to the 33-byte compressed format.
func (epubk *ECDSAPublicKey) MarshalBinary() (data []byte, err error) {
	return ecrypto.CompressPubkey(epubk.ECDSA()), nil
}

var _ PublicKey = &ECDSAPublicKey{}

func RecoverPubkey(sig Signature, hash []byte) (PublicKey, error) {
	bs, ok := sig.([]byte)
	if !ok {
		return nil, errors.Errorf("couldn't turn sig into bytes?")
	}

	recoveredPub, err := ecrypto.SigToPub(hash, bs)
	if err != nil {
		return nil, errors.Wrap(err, "error turning signature to public key")
	}

	return PubFromECDSA(recoveredPub), nil
}

// ECDSA returns a standard ecdsa.PublicKey based on this ECDSAPublicKey
func (epubk *ECDSAPublicKey) ECDSA() *ec.PublicKey {
	return (*ec.PublicKey)(epubk)
}

func (epubk *ECDSAPublicKey) Verify(sig Signature, hash []byte) (err error) {
	if len(hash) != 32 {
		return errors.Errorf("hash is required to be exactly 32 bytes (was %d)", len(hash))
	}

	sigBs, ok := sig.([]byte)
	if !ok {
		return errors.Errorf("sig wasn't []byte?")
	}
	sigBs = sigBs[:len(sigBs)-1] // remove the "recovery ID" V Ethereum adds to signatures. TODO: wtf is V used for?
	pkBs, _ := epubk.MarshalBinary()

	if !ecrypto.VerifySignature(pkBs, hash, sigBs) {
		return ErrBadSignature{}
	}
	/*
		recoveredPub, err := ecrypto.SigToPub(hash, sigBs)

		if err != nil {
			return false, errors.Wrap(err, "error turning signature to public key")
		}

		recoveredAddr := ecrypto.PubkeyToAddress(*recoveredPub)
		pubAddress := ecrypto.PubkeyToAddress(*epubk.ECDSA())

		if recoveredAddr != pubAddress {
			err = ErrSignMismatch{pubAddress, recoveredAddr}
			ok = false
		}
	*/

	return
}

func (epubk *ECDSAPublicKey) Fingerprint() (fp Fingerprint) {
	return Fingerprint(ecrypto.PubkeyToAddress(*epubk.ECDSA()))
}

// Compare this public key to a fingerprint
func (epubk *ECDSAPublicKey) Compare(f Fingerprint) (ok bool, err error) {
	panic("wip")
}

type PrivateKey interface {
	PublicKey
	Public() PublicKey
	Sign(msg []byte) Signature
	Derive([]byte) (PrivateKey, error)
}

type ECDSAPrivateKey ec.PrivateKey

var _ PrivateKey = &ECDSAPrivateKey{}

func PrivFromECDSA(pr *ec.PrivateKey) *ECDSAPrivateKey {
	return (*ECDSAPrivateKey)(pr)
}

func (epriv *ECDSAPrivateKey) Compare(f Fingerprint) (ok bool, err error) {
	panic("implement me")
}

func (epriv *ECDSAPrivateKey) Fingerprint() Fingerprint {
	return epriv.Public().Fingerprint()
}

func (epriv *ECDSAPrivateKey) Verify(sig Signature, message []byte) error {
	return epriv.Public().Verify(sig, message)
}

// Sign calculates an ECDSA signature for a given hash. The hash must be exactly 32 bytes.
//
// This function is susceptible to chosen plaintext attacks that can leak information about the private key that is used
// for signing. Callers must be aware that the given hash cannot be chosen by an adversary. Common solution is to hash
// any input before calculating the signature.
func (epriv *ECDSAPrivateKey) Sign(hash []byte) Signature {
	std := epriv.ECDSA()
	sig, err := ecrypto.Sign(hash, std)
	if err != nil {
		panic(err)
	}
	return sig
}

func (epriv *ECDSAPrivateKey) UnmarshalBinary(data []byte) error {
	priv, err := ecrypto.ToECDSA(data)
	*epriv = ECDSAPrivateKey(*priv)
	return err
}

func (epriv *ECDSAPrivateKey) MarshalBinary() (data []byte, err error) {
	return ecrypto.FromECDSA(epriv.ECDSA()), nil
}

// ECDSA returns a standard ecdsa.PrivateKey based on this ECDSAPrivateKey
func (epriv *ECDSAPrivateKey) ECDSA() *ec.PrivateKey {
	return (*ec.PrivateKey)(epriv)
}

func (epriv *ECDSAPrivateKey) Public() PublicKey {
	return (*ECDSAPublicKey)(&epriv.PublicKey)
}

func Generate() (PrivateKey, error) {
	pk, err := ecrypto.GenerateKey()
	if err != nil {
		return nil, err
	}

	return (*ECDSAPrivateKey)(pk), nil
}

func (epriv *ECDSAPrivateKey) Derive(expansion []byte) (PrivateKey, error) {
	tempSK := &ec.PrivateKey{
		PublicKey: ec.PublicKey{
			Curve: epriv.Curve,
			X:     new(big.Int),
			Y:     new(big.Int),
		},
		D: new(big.Int),
	}

	var k = new(big.Int).SetBytes(expansion)
	var one = new(big.Int).SetInt64(1)
	n := new(big.Int).Sub(epriv.Params().N, one)
	k.Mod(k, n)
	k.Add(k, one)

	tempSK.D.Add(epriv.D, k)
	tempSK.D.Mod(tempSK.D, epriv.PublicKey.Params().N)

	// Compute temporary public key
	tempX, tempY := epriv.PublicKey.ScalarBaseMult(k.Bytes())
	tempSK.PublicKey.X, tempSK.PublicKey.Y =
		tempSK.PublicKey.Add(
			epriv.PublicKey.X, epriv.PublicKey.Y,
			tempX, tempY,
		)

	// Verify temporary public key is a valid point on the reference curve
	isOn := tempSK.Curve.IsOnCurve(tempSK.PublicKey.X, tempSK.PublicKey.Y)
	if !isOn {
		return nil, errors.New("failed temporary public key IsOnCurve check.")
	}

	return (*ECDSAPrivateKey)(tempSK), nil
}

/*
func (kd *ecdsaPublicKeyKeyDeriver) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (dk bccsp.Key, err error) {
	// Validate opts
	if opts == nil {
		return nil, errors.New("Invalid opts parameter. It must not be nil.")
	}

	ecdsaK := k.(*ecdsaPublicKey)

	switch opts.(type) {
	// Re-randomized an ECDSA private key
	case *bccsp.ECDSAReRandKeyOpts:
		reRandOpts := opts.(*bccsp.ECDSAReRandKeyOpts)
		tempSK := &ecdsa.PublicKey{
			Curve: ecdsaK.pubKey.Curve,
			X:     new(big.Int),
			Y:     new(big.Int),
		}

		var k = new(big.Int).SetBytes(reRandOpts.ExpansionValue())
		var one = new(big.Int).SetInt64(1)
		n := new(big.Int).Sub(ecdsaK.pubKey.Params().N, one)
		k.Mod(k, n)
		k.Add(k, one)

		// Compute temporary public key
		tempX, tempY := ecdsaK.pubKey.ScalarBaseMult(k.Bytes())
		tempSK.X, tempSK.Y = tempSK.Add(
			ecdsaK.pubKey.X, ecdsaK.pubKey.Y,
			tempX, tempY,
		)

		// Verify temporary public key is a valid point on the reference curve
		isOn := tempSK.Curve.IsOnCurve(tempSK.X, tempSK.Y)
		if !isOn {
			return nil, errors.New("Failed temporary public key IsOnCurve check.")
		}

		return &ecdsaPublicKey{tempSK}, nil
	default:
		return nil, fmt.Errorf("Unsupported 'KeyDerivOpts' provided [%v]", opts)
	}
}
}*/
