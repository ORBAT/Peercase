// package sign provides a standardized interface for cryptographic signatures and a default implementation with ECDSA
// with the secp256k1 curve.
package sign

import (
	ec "crypto/ecdsa"
	"encoding"
	"fmt"
	"math/big"

	ethco "github.com/ethereum/go-ethereum/common"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

var hash = ecrypto.Keccak256

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

// A Fingerprint uniquely identifies a signature key
//
// TODO: move up to crypto pkg
type Fingerprint []byte

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
	Verify(sig Signature, message []byte) (ok bool, err error)
	Compare(f Fingerprint) (ok bool, err error)
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

// ECDSAPublicKey is an ECDSA public key
type ECDSAPublicKey ec.PublicKey

// UnmarshalBinary creates a private key with the given D value
func (epubk *ECDSAPublicKey) UnmarshalBinary(data []byte) error {
	pub := ecrypto.ToECDSAPub(data)
	*epubk = (ECDSAPublicKey)(*pub)
	return nil
}

func (epubk *ECDSAPublicKey) MarshalBinary() (data []byte, err error) {
	return ecrypto.FromECDSAPub(epubk.Std()), nil
}

var _ PublicKey = &ECDSAPublicKey{}

// Std returns a standard ecdsa.PublicKey based on this ECDSAPublicKey
func (epubk *ECDSAPublicKey) Std() *ec.PublicKey {
	return (*ec.PublicKey)(epubk)
}

func (epubk *ECDSAPublicKey) Verify(sig Signature, hash []byte) (ok bool, err error) {
	ok = true
	if len(hash) != 32 {
		panic(fmt.Errorf("hash is required to be exactly 32 bytes (%d)", len(hash)))
	}

	sigBs := sig.([]byte)

	recoveredPub, err := ecrypto.SigToPub(hash, sigBs)

	if err != nil {
		return false, errors.Wrap(err, "error turning signature to public key")
	}

	recoveredAddr := ecrypto.PubkeyToAddress(*recoveredPub)
	pubAddress := ecrypto.PubkeyToAddress(*epubk.Std())

	if recoveredAddr != pubAddress {
		err = ErrSignMismatch{pubAddress, recoveredAddr}
		ok = false
	}

	return
}

func (epubk *ECDSAPublicKey) Fingerprint() (fp Fingerprint) {
	return ecrypto.PubkeyToAddress(*epubk.Std()).Bytes()
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

func (epriv *ECDSAPrivateKey) Compare(f Fingerprint) (ok bool, err error) {
	panic("implement me")
}

func (epriv *ECDSAPrivateKey) Fingerprint() Fingerprint {
	return epriv.Public().Fingerprint()
}

func (epriv *ECDSAPrivateKey) Verify(sig Signature, message []byte) (ok bool, err error) {
	return epriv.Public().Verify(sig, message)
}

// Sign calculates an ECDSA signature for a given hash. The hash must be exactly 32 bytes.
//
// This function is susceptible to chosen plaintext attacks that can leak information about the private key that is used
// for signing. Callers must be aware that the given hash cannot be chosen by an adversary. Common solution is to hash
// any input before calculating the signature.
func (epriv *ECDSAPrivateKey) Sign(hash []byte) Signature {
	std := epriv.Std()
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
	return ecrypto.FromECDSA(epriv.Std()), nil
}

func (epriv *ECDSAPrivateKey) Std() *ec.PrivateKey {
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

// signHash is a helper function that calculates a hash for the given message
// that can be safely used to calculate a signature from.
//
// The hash is calulcated as
//   keccak256("\x19Ethereum Signed Message:\n"${message length}${message}).
//
// This gives context to the signed message and prevents signing of transactions.
func signHash(data []byte) []byte {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return ecrypto.Keccak256([]byte(msg))
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
import "github.com/hyperledger/fabric/bccsp"

func KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (dk bccsp.Key, err error) {
	// Validate opts
	if opts == nil {
		return nil, errors.New("Invalid opts parameter. It must not be nil.")
	}

	ecdsaK := k.(*ecdsaPrivateKey)

	switch opts.(type) {
	// Re-randomized an ECDSA private key
	case *bccsp.ECDSAReRandKeyOpts:
		reRandOpts := opts.(*bccsp.ECDSAReRandKeyOpts)
		tempSK := &ec.PrivateKey{
			PublicKey: ec.PublicKey{
				Curve: epriv.Curve,
				X:     new(big.Int),
				Y:     new(big.Int),
			},
			D: new(big.Int),
		}

		var k = new(big.Int).SetBytes(reRandOpts.ExpansionValue())
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
			return nil, errors.New("Failed temporary public key IsOnCurve check.")
		}

		return &ecdsaPrivateKey{tempSK}, nil
	default:
		return nil, fmt.Errorf("Unsupported 'KeyDerivOpts' provided [%v]", opts)
	}
}*/
