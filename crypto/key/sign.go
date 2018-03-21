package key

import (
	ec "crypto/ecdsa"
	"encoding"
	"fmt"
	"math/big"

	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

var hash = ecrypto.Keccak256

type ErrSignatureKeyMismatch struct{ Pub, Recovered string }

func (e ErrSignatureKeyMismatch) Error() string {
	return fmt.Sprintf("signature key mismatch: %s != %s", e.Pub, e.Recovered)
}

// A Fingerprint identifies something
type Fingerprint []byte

// Signature represents a generic cryptographic signature
type Signature interface {
}

type ECDSASignature []byte

// Values returns the r, s and v values of the ECDSA signature
func (ecSig ECDSASignature) Values() (r, s, v *big.Int) {
	if len(ecSig) != 65 {
		panic(fmt.Sprintf("wrong size for signature: got %d, want 65", len(ecSig)))
	}
	r = new(big.Int).SetBytes(ecSig[:32])
	s = new(big.Int).SetBytes(ecSig[32:64])
	v = new(big.Int).SetBytes([]byte{ecSig[64] + 27})
	return r, s, v
}

type Public interface {
	Fingerprint() Fingerprint
	Verify(sig Signature, message []byte) (ok bool, err error)
	Compare(f Fingerprint) (ok bool, err error)
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

type ECDSAPublic ec.PublicKey

// UnmarshalBinary creates a private key with the given D value
func (epubk *ECDSAPublic) UnmarshalBinary(data []byte) error {
	pub := ecrypto.ToECDSAPub(data)
	*epubk = (ECDSAPublic)(*pub)
	return nil
}

func (epubk *ECDSAPublic) MarshalBinary() (data []byte, err error) {
	return ecrypto.FromECDSAPub(epubk.Std()), nil
}

var _ Public = &ECDSAPublic{}

func (epubk *ECDSAPublic) Std() *ec.PublicKey {
	return (*ec.PublicKey)(epubk)
}

func (epubk *ECDSAPublic) Verify(sig Signature, message []byte) (ok bool, err error) {
	digest := hash(message)
	ok = true
	if len(digest) != 32 {
		panic(fmt.Errorf("digest is required to be exactly 32 bytes (%d)", len(digest)))
	}
	sigBs := sig.([]byte)

	recoveredPub, err := ecrypto.SigToPub(digest, sigBs)

	if err != nil {
		return false, errors.Wrap(err, "error turning signature to public key")
	}

	recoveredAddr := ecrypto.PubkeyToAddress(*recoveredPub)
	pubAddress := ecrypto.PubkeyToAddress(*epubk.Std())

	if recoveredAddr != pubAddress {
		err = ErrSignatureKeyMismatch{pubAddress.String(), recoveredAddr.String()}
		ok = false
	}

	return
}

func (epubk *ECDSAPublic) Fingerprint() (fp Fingerprint) {
	return ecrypto.PubkeyToAddress(*epubk.Std()).Bytes()
}

// Compare this public key to a fingerprint
func (epubk *ECDSAPublic) Compare(f Fingerprint) (ok bool, err error) {
	panic("wip")
}

type Private interface {
	Public
	Public() Public
	Sign(msg []byte) Signature
	Derive([]byte) (Private, error)
}

type ECDSAPrivate ec.PrivateKey

var _ Private = &ECDSAPrivate{}

func (epriv *ECDSAPrivate) Compare(f Fingerprint) (ok bool, err error) {
	panic("implement me")
}

func (epriv *ECDSAPrivate) Fingerprint() Fingerprint {
	return epriv.Public().Fingerprint()
}

func (epriv *ECDSAPrivate) Verify(sig Signature, message []byte) (ok bool, err error) {
	return epriv.Public().Verify(sig, message)
}

func (epriv *ECDSAPrivate) Sign(msg []byte) Signature {
	h := hash(msg)
	std := epriv.Std()
	sig, err := ecrypto.Sign(h, std)
	if err != nil {
		panic(err)
	}
	return sig
}

func (epriv *ECDSAPrivate) UnmarshalBinary(data []byte) error {
	priv, err := ecrypto.ToECDSA(data)
	*epriv = ECDSAPrivate(*priv)
	return err
}

func (epriv *ECDSAPrivate) MarshalBinary() (data []byte, err error) {
	return ecrypto.FromECDSA(epriv.Std()), nil
}

func (epriv *ECDSAPrivate) Std() *ec.PrivateKey {
	return (*ec.PrivateKey)(epriv)
}

func (epriv *ECDSAPrivate) Public() Public {
	return (*ECDSAPublic)(&epriv.PublicKey)
}

func Generate() (Private, error) {
	pk, err := ecrypto.GenerateKey()
	if err != nil {
		return nil, err
	}

	return (*ECDSAPrivate)(pk), nil
}

func (epriv *ECDSAPrivate) Derive(expansion []byte) (Private, error) {
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
		return nil, errors.New("Failed temporary public key IsOnCurve check.")
	}

	return (*ECDSAPrivate)(tempSK), nil
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
