package key

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testMsg = []byte("bla bla bla")

func mustGenKey() Private {
	if k, err := Generate(); err != nil {
		panic(err)
	} else {
		return k
	}
}

var testAddrHex = "970e8128ab834e8eac17ab8e3812f010678cf791"
var testPrivHex = "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032"

func TestBla(t *testing.T) {
	key, _ := crypto.HexToECDSA(testPrivHex)

	addr := common.HexToAddress(testAddrHex)

	msg := crypto.Keccak256([]byte("foo"))
	sig, err := crypto.Sign(msg, key)
	if err != nil {
		t.Errorf("Sign error: %s", err)
	}
	recoveredPub, err := crypto.Ecrecover(msg, sig)
	if err != nil {
		t.Errorf("ECRecover error: %s", err)
	}
	pubKey := crypto.ToECDSAPub(recoveredPub)
	recoveredAddr := crypto.PubkeyToAddress(*pubKey)
	if addr != recoveredAddr {
		t.Errorf("Address mismatch: want: %x have: %x", addr, recoveredAddr)
	}

	// should be equal to SigToPub
	recoveredPub2, err := crypto.SigToPub(msg, sig)
	if err != nil {
		t.Errorf("ECRecover error: %s", err)
	}
	recoveredAddr2 := crypto.PubkeyToAddress(*recoveredPub2)
	if addr != recoveredAddr2 {
		t.Errorf("Address mismatch: want: %x have: %x", addr, recoveredAddr2)
	}
}

func TestECDSAPrivateKey_Sign(t *testing.T) {
	assert := assert.New(t)
	priv := mustGenKey()

	sig := priv.Sign(testMsg)

	ok, err := priv.Public().Verify(sig, testMsg)
	assert.NoError(err, "verification should not fail")
	assert.True(ok, "Verify should return true")

	(sig.([]byte))[0] = 1
	ok, err = priv.Public().Verify(sig, testMsg)
	assert.Error(err, "verification should fail")
	assert.False(ok, "Verify should return false")

	priv2 := mustGenKey()
	sig2 := priv2.Sign(testMsg)
	ok, err = priv.Public().Verify(sig2, testMsg)
	assert.Error(err, "verification should fail")
	assert.False(ok, "Verify should return false")

}

func TestECDSAPrivateKey_MarshalBinary(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	priv := mustGenKey()
	sigOrig := priv.Sign(testMsg)

	bs, err := priv.MarshalBinary()
	require.NotEmpty(bs, "marshal should have produced bytes")
	require.NoError(err, "marshal should not fail")

	privUnmarshal := new(ECDSAPrivate)
	assert.NoError(privUnmarshal.UnmarshalBinary(bs), "unmarshal should not fail")
	ok, err := privUnmarshal.Public().Verify(sigOrig, testMsg)
	require.NoError(err, "unmarshaled key should be able to verify")
	assert.True(ok, "unmarshaled key should verify original signature")
}

var testExpansion = []byte{216, 195, 190, 88, 224, 20, 1, 204, 175, 166, 113, 5, 36, 249, 89, 23, 235, 200, 182, 20, 28, 177, 150, 106, 71, 10, 9, 89, 6, 13, 6, 93}

func TestECDSAPrivate_Derive(t *testing.T) {
	//	assert := assert.New(t)
	require := require.New(t)
	priv := mustGenKey()
	_, err := priv.Derive(testExpansion)
	require.NoError(err, "Derive should not fail")
	// TODO: test that derives a pub key
	t.Error("WIP")
}