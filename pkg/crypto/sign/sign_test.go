package sign

import (
	"testing"

	"github.com/ORBAT/Peerdoc/pkg/crypto"
	eco "github.com/ethereum/go-ethereum/common"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testMsg = []byte("bla bla bla")

func mustGenKey() PrivateKey {
	if k, err := Generate(); err != nil {
		panic(err)
	} else {
		return k
	}
}

var testAddrHex = "970e8128ab834e8eac17ab8e3812f010678cf791"
var testPrivHex = "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032"

func TestBla(t *testing.T) {
	key, _ := ecrypto.HexToECDSA(testPrivHex)

	addr := eco.HexToAddress(testAddrHex)

	msg := ecrypto.Keccak256([]byte("foo"))
	sig, err := ecrypto.Sign(msg, key)
	if err != nil {
		t.Errorf("Sign error: %s", err)
	}
	recoveredPub, err := ecrypto.Ecrecover(msg, sig)
	if err != nil {
		t.Errorf("ECRecover error: %s", err)
	}
	pubKey := ecrypto.ToECDSAPub(recoveredPub)
	recoveredAddr := ecrypto.PubkeyToAddress(*pubKey)
	if addr != recoveredAddr {
		t.Errorf("Address mismatch: want: %x have: %x", addr, recoveredAddr)
	}

	// should be equal to SigToPub
	recoveredPub2, err := ecrypto.SigToPub(msg, sig)
	if err != nil {
		t.Errorf("ECRecover error: %s", err)
	}
	recoveredAddr2 := ecrypto.PubkeyToAddress(*recoveredPub2)
	if addr != recoveredAddr2 {
		t.Errorf("Address mismatch: want: %x have: %x", addr, recoveredAddr2)
	}
}

func TestECDSAPrivateKey_Sign(t *testing.T) {
	assert := assert.New(t)
	priv := mustGenKey()

	testHash := crypto.Hash(testMsg)
	sig := priv.Sign(testHash)

	err := priv.Public().Verify(sig, testHash)
	assert.NoError(err, "verification should not fail")

	(sig.([]byte))[0] = 1
	err = priv.Public().Verify(sig, testHash)
	assert.Error(err, "verification should fail")

	priv2 := mustGenKey()
	sig2 := priv2.Sign(testHash)
	err = priv.Public().Verify(sig2, testHash)
	assert.Error(err, "verification should fail")

}

func TestECDSAPrivateKey_MarshalBinary(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	priv := mustGenKey()
	testHash := crypto.Hash(testMsg)
	sigOrig := priv.Sign(testHash)

	bs, err := priv.MarshalBinary()
	require.NotEmpty(bs, "marshal should have produced bytes")
	require.NoError(err, "marshal should not fail")

	privUnmarshal := new(ECDSAPrivateKey)
	assert.NoError(privUnmarshal.UnmarshalBinary(bs), "unmarshal should not fail")
	err = privUnmarshal.Public().Verify(sigOrig, testHash)
	require.NoError(err, "unmarshaled key should be able to verify")
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
