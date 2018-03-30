package sign

import (
	"testing"

	"github.com/ORBAT/Peerdoc/pkg/crypto"
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
	t.Skip("Not done yet")
}
