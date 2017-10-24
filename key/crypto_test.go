package key

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

var testMsg = []byte("bla bla bla")

func mustGenKey() Private {
	if k, err := Generate(); err != nil {
		panic(err)
	} else {
		return k
	}
}

func TestECDSAPrivateKey_Sign(t *testing.T) {
	assert := assert.New(t)
	priv := mustGenKey()

	sig := priv.Sign(testMsg)

	t.Logf("signature is %s", common.ToHex(sig.([]byte)))
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
