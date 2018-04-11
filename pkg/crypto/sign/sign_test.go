package sign

import (
	"crypto/ecdsa"
	"math/rand"
	"testing"

	"github.com/ORBAT/Peerdoc/pkg/crypto/hash"
	"github.com/attic-labs/noms/go/chunks"
	"github.com/attic-labs/noms/go/datas"
	"github.com/attic-labs/noms/go/types"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testMsg = []byte("bla bla bla")

func mustGenKey(seed int64) PrivateKey {
	ec, err := ecdsa.GenerateKey(ecrypto.S256(), rand.New(rand.NewSource(seed)))
	if err != nil {
		panic(err)
	}
	return PrivFromECDSA(ec)
}

func TestECDSAPrivateKey_Sign(t *testing.T) {
	assert := assert.New(t)
	priv := mustGenKey(1)

	testHash := hash.Of(testMsg)
	sig := priv.Sign(testHash)

	err := priv.Public().Verify(sig, testHash)
	assert.NoError(err, "verification should not fail")

	(sig.([]byte))[0] = 1
	err = priv.Public().Verify(sig, testHash)
	assert.Error(err, "verification should fail")

	priv2 := mustGenKey(2)
	sig2 := priv2.Sign(testHash)
	err = priv.Public().Verify(sig2, testHash)
	assert.Error(err, "verification should fail")

}

func TestECDSAPrivateKey_MarshalBinary(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	priv := mustGenKey(1)
	testHash := hash.Of(testMsg)
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

func TestECDSAPrivateKey_DeriveSymmetric(t *testing.T) {
	const (
		keyLen  = 64
		testCtx = "test context"
	)
	assert := assert.New(t)
	require := require.New(t)

	key1Bs := make([]byte, keyLen)
	pr := mustGenKey(1)
	n, err := pr.DeriveSymmetric(1, testCtx, key1Bs)
	require.NoError(err, "key derivation should not return an error")
	assert.Equal(keyLen, n, "n should be equal to the key length")

	key2Bs := make([]byte, keyLen)
	n, err = pr.DeriveSymmetric(2, testCtx, key2Bs)
	assert.NoError(err, "key derivation should not return an error")
	assert.Equal(keyLen, n, "n should be equal to the key length")

	assert.NotEqual(key2Bs, key1Bs, "changing the index should result in a different key")

	key3Bs := make([]byte, keyLen)
	n, err = pr.DeriveSymmetric(1, testCtx+"blep", key3Bs)
	assert.NoError(err, "key derivation should not return an error")
	assert.Equal(keyLen, n, "n should be equal to the key length")
	assert.NotEqual(key3Bs, key1Bs, "changing the context should result in a different key")
}

func TestECDSAPrivate_Derive(t *testing.T) {
	//	assert := assert.New(t)
	require := require.New(t)
	priv := mustGenKey(1)
	_, err := priv.Derive(testExpansion)
	require.NoError(err, "Derive should not fail")
	// TODO(ORBAT): test that derives a pub key
	t.Skip("Not done yet")
}

func randomFingerprint(seed int64) Fingerprint {
	fpbs := make([]byte, FingerprintLen)
	rand.Seed(seed)
	rand.Read(fpbs)
	fp, err := BytesToFingerprint(fpbs)
	if err != nil {
		panic(err)
	}
	return fp
}

func TestParseFingerprint(t *testing.T) {
	fp := randomFingerprint(1)
	fps := fp.String()
	fromS, err := ParseFingerprint(fps)
	require.NoError(t, err, "parsing fingerprint from string should not fail")
	assert.Equal(t, fp, fromS)
}

func newMemNoms(ns string) (chunks.ChunkStore, datas.Database) {
	store := chunks.NewMemoryStoreFactory().CreateStore(ns)
	db := datas.NewDatabase(store)
	return store, db
}

func TestFingerprint_MarshalNoms(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_, db := newMemNoms("ns")
	fp := randomFingerprint(1)
	v, err := fp.MarshalNoms(db)
	require.NoError(err, "MarshalNoms should not fail")
	assert.EqualValues(fingerprintNomsType, types.TypeOf(v), "MarshalNoms should return a value of the correct type")
	t.Log(fp, v)
}
