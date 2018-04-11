package hash

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func randomHash(seed int64) Hash {
	hbs := make([]byte, ByteLen)
	rand.Seed(seed)
	rand.Read(hbs)
	h, err := From(hbs)
	if err != nil {
		panic(err)
	}
	return h
}

func TestParse(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	h := randomHash(1)
	hstr := h.String()

	hfroms, err := Parse(hstr)
	require.NoError(err, "parsing hash should not fail")
	assert.Equal(h, hfroms, "parsed hash should match original")
}
