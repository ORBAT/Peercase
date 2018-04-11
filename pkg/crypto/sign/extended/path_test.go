package extended

import (
	"testing"

	"github.com/ORBAT/Peerdoc/pkg/crypto/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyPath_String(t *testing.T) {
	t.Run("with parent", func(t *testing.T) {
		require := require.New(t)
		fp, _ := sign.ParseFingerprint("abuvo1p1g9iku5hvbs7pkogteaamdhqd")
		testPath := KeyPath{
			Parent: fp,
			Path:   []uint32{HardenedKeyStart, 1239677, 33 + HardenedKeyStart},
		}
		require.Equal("abuvo1p1g9iku5hvbs7pkogteaamdhqd/0'/1239677/33'", testPath.String())
	})

	t.Run("without parent", func(t *testing.T) {
		require := require.New(t)
		testPath := KeyPath{
			Path: []uint32{HardenedKeyStart, 1239677, 33 + HardenedKeyStart},
		}
		require.Equal("0'/1239677/33'", testPath.String())
	})
}

func TestParseKeyPath(t *testing.T) {
	t.Run("with parent", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)
		fp, _ := sign.ParseFingerprint("abuvo1p1g9iku5hvbs7pkogteaamdhqd")
		const TestPathWithParent = "   abuvo1p1g9iku5hvbs7pkogteaamdhqd /0 ' /  1239677 / 33'  "
		p, err := ParseKeyPath(TestPathWithParent)
		require.NoError(err, "parsing should not fail")
		assert.Equal(fp, p.Parent, "parsed parent FP should match")
		assert.Len(p.Path, 3, "should have had 3 children in path")
		assert.EqualValues(HardenedKeyStart, p.Path[0], "first path element should be 0'")
		assert.EqualValues(1239677, p.Path[1], "second path element should match")
		assert.EqualValues(33+HardenedKeyStart, p.Path[2], "third path element should be 33'")
	})

	t.Run("without parent", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)
		const TestPathWithParent = "   0 ' /  1239677 / 33'  "
		p, err := ParseKeyPath(TestPathWithParent)
		require.NoError(err, "parsing should not fail")
		assert.True(p.Parent.IsZero(), "parsed parent FP should be zero")
		assert.Len(p.Path, 3, "should have had 3 children in path")
		assert.EqualValues(HardenedKeyStart, p.Path[0], "first path element should be 0'")
		assert.EqualValues(1239677, p.Path[1], "second path element should match")
		assert.EqualValues(33+HardenedKeyStart, p.Path[2], "third path element should be 33'")
	})

}
