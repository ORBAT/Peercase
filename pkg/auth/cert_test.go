package auth

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAttrs_Bytes(t *testing.T) {
	a := Attrs(map[string][]byte{"qq": []byte("key_qq"), "aa": []byte("key_aa"), "ab": []byte("key_ab"), "ac": []byte("key_ac")})
	require.Equal(t, []byte("aa=key_aa,ab=key_ab,ac=key_ac,qq=key_qq"), a.Bytes())
}
