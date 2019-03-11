// package authn provides authentication-related types and functionality
package authn

import "github.com/ORBAT/Peerdoc/pkg/crypto/sign"

type Identity interface {

	// Key returns they signature key associated with this identity.
	Key() sign.PublicKey
}
