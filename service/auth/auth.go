package auth

import a "github.com/ORBAT/Peerdoc/pkg/auth"

// The Authorization service tells whether an Identity has the Grants for a Capability
type Authorization interface {
	Authorized(identity a.Identity, capability a.Capability) (ok bool, err error)
}
