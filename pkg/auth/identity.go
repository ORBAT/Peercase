package auth

type Identity interface {
	Certificate
	Name() string
	Metadata() map[string][]byte
	Grants() []Grant
}

// A Capability gives access to something according to a path and permission flags.
type Capability struct {
	Path string
	CapFlags
}

const (
	CapPermCreate CapFlags = 1 << (4 - 1 - iota)
	CapPermRead
	CapPermUpdate
	CapPermDelete

	// CapPermFull gives full CRUD access
	CapPermFull CapFlags = 0xF
)

// CapFlags specifies permission flags for the Capability.
//
// Leaving the flags at 0 will remove all rights
// from that point onwards. For example, if person A has a grant with CapPermFull for
//   /.orgs/fi/some-company/some-team/*
// putting a grant with CapFlags(0) at
//   /.orgs/fi/some-company/some-team/.identities/*
// would mean A had otherwise full access to everything under /.orgs/fi/some-company/some-team/, except for the
// ./identities subfolder
type CapFlags uint32

// On checks that all the flags in f are all on in cf
func (cf CapFlags) On(f CapFlags) bool {
	return cf&f == f
}

// Set flags fs on cf
func (cf CapFlags) Set(fs ...CapFlags) {
	for _, f := range fs {
		cf |= f
	}
}

// Grants give Identities Capabilities
type Grant struct {
	Certificate
	Capability
}

func (cf CapFlags) String() string {
	var buf [4]byte // only using last 4 bits at the moment
	const crud = "crud"
	for i, c := range crud {
		if cf&(1<<uint(4-1-i)) != 0 {
			buf[i] = byte(c)
		} else {
			buf[i] = '-'
		}
	}
	return string(buf[:4])
}
