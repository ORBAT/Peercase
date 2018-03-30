package buffer

import "io"

// A Bytes is a variable-sized buffer of bytes with Read and Write
// methods. The zero value for Bytes is an empty buffer ready to use.
type Bytes []byte

// Write writes len(p) bytes from p to the Bytes.
func (b *Bytes) Write(p []byte) (int, error) {
	*b = append(*b, p...)
	return len(p), nil
}

// Read reads up to len(p) bytes into p from the Bytes.
func (b *Bytes) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(*b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, *b)
	*b = (*b)[n:]
	return n, nil
}
