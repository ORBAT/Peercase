package internal

import (
	"bytes"
	"encoding/binary"

	"github.com/ORBAT/Peerdoc/pkg/crypto/sign"
	"github.com/ORBAT/Peerdoc/pkg/util/buffer"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/pkg/errors"
)

const cksumLen = 4

var (
	ErrBadChecksum = errors.New("bad extended key checksum")
)

// WireFmt is an utility struct for turning ExtendedKeys into byte slices
type WireFmt struct {
	Version   [4]byte
	Depth     byte
	ParentFP  [sign.FingerprintLen]byte
	ChildNum  [4]byte
	ChainCode [32]byte
	KeyData   [33]byte
}

func (w *WireFmt) UnmarshalBinary(bs []byte) error {
	cksumStart := len(bs) - cksumLen

	payload := bs[:cksumStart]
	cksum := bs[cksumStart:]
	expected := chainhash.DoubleHashB(payload)[:cksumLen]
	if !bytes.Equal(expected, cksum) {
		return ErrBadChecksum
	}
	buf := buffer.Bytes(payload)
	return binary.Read(&buf, binary.BigEndian, w)
}

func (w *WireFmt) MarshalBinary() (bs []byte, err error) {
	buf := buffer.Bytes(bs)
	err = binary.Write(&buf, binary.BigEndian, w)
	buf = append(buf, chainhash.DoubleHashB(buf)...)
	return
}
