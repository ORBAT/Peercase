package extended

import (
	"strconv"
	"strings"

	"github.com/ORBAT/Peerdoc/pkg/crypto/hash"
	"github.com/ORBAT/Peerdoc/pkg/crypto/sign"
	"github.com/pkg/errors"
)

type KeyPath struct {
	Parent sign.Fingerprint
	Path   []uint32
}

func (kp KeyPath) String() string {
	var sb strings.Builder
	sb.Grow(hash.StringLen + len(kp.Path)*3)

	if !kp.Parent.IsZero() {
		sb.WriteString(kp.Parent.String())
		sb.WriteByte('/')
	}

	for i, elem := range kp.Path {
		if i != 0 {
			sb.WriteByte('/')
		}
		if elem >= HardenedKeyStart {
			sb.WriteString(strconv.Itoa(int(elem) - HardenedKeyStart))
			sb.WriteByte('\'')
		} else {
			sb.WriteString(strconv.Itoa(int(elem)))
		}
	}
	return sb.String()
}

func ParseKeyPath(path string) (kp KeyPath, err error) {
	noSp := strings.Replace(path, " ", "", -1)
	split := strings.Split(noSp, "/")
	if len(split) == 0 {
		return kp, errors.New("empty key path")
	}

	if hash.IsHash(split[0]) {
		parentFP, err := sign.ParseFingerprint(split[0])
		if err != nil {
			return kp, errors.Wrap(err, "error parsing parent fingerprint")
		}
		split = split[1:]
		kp.Parent = parentFP
	}

	keyIdxs := make([]uint32, len(split))
	for i, idxStr := range split {
		var idx uint32
		if last := len(idxStr) - 1; idxStr[last] == '\'' {
			idxStr = idxStr[:last]
			idx += HardenedKeyStart
		}
		pidx, err := strconv.ParseUint(idxStr, 10, 32)
		if err != nil {
			return kp, errors.Wrapf(err, `"%s" doesn't look like a valid number`, idxStr)
		}
		idx += uint32(pidx)
		keyIdxs[i] = idx
	}

	kp.Path = keyIdxs

	return
}
