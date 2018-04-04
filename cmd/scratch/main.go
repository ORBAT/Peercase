package main

import (
	"io/ioutil"
	"math/rand"
	"strings"
	"time"

	"github.com/ORBAT/Peerdoc/log"
	"github.com/ORBAT/Peerdoc/pkg/crypto/hash"
	"github.com/ORBAT/Peerdoc/pkg/crypto/sign"
	"github.com/attic-labs/noms/go/chunks"
	"github.com/attic-labs/noms/go/datas"
	"github.com/attic-labs/noms/go/marshal"
	"github.com/attic-labs/noms/go/nomdl"
	"github.com/attic-labs/noms/go/types"
	"go.uber.org/zap"
)

func NewMemNoms(ns string) (chunks.ChunkStore, datas.Database) {
	store := chunks.NewMemoryStoreFactory().CreateStore(ns)
	db := datas.NewDatabase(store)
	return store, db
}

func ToHuman(v types.Value) string {
	return strings.Replace(types.EncodedValue(v), "\n", " ", -1)
}

type encryptedPayload struct {
	Method      string
	Fingerprint sign.Fingerprint
	KeyIdx      uint32
	Payload     types.Blob `noms:"original"`
}

type epRef struct {
	Method      string
	Fingerprint sign.Fingerprint
	KeyIdx      uint32
	PayloadRef  types.Ref `noms:"original"` // Ref<Blob>
}

type CryptoInfo struct {
	Method      string
	Fingerprint sign.Fingerprint
	KeyIdx      uint32
}

var cryptoInfoTempl = types.MakeStructTemplate("CryptoInfo", []string{"method", "fingerprint", "keyIdx"})

func (ci CryptoInfo) MarshalNoms(vrw types.ValueReadWriter) (val types.Value, err error) {
	fpNoms, err := ci.Fingerprint.MarshalNoms(vrw)
	if err != nil {
		return nil, err
	}
	ciNoms := cryptoInfoTempl.NewStruct([]types.Value{types.String(ci.Method), fpNoms, types.Number(ci.KeyIdx)})
	return ciNoms, nil
}

func NewCryptoInfo(method string, fp sign.Fingerprint, keyIdx uint32) CryptoInfo {
	return CryptoInfo{
		Method:      method,
		Fingerprint: fp,
		KeyIdx:      keyIdx,
	}
}

type EncryptedRef struct {
	CryptoInfo
	Payload types.Ref `noms:"original"` // Ref<Blob>
}

func (EncryptedRef) ContType() ContentType {
	return ContentEncrRef
}

type EncryptedBlob struct {
	CryptoInfo
	Payload types.Blob `noms:"original"`
}

func (EncryptedBlob) ContType() ContentType {
	return ContentEncrBlob
}

type Container struct {
	Contents map[string]*Node
}

func (Container) ContType() ContentType {
	return ContentContainer
}

type ContentType string

const (
	ContentContainer = ContentType("Container")
	ContentEncrRef   = ContentType("EncryptedRef")
	ContentEncrBlob  = ContentType("EncryptedBlob")
)

type Content interface {
	ContType() ContentType
}

type Metadata struct {
	Creator sign.Fingerprint
	Ctime   types.Number
	ID      string
}

type Node struct {
	Metadata Metadata
	Contents Content // see nomdl spec below
	Parent   *Node   `noms:"original"` // Ref<Cycle<Node>>
}

type CreateEncType func() types.Struct

func EncECIES(date []byte) types.Struct {
	panic("WIP")
}

func NewMetadata(ctor sign.Fingerprint) Metadata {
	nowUnix := time.Now().Unix()
	md := Metadata{
		Creator: ctor,
		Ctime:   types.Number(nowUnix),
	}
	idbs := make([]byte, hash.ByteLen)
	rand.Seed(nowUnix)
	rand.Read(idbs)
	h := hash.Of(idbs)
	md.ID = h.String()
	return md
}

func NewLeafNode(md Metadata, createBlob CreateEncType) *Node {
	panic("WIP")
}

var nodeType = nomdl.MustParseType(`Struct Node {
	metadata: Struct Metadata {
		creator: Blob, // a fingerprint  
		ctime: Number,
		id: String,
	},
	contents: Struct Encrypted {
		info: Struct CryptoInfo {
			method: String,
			fingerprint: Struct Fingerprint {
				bytes: Blob,
			},
			keyIdx?: Number,
		},
		data: Ref<Blob> | Blob
	} | Struct Container {
		children: Map<String, Cycle<Node>>,
	},
	parent: Ref<Cycle<Node>>,
}`)

var cryptoInfoType, encryptedType, containerType *types.Type

func init() {
	nodeDesc := nodeType.Desc.(types.StructDesc)
	contentType, _ := nodeDesc.Field("contents")
	contentCompound := contentType.Desc.(types.CompoundDesc)

	for _, elemType := range contentCompound.ElemTypes {
		switch elemType.Desc.(types.StructDesc).Name {
		case "Encrypted":
			encryptedType = elemType
		case "Container":
			contentType = elemType
		}
	}

	encryptedType, _ = nodeDesc.Field("contents")
	cryptoInfoType, _ = encryptedType.Desc.(types.StructDesc).Field("info")
}

/*
`Struct Inode {
          attr: Struct Attr {
            ctime: Number,
            gid: Number,
            mode: Number,
            mtime: Number,
            uid: Number,
            xattr: Map<String, Blob>,
          },
          contents: Struct Symlink {
              targetPath: String,
            } | Struct File {
              data: Ref<Blob>,
            } | Struct Directory {
              entries: Map<String, Cycle<Inode>>,
            },
        }`
*/

/*
`Struct Node {
          attr: Struct Attr {
            ctime: Number,
            gid: Number,
            mode: Number,
            mtime: Number,
            uid: Number,
            xattr: Map<String, Blob>,
          },
          contents: Struct EncryptedPayload {
              method: String,

              data: Ref<Blob>,
            } | Struct Directory {
              entries: Map<String, Cycle<Inode>>,
            },
        }`
*/

func main() {
	logger := log.DevLogger("scratch")
	defer logger.Sync()
	_, db := NewMemNoms("ns")

	r := rand.New(rand.NewSource(1))

	testEncPload(r, db, logger)

	testEncPloadRef(r, db, logger)

}

func testEncPloadRef(r *rand.Rand, db datas.Database, logger *zap.Logger) {
	l := logger.Named("blob-ref")
	ds := db.GetDataset("enc-ref-test")
	fp := newFp(r)
	blob := types.NewBlob(db, strings.NewReader("payload string ref"))
	bref := db.WriteValue(blob)
	pload := epRef{
		Method:      "bla",
		Fingerprint: fp,
		PayloadRef:  bref,
		KeyIdx:      666,
	}
	ploadVal, err := marshal.Marshal(db, pload)
	l.Info("marshaled", zap.Error(err), zap.Stringer("bref.TargetHash()", bref.TargetHash()))
	ds, err = db.CommitValue(ds, ploadVal)
	l.Info("committed", zap.Error(err))
	outVal := ds.HeadValue()
	readPl := epRef{}
	err = marshal.Unmarshal(outVal, &readPl)
	l.Info("unmarshaled", zap.Error(err), zap.Any("readPl", readPl), zap.Stringer("readPl.PayloadRef.TargetHash", readPl.PayloadRef.TargetHash()))

	actualPayload, err := ioutil.ReadAll(readPl.PayloadRef.TargetValue(db).(types.Blob).Reader())
	l.Info("got payload from noms", zap.Error(err), zap.ByteString("actualPayload", actualPayload))

}

func testEncPload(r *rand.Rand, db datas.Database, logger *zap.Logger) {
	l := logger.Named("just-blob")
	ds := db.GetDataset("enc-test")
	fp := newFp(r)
	pl := encryptedPayload{
		Method:      "bla",
		Fingerprint: fp,
		Payload:     types.NewBlob(db, strings.NewReader("payload string")),
		KeyIdx:      666,
	}
	v, err := marshal.Marshal(db, pl)
	l.Info("marshaled", zap.Error(err))

	ds, err = db.CommitValue(ds, v)
	l.Info("committed", zap.Error(err))

	outVal := ds.HeadValue()
	outPl := encryptedPayload{}
	err = marshal.Unmarshal(outVal, &outPl)
	l.Info("unmarshaled", zap.Error(err), zap.Any("outPl", outPl))
	outPayload, err := ioutil.ReadAll(outPl.Payload.Reader())
	l.Info("got payload from noms", zap.Error(err), zap.ByteString("outPayload", outPayload))
}

func newFp(r *rand.Rand) sign.Fingerprint {
	fp := make([]byte, sign.FingerprintLen)
	r.Read(fp)
	return sign.BytesToFingerprint(fp)
}
