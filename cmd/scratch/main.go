package main

import (
	crand "crypto/rand"
	"encoding/binary"
	"io"
	"io/ioutil"
	"math/rand"
	"strings"
	"time"

	"github.com/ORBAT/Peerdoc/log"
	"github.com/ORBAT/Peerdoc/pkg/crypto/sign"
	"github.com/ORBAT/Peerdoc/pkg/crypto/sign/extended"
	"github.com/attic-labs/noms/go/chunks"
	"github.com/attic-labs/noms/go/datas"
	"github.com/attic-labs/noms/go/marshal"
	"github.com/attic-labs/noms/go/nomdl"
	"github.com/attic-labs/noms/go/types"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/google/uuid"
	"github.com/pkg/errors"
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

type ContentType string

const (
	ContentContainer = ContentType("Container")
	ContentEncrRef   = ContentType("EncryptedRef")
	ContentEncrBlob  = ContentType("EncryptedBlob")
)

type EncryptMethod string

const (
	EncMethodECIES = EncryptMethod("ecies")
	EncMethodDARE  = EncryptMethod("dare")
)

type Content interface {
	ContType() ContentType
}

type Decryptable interface {
	Decrypt(k *extended.Key, idx uint32) io.Reader
}

type CryptoInfo struct {
	Method      EncryptMethod
	Fingerprint sign.Fingerprint
	KeyIdx      uint32
}

func NewCryptoInfo(method EncryptMethod, fp sign.Fingerprint, keyIdx uint32) CryptoInfo {
	return CryptoInfo{
		Method:      method,
		Fingerprint: fp,
		KeyIdx:      keyIdx,
	}
}

type encryptedRef struct {
	Payload types.Ref `noms:"original"` // Ref<Blob>
}

func (encryptedRef) ContType() ContentType {
	return ContentEncrRef
}

type encryptedBlob struct {
	Payload types.Blob `noms:"original"`
}

func (encryptedBlob) ContType() ContentType {
	return ContentEncrBlob
}

type Container struct {
	Contents map[string]*Node
	Keys     struct {
		Read     sign.Fingerprint
		WriteSig sign.Fingerprint
	}
}

func (Container) ContType() ContentType {
	return ContentContainer
}

type Metadata struct {
	Name    string
	Creator sign.Fingerprint
	Ctime   int64
	Mtime   int64
	ID      string // this only needs to be unique within a directory, not globally (???)
}

type Node struct {
	Metadata Metadata
	Contents Content // see nomdl spec below
	Parent   *Node   `noms:"original"` // Ref<Cycle<Node>>
}

type Encrypted struct {
	cont struct {
		Info CryptoInfo
		Data types.Struct `noms:"original"` // either encryptedBlob or encryptedRef depending on Info
	}
}

func (e *Encrypted) Decrypt(k *extended.Key, idx int) io.Reader {
	switch e.cont.Info.Method {
	case EncMethodDARE: // symmetric, so encryptedRef

	case EncMethodECIES: // asymmetric, so encryptedBlob
	}
	panic("wip")
}

func idxToBytes(i uint32) []byte {
	bs := make([]byte, 4)
	binary.BigEndian.PutUint32(bs, i)
	return bs
}

type DoEncrypt func() (Encrypted, error)

func EncECIES(data []byte, k *extended.Key, keyIdx uint32) (DoEncrypt, error) {
	pub, err := k.ECPubKey()
	if err != nil {
		errors.Wrap(err, "error getting pub key from extended key")
		return nil, err
	}
	eciesK := ecies.ImportECDSAPublic(pub.(sign.PubIsECDSA).ECDSA())
	return func() (enc Encrypted, err error) {
		bs, err := ecies.Encrypt(crand.Reader, eciesK, data, idxToBytes(keyIdx), nil)
		if err != nil {
			return enc, errors.Wrap(err, "error doing ECIES")
		}
		ci := NewCryptoInfo(EncMethodECIES, k.Fingerprint(), keyIdx)

	}, nil
}

func EncDARE(src io.Reader) DoEncrypt {

}

func NewMetadata(name string, ctor sign.Fingerprint) Metadata {
	nowUnix := time.Now().Unix()
	md := Metadata{
		Creator: ctor,
		Ctime:   nowUnix,
		Mtime:   nowUnix,
		Name:    name,
	}
	md.ID = uuid.New().String()
	return md
}

func NewEncrypted(md Metadata, createBlob DoEncrypt) *Node {
	panic("WIP")
}

var nodeType = nomdl.MustParseType(`Struct Node {
	metadata: Struct Metadata {
		creator: Struct Fingerprint {
				bytes: Blob,
			}, // a fingerprint  
		ctime: Number,
		id: String,
		name: String,
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
		children: Map<String, Cycle<Node>>, // map from ID -> Node
		keys: Struct {
			writeSig: Struct Fingerprint {bytes: Blob},
			read: Struct Fingerprint {bytes: Blob},
		},
	},
	parent?: Ref<Cycle<Node>>,
}`)

var cryptoInfoType, encryptedType, containerType *types.Type

func init() {
	cryptoInfoType = marshal.MustMarshalType(&CryptoInfo{})
	encryptedType = types.MakeStructTypeFromFields("Encrypted", map[string]*types.Type{"info": cryptoInfoType, "data": nomdl.MustParseType(`Ref<Blob> | Blob`)})
	//containerType = types.
	/*	nodeDesc := nodeType.Desc.(types.StructDesc)
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
		cryptoInfoType, _ = encryptedType.Desc.(types.StructDesc).Field("info")*/
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
