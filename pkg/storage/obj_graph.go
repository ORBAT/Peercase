package storage

type EncryptionMethod string

const (
	EncryptionDARE  = EncryptionMethod("dare")
	EncryptionECIES = EncryptionMethod("ecies")
)

// ObjectGraph is implemented by encrypted object graphs
type ObjectGraph interface {
}
