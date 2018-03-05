package main

import (
	"fmt"
	"strings"
	"sync"

	"github.com/ORBAT/Peerdoc/log"
	"github.com/attic-labs/noms/go/chunks"
	"github.com/attic-labs/noms/go/datas"
	"github.com/attic-labs/noms/go/merge"
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

func NewFile(ds datas.Dataset, content string) (file types.Struct, blobRef types.Ref) {
	db := ds.Database()
	blobRef = db.WriteValue(types.NewBlob(db, strings.NewReader(content)))
	file = types.NewStruct("File", types.StructData{
		"data": blobRef,
	})

	return
}

func NewDir(ds datas.Dataset) (dir types.Struct, newDs datas.Dataset) {
	db := ds.Database()
	dir = types.NewStruct("Directory", types.StructData{
		"entries": types.NewMap(db),
	})

	newDs, err := db.CommitValue(ds, dir)
	if err != nil {
		panic("error committing new dir: " + err.Error())
	}

	return
}

func AddFileTo(ds datas.Dataset, dir types.Struct, file types.Struct, name string) (newDir types.Struct, newDs datas.Dataset) {
	db := ds.Database()
	entries := dir.Get("entries").(types.Map)
	entries = entries.Edit().Set(types.String(name), file).Map()
	newDir = dir.Set("entries", entries)

	newDs, err := db.CommitValue(ds, newDir)
	if err != nil {
		panic("error committing new file to dir: " + err.Error())
	}

	return
}

func main() {
	logger := log.DevLogger
	defer logger.Sync()

	log1 := logger.With("node", "node1")
	log2 := logger.With("node", "node2")

	//	fileType := nomdl.MustParseType(`
	//		Struct File {
	//			data: Ref<Blob>,
	//		}`)

	_, db1 := NewMemNoms("first")
	ds1 := db1.GetDataset("files")
	log1.Infow("created db1")

	dir1Struct, ds1 := NewDir(ds1)
	log1.Infow("wrote root dir", "dir_hash", dir1Struct.Hash(), "struct", ToHuman(dir1Struct))

	file11Struct, file11BlobRef := NewFile(ds1, "file 1 contents")
	log1.Infow("wrote file1", "blob_hash", file11BlobRef.TargetHash(), "struct", ToHuman(file11Struct))

	file12Struct, file12BlobRef := NewFile(ds1, "file 2 contents")
	log1.Infow("wrote file2", "blob_hash", file12BlobRef.TargetHash(), "struct", ToHuman(file12Struct))

	dir1Struct, ds1 = AddFileTo(ds1, dir1Struct, file11Struct, "file1")
	dir1Struct, ds1 = AddFileTo(ds1, dir1Struct, file12Struct, "file2")
	log1.Infow("wrote two files to root", "dir_hash", dir1Struct.Hash(), "struct", ToHuman(dir1Struct))

	log1.Infow("head status", "head1", ToHuman(ds1.Head()), "head_hash", ds1.Head().Hash(), "file11_struct_hash", file11Struct.Hash())

	cs2, db2 := NewMemNoms("second")
	ds2 := db2.GetDataset("files")
	log2.Infow("created db2")

	dir2Struct, ds2 := NewDir(ds2)
	log2.Infow("wrote root dir", "dir_hash", dir2Struct.Hash(), "struct", ToHuman(dir2Struct))

	file21Struct, file21BlobRef := NewFile(ds2, "file 1 contents")
	log2.Infow("wrote file1", "blob_hash", file21BlobRef.TargetHash(), "struct", ToHuman(file21Struct))

	file23Struct, file23BlobRef := NewFile(ds2, "file 3 contents")
	log2.Infow("wrote file3", "blob_hash", file23BlobRef.TargetHash(), "struct", ToHuman(file23Struct))

	dir2Struct, ds2 = AddFileTo(ds2, dir2Struct, file21Struct, "file1")
	dir2Struct, ds2 = AddFileTo(ds2, dir2Struct, file23Struct, "file3")
	log2.Infow("wrote two files to root", "dir_hash", dir2Struct.Hash(), "struct", ToHuman(dir2Struct))

	log2.Infow("head status", "head", ToHuman(ds2.Head()), "head_hash", ds2.Head().Hash())

	progCh := make(chan datas.PullProgress, 256)

	var wg sync.WaitGroup
	wg.Add(1)

	go func(ch chan datas.PullProgress, wg *sync.WaitGroup) {
		defer log2.Sync()
		for prog := range ch {
			log2.Infow("pull progressed", "prog_struct", fmt.Sprintf("%+v", prog))
		}
		log2.Info("progress channel closed")
		wg.Done()
	}(progCh, &wg)

	// NOTE: ds2.HeadRef().TargetHash() == ds2.Head().Hash()

	datas.Pull(db1, db2, ds1.HeadRef(), progCh)
	close(progCh)
	wg.Wait()

	log2.Infow("did the pull go through?", "has_file12_blob_tgt", cs2.Has(file12BlobRef.TargetHash()), "has_file12_struct", cs2.Has(file12Struct.Hash()))

	log2.Infow("head status", "head", ToHuman(ds2.Head()), "head_hash", ds2.Head().Hash())

	log2.Infow("finding common ancestor for merge", "src", ds1.Head().Hash(), "our", ds2.Head().Hash())
	anc, foundAnc := datas.FindCommonAncestor(ds1.HeadRef(), ds2.HeadRef(), db2)

	log2.Infow("ancestor find done", "ok", foundAnc, "anc", anc.TargetHash())
	if !foundAnc {
		log2.DPanic("couldn't find ancestor")
	}

	// this won't happen with the setup above, it's here just for "completeness"
	if anc.Equals(ds2.HeadRef()) {
		log2.Infow("can do ff merge")
		newDs2, err := db2.SetHead(ds2, ds1.HeadRef())
		if err != nil {
			log2.DPanic("SetHead went boom", zap.Error(err))
		}
		ds2 = newDs2
	} else {
		log2.Info("doing 3-way merge")
		merged, err := merge.ThreeWay(ds2.HeadValue(),
			ds1.HeadValue(),
			anc.TargetValue(db2).(types.Struct).Get("value"),
			db2, nil, nil)
		if err != nil {
			log2.DPanicw("merge fuckup", zap.Error(err))
		}
		newCommit := datas.NewCommit(merged, types.NewSet(db2, ds2.HeadRef(), ds1.HeadRef()), types.EmptyStruct)
		commitRef := db2.WriteValue(newCommit)
		log2.Infow("wrote new commit", "ref_tgt", commitRef.TargetHash())
		if newds, err := db2.SetHead(ds2, commitRef); err != nil {
			log2.DPanicw("SetHead fuckup", zap.Error(err))
		} else {
			ds2 = newds
		}

	}

	log2.Infow("head status", "head", ToHuman(ds2.Head()), "head_hash", ds2.Head().Hash())

}
