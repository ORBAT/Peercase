package main

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"sync"

	"github.com/ORBAT/Peerdoc/pkg/crypto/sign/extended"
	"github.com/btcsuite/btcutil/base58"
)

func makeBuckets(min, max, numberOfBuckets uint32) [][2]uint32 {
	bukSiz := (max - min) / numberOfBuckets
	overfl := (max - min) % numberOfBuckets
	buks := make([][2]uint32, numberOfBuckets)
	prevBuk := uint32(min)
	var currb uint32
	for i := range buks {
		if overfl > 0 {
			currb = prevBuk + bukSiz + 1
			overfl--
		} else {
			currb = prevBuk + bukSiz
		}
		buks[i][0] = prevBuk + 1
		buks[i][1] = currb
		prevBuk = currb
	}
	return buks
}

type res struct {
	pfx string
	bs  []byte
	i   uint32
}

func findInRange(min, max uint32, bs []byte, wg *sync.WaitGroup, out chan res, end chan struct{}) {
	defer wg.Done()
	serBs := make([]byte, len(bs))
	copy(serBs, bs)

	prefixBs := make([]byte, 4)
	be := binary.BigEndian

	var (
		encStr string
		prefix string
	)

	for i := min; i <= max; i++ {
		select {
		case <-end:
			break
		default:
		}
		copy(serBs[:4], prefixBs)
		encStr = base58.Encode(serBs)
		prefix = strings.ToLower(encStr[:4])
		if prefix == "pprv" || prefix == "ppub" {
			bsCopy := make([]byte, 4)
			copy(bsCopy, prefixBs)
			out <- res{encStr[:4], bsCopy, i}
		}
		be.PutUint32(prefixBs, i)
	}

	return
}

func main() {
	s, err := extended.GenerateSeed(extended.RecommendedSeedLen)
	if err != nil {
		panic(err)
	}
	mk, err := extended.NewMaster(s)
	if err != nil {
		panic(err)
	}

	numGo := float64(runtime.NumCPU()) * 2
	// magic numbers I got from manual testing to get prefixes starting with P...
	buks := makeBuckets(3150000000, 3353979778, uint32(numGo))
	fmt.Println(buks)

	serBs := mk.Bytes()
	fmt.Printf("initial key %s, len serBs %d\n", base58.Encode(serBs), len(serBs))

	results := make(chan res, 10)
	end := make(chan struct{})
	found := make(map[string][]byte)
	go func() {
		for res := range results {
			if _, ok := found[res.pfx]; !ok {
				found[res.pfx] = res.bs
				if len(found) == 2 {
					break
				}
			}
		}
		close(end)
	}()

	var wg sync.WaitGroup
	for _, buk := range buks {
		fmt.Println("starting search for bukkit", buk)
		wg.Add(1)
		go findInRange(buk[0], buk[1], serBs, &wg, results, end)
	}
	wg.Wait()
	close(results)
	for prefix, bytes := range found {
		fmt.Printf("Bytes %v gives prefix %s\n", bytes, prefix)
	}
}
