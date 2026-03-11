package trie

import (
	"fmt"
	"os"
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

type BlockTracker struct {
	BlockNum uint64
	Reads    map[common.Hash]int
	Writes   map[common.Hash]int
	Deletes  map[common.Hash]int
}

var (
	TrackExecution bool
	CurrentBlock   *BlockTracker
	LogChannel     = make(chan *BlockTracker, 1000)
	logFile        *os.File
	once           sync.Once
)

func startBackgroundWriter() {
	var err error
	logFile, err = os.OpenFile("cache_sim_data.csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}

	go func() {
		for blockData := range LogChannel {
			// Format: BLOCK_NUMBER, TYPE, HASH, SIZE_IN_BYTES
			for hash, size := range blockData.Reads {
				logFile.WriteString(fmt.Sprintf("%d,READ,%s,%d\n", blockData.BlockNum, hash.Hex(), size))
			}
			for hash, size := range blockData.Writes {
				logFile.WriteString(fmt.Sprintf("%d,WRITE,%s,%d\n", blockData.BlockNum, hash.Hex(), size))
			}
			for hash, size := range blockData.Deletes {
				logFile.WriteString(fmt.Sprintf("%d,DELETE,%s,%d\n", blockData.BlockNum, hash.Hex(), size))
			}
			
			// Help the GC
			blockData.Reads = nil
			blockData.Writes = nil
			blockData.Deletes = nil
		}
	}()
}

// BeginBlockTracking is called by Nitro when ArbOS begins a block
func BeginBlockTracking(blockNum uint64) {
	once.Do(startBackgroundWriter)

	CurrentBlock = &BlockTracker{
		BlockNum: blockNum,
		Reads:    make(map[common.Hash]int),
		Writes:   make(map[common.Hash]int),
		Deletes:  make(map[common.Hash]int),
	}
	TrackExecution = true
}

// EndBlockTracking is called by Nitro when ArbOS finishes a block
func EndBlockTracking() {
	if TrackExecution && CurrentBlock != nil {
		LogChannel <- CurrentBlock
		CurrentBlock = nil
	}
	TrackExecution = false
}

func (t *Trie) trackNodeAccess(n node) {
	if !TrackExecution || n == nil || CurrentBlock == nil {
		return
	}

	var nodeHash []byte
	switch n := n.(type) {
	case hashNode:
		nodeHash = n
	case *shortNode:
		nodeHash = n.flags.hash
	case *fullNode:
		nodeHash = n.flags.hash
	}

	if len(nodeHash) > 0 {
		hash := common.BytesToHash(nodeHash)
		// Mark Reads with size 0 (Simulator assumes ~200 bytes for cold reads)
		CurrentBlock.Reads[hash] = 0
	}
}
