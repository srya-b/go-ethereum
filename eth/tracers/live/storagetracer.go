
// Package live registers live tracers for the Ethereum VM.
package live

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/eth/tracers"
	"github.com/ethereum/go-ethereum/log"
)

type KeyPair struct {
	Address		common.Address	`json:"address"`
	Key			common.Hash		`json:"key"`
}

const (
	OPCODE		= "opcode"	
	BALANCE		= "balance"
	HOOK		= "hook"
	NONCE		= "nonce"
	ARB			= "arb"
	ARBTRANSFER = "arbtransfer"
	CODE		= "code"
)

type KeyAccess struct {
	Type		string		`json:"type"`
	Pair		KeyPair		`json:"pair"`
}

// TxTrace holds all state changes for a single transaction.
type TxTrace struct {
	BlockNumber *big.Int       		`json:"blockNumber"`
	TxIndex     	uint            `json:"txIndex"`
	TxHash			common.Hash	   `json:"txHash,omitempty"`
	WriteAccesses	[]KeyAccess		`json:"writes"`
	ReadAccesses	[]KeyAccess		`json:"reads"`
	CumulativeGas	uint64			`json:"cumulativeGas"`
	GasUsed			uint64			`json:"gasUsed"`
	GasUsedForL1	uint64			`json:gasUsedForL1"`
	TxType			uint8			`json:"type"`	
 
	// for internal use only, not saved
	Writes		map[KeyAccess]bool	`json:"-"`
	Reads		map[KeyAccess]bool	`json:"-"`
}

// BlockTrace is the final output file, containing all tx traces for a block.
type BlockTrace struct {
	BlockNumber *big.Int   `json:"blockNumber"`
	Traces      []*TxTrace  `json:"transactions"`
}

// StateAccessConfig holds the configuration for the tracer.
type StateAccessConfig struct {
	// OutputPath specifies the directory to write trace files to.
	OutputPath string `json:"path"`
}

// Register the tracer in the live tracer framework.
func init() {
	tracers.LiveDirectory.Register("stateAccessTracer", NewStateAccessTracer)
}

// newStateAccessTracer is the constructor called by the tracer framework.
//func NewStateAccessTracer(ctx *tracers.Context, cfg json.RawMessage) (tracers.Tracer, error) {
func NewStateAccessTracer(cfg json.RawMessage) (*tracing.Hooks, error) {
	var config StateAccessConfig
	if cfg != nil {
		if err := json.Unmarshal(cfg, &config); err != nil {
			return nil, fmt.Errorf("failed to unmarshal stateAccessTracer config: %v", err)
		}
	}
	if config.OutputPath == "" {
		config.OutputPath = "." // Default to current directory
	}

	fmt.Println("Create directories")
	// Create the directory if it doesn't exist
	if err := os.MkdirAll(config.OutputPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output path %s: %v", config.OutputPath, err)
	}

	t := &StateAccessTracer{
		config:         &config,
		allTraces:      make(map[common.Hash]*TxTrace),
		blockTraceData: make([]*TxTrace, 0),
	}

	fmt.Println("Return tracing hooks")
	return &tracing.Hooks{
		OnOpcode:			t.OnOpcode,
		OnFault:			t.OnFault,
		OnTxStart:			t.OnTxStart,
		OnTxEnd:			t.OnTxEnd,
		OnBlockStart:		t.OnBlockStart,		
		OnBlockEnd:			t.OnBlockEnd,
		OnBlockEndMetrics:	t.OnBlockEndMetrics,
		// These ones below are all called in 
		OnBalanceChange:	t.OnBalanceChange,
		OnNonceChangeV2:	t.OnNonceChangeV2,
		OnCodeChange:		t.OnCodeChange,
		OnStorageChange:	t.OnStorageChange,
		OnBlockHashRead:	t.OnBlockHashRead,
		CaptureArbitrumTransfer:		t.CaptureArbitrumTransfer,
		CaptureArbitrumStorageGet:	t.CaptureArbitrumStorageGet,
		CaptureArbitrumStorageSet:	t.CaptureArbitrumStorageSet,
	}, nil

}

func (t *StateAccessTracer) OnFault(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, depth int, err error) { }

// StateAccessTracer implements both tracers.Tracer and tracers.StructLogger.
type StateAccessTracer struct {
	config *StateAccessConfig
	mu     sync.RWMutex

	allTraces      map[common.Hash]*TxTrace // Map to hold traces *during* block processing
	blockTraceData []*TxTrace               // List to hold all *completed* tx traces for the block

	// Current tx state
	currentBlockNo *big.Int
	currentTxIndex uint
	currentTrace   *TxTrace
	currentTxHash  common.Hash
}

// CaptureStart is called *before* the EVM execution of the top-level transaction.
func (t *StateAccessTracer) OnBlockStart(ev tracing.BlockEvent) { 
	t.mu.Lock()
	defer t.mu.Unlock()

	// validate that everything was cleared
	if t.currentTrace != nil || len(t.allTraces) != 0 || len(t.blockTraceData) != 0 {
		log.Error("Previous block's data not cleraed", "currentTrace", t.currentTrace != nil, "allTraces", len(t.allTraces), "blockTraceData", len(t.blockTraceData))
		panic("")
	}
	t.currentBlockNo = ev.Block.Number()
}

func (t *StateAccessTracer) OnTxStart(vm *tracing.VMContext, tx *types.Transaction, from common.Address) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// since OnBlockEnd won't be used, if the block numbe of this new transaction is different
	// from the previous transaction then a block boundary is hit and save the previous block to file
	if t.currentBlockNo.Cmp(vm.BlockNumber) != 0 {
		log.Error("Transaction not in the right block", "currentBlockNo", t.currentBlockNo.String(), "vm.BlockNumber", vm.BlockNumber.String())
	}

	hash := tx.Hash()
	// Use allTraces map to safely determine the index
	t.currentTxHash = hash
	t.currentTxIndex = uint(len(t.allTraces))

	t.currentTrace = &TxTrace{
		BlockNumber: 	vm.BlockNumber,
		TxHash: 	 	hash,
		TxIndex:     	t.currentTxIndex,
		//Changes:     	make([]*StateChange, 0), // This will be filled with the changes
		WriteAccesses: 	make([]KeyAccess, 0),
		ReadAccesses:	make([]KeyAccess, 0),
		
		Writes:			make(map[KeyAccess]bool),
		Reads:			make(map[KeyAccess]bool),
	}

	t.allTraces[hash] = t.currentTrace
}

func (t *StateAccessTracer) OnOpcode(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	opcode := vm.OpCode(op)

	if t.currentTrace == nil {
		log.Error("OnOpcode no OnTxStart", "opcode", opcode, "addr", scope.Address())
		panic("")
	}

	stack := scope.StackData()
	stacklen := len(stack)

	if IsStorageRead(opcode) {		// SLOAD
		slot := common.Hash(stack[stacklen-1].Bytes32())
		addr := scope.Address()

		k := KeyAccess{OPCODE, KeyPair{addr, slot}}
		t.currentTrace.Reads[k] = true
	} else if IsStorageWrite(opcode) {		// SSTORE
		slot := common.Hash(stack[stacklen-1].Bytes32())
		addr := scope.Address()

		k := KeyAccess{OPCODE, KeyPair{addr, slot}}
		t.currentTrace.Writes[k] = true
	} else if IsBalance(opcode) {	// BALANCE
		addr := common.Address(stack[stacklen-1].Bytes20())
		k := KeyAccess{BALANCE, KeyPair{addr, common.Hash{}}}

		t.currentTrace.Reads[k] = true
	}
}

func (t *StateAccessTracer) OnStorageChange(addr common.Address, slot common.Hash, prev, new common.Hash) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.currentTrace == nil {
		log.Error("OnStorageChange no OnTxStart", "addr", addr, "slot", slot)
		panic("")
	}

	k := KeyAccess{HOOK, KeyPair{addr, slot}}
	t.currentTrace.Writes[k] = true
}

func (t *StateAccessTracer) OnBalanceChange(addr common.Address, prev, new *big.Int, reason tracing.BalanceChangeReason) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.currentTrace == nil {
		log.Error("OnBalanceChange no OnTxStart", "addr", addr, "prev", prev.String(), "new", new.String(), "reason", reason)
		panic("")
	}

	k := KeyAccess{BALANCE, KeyPair{addr, common.Hash{}}}
	t.currentTrace.Writes[k] = true
}

func (t *StateAccessTracer) OnNonceChangeV2(addr common.Address, prev, new uint64, reason tracing.NonceChangeReason) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if prev == new {
		// there are some nonce changes that happen between tranasction boundaries
		return
	}

	if t.currentTrace == nil {
		log.Error("OnNonceChangeV2 no OnTxStart", "addr", addr, "prev", prev, "new", new, "reason", reason)
		panic("")
	}

	k := KeyAccess{NONCE, KeyPair{addr, common.Hash{}}}
	t.currentTrace.Writes[k] = true
}

// NOT USED FOR NOW
func (t *StateAccessTracer) OnBlockHashRead(blockNumber uint64, hash common.Hash) {
	//fmt.Println(fmt.Sprintf("OnBlockHashRead | block number %d, hash %v", blockNumber, hash))
}

func (t *StateAccessTracer) CaptureArbitrumStorageGet(key common.Hash, depth int, before bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	
	log.Info("Arb storage get")

	if t.currentTrace == nil {
		log.Error("CatureArbitrumStorageGet no OnTxStart", "key", key)
		panic("")
	}

	k := KeyAccess{ARB, KeyPair{common.Address{}, key}}
	t.currentTrace.Reads[k] = true
}

func (t *StateAccessTracer) CaptureArbitrumStorageSet(key, value common.Hash, depth int, before bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.currentTrace == nil {
		log.Error("CatureArbitrumStorageSet no OnTxStart", "key", key, "value", value)
		panic("")
	}

	k := KeyAccess{ARB, KeyPair{common.Address{}, key}}
	t.currentTrace.Writes[k] = true
}

func (t *StateAccessTracer) CaptureArbitrumTransfer(from, to *common.Address, value *big.Int, before bool, reason tracing.BalanceChangeReason) {
	t.mu.Lock()
	defer t.mu.Unlock()

	fromS := common.Address{}
	toS := common.Address{}
	
	if from != nil {
		fromS = *from
	}
	if to != nil {
		toS = *to
	}

	if t.currentTrace == nil {
		log.Error("CaptureArbitrumTransfer no OnTxStart", "from", fromS, "to", toS, "value", value.String())
		panic("")
	}

	kfrom := KeyAccess{ARBTRANSFER, KeyPair{fromS, common.Hash{}}}
	kto := KeyAccess{ARBTRANSFER, KeyPair{toS, common.Hash{}}}

	t.currentTrace.Writes[kfrom] = true
	t.currentTrace.Writes[kto] = true
}

func (t *StateAccessTracer) OnCodeChange(addr common.Address, prevCodeHash common.Hash, prevCode []byte, codeHash common.Hash, code []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.currentTrace == nil {
		log.Error("OnCodeChange no OnTxStart", "addr", addr)
		panic("")
	}

	k := KeyAccess{CODE, KeyPair{addr, common.Hash{}}}
	t.currentTrace.Writes[k] = true
}

// CaptureTxEnd is called at the end of each transaction.
// We no longer write the file here. We just aggregate the data.
func (t *StateAccessTracer) OnTxEnd(receipt *types.Receipt, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.currentTrace == nil {
		// Should not happen if OnTxStart was called, but good to check.
		log.Error("Empty transaction??")
		panic("")
	}

	// tx is done, we have all the data in currentTrace and we append the current Trace to the block traces
	// but first some validation checls
	if receipt != nil {
		if receipt.BlockNumber.Cmp(t.currentBlockNo) != 0 {
			log.Error("Ending a different block than started with", "currentBlockNumber", t.currentBlockNo.String(), "receipt", receipt.BlockNumber.String())
			panic("")
		}

		if receipt.TransactionIndex != t.currentTxIndex {
			log.Error("Transaction index in receipt differs from us.", "us", t.currentTxIndex, "receipt", receipt.TransactionIndex)
			panic("")
		}
	} else {
		log.Error("OnTxEnd | no receipt...", "err", err)
		panic("")
	}

	
	// Move data in Writes and Reads into WriteAccesses and ReadAccesses because
	// that is what will be written to file
	t.currentTrace.WriteAccesses = make([]KeyAccess, 0, len(t.currentTrace.Writes))
	t.currentTrace.ReadAccesses = make([]KeyAccess, 0, len(t.currentTrace.Reads))

	for k := range t.currentTrace.Writes {
		t.currentTrace.WriteAccesses = append(t.currentTrace.WriteAccesses, k)
	}
	for k := range t.currentTrace.Reads {
		t.currentTrace.ReadAccesses = append(t.currentTrace.ReadAccesses, k)
	}

	t.currentTrace.Writes = nil
	t.currentTrace.Reads = nil

	// Add the gas amounts
	t.currentTrace.CumulativeGas = receipt.CumulativeGasUsed
	t.currentTrace.GasUsed = receipt.GasUsed
	t.currentTrace.GasUsedForL1 = receipt.GasUsedForL1
	t.currentTrace.TxType = receipt.Type

	t.blockTraceData = append(t.blockTraceData, t.currentTrace)
	t.currentTrace = nil
}

func (t *StateAccessTracer) OnBlockEnd(err error) {
}

// CaptureEnd is the *block-level* hook.
// This is where we write the aggregated block file.
// **NOTE: This hook is NOT called by the Nitro L2 execution engine.**
//func (t *StateAccessTracer) OnBlockEnd(output []byte, gasUsed uint64, duration time.Duration, err error) {
func (t *StateAccessTracer) OnBlockEndMetrics(blockNumber uint64, blockInsertDuration time.Duration) {
	
	if t.currentBlockNo.Uint64() != blockNumber {
		log.Error("OnBlocENd block numbers differ", "ours", t.currentBlockNo.Uint64(), "hook", blockNumber)
		panic("")
	}

	// even if there are no transactions here, i.e. len(blockTraceData) = 0, we should log an empty block
	// just for completeness
	blockTrace := BlockTrace{
		BlockNumber: t.currentBlockNo,
		Traces: t.blockTraceData,
	}

	// Write to a block-specific file
	fileName := fmt.Sprintf("%s/state_trace_block_%s.json", t.config.OutputPath, t.currentBlockNo.String())
	file, err := os.Create(fileName)
	if err != nil {
		log.Error("[StateAccessTracer] Failed to create file", "name", fileName, "err", err)
		panic("")
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(blockTrace); err != nil {
		log.Error("[StateAccessTracer] failed to write json to file", "name", fileName, "err", err)
		panic("")
	}

	// all transactions are written to the file so clear everything to start again 
	// for this new transaction we are about to process after this if block ends
	t.allTraces = make(map[common.Hash]*TxTrace)
	t.blockTraceData = make([]*TxTrace, 0)
}
