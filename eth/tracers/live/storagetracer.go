
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
)

// StateAccess encompasses everything that touches the chain state excluding arbitrum state stuff (I think)
// We record opcode accesses and StorageChange accesses differently and the Type variable indicates which this is
// we record both to make sure we don't miss anything, because SSTORE to the same current value of the slot
// isn't captured in StorageChange
type StateAccess struct {
	Type     string         `json:"type"`
	Read     bool           `json:"read"`
	Address  common.Address `json:"address"`
	Slot     common.Hash    `json:"slot,omitempty"`
	OldValue string         `json:"oldValue,omitempty"`
	NewValue string         `json:"newValue"`
}

type BalanceAccess struct {
	Address common.Address	`json:"address"`
	Read	bool			`json:"read"`
	Prev	uint64			`json:"prev"`
	New		uint64			`json:"new"`
}

type NonceChange struct {
	Address common.Address	`json:"address"`
	Prev	uint64			`json:"prev"`		
	New		uint64			`json:"new"`
}

// NOT USED FOR NOW
type BlockHashRead struct {
	BlockNumber uint64			`json:"number"`
	BlockHash	common.Hash		`json:"hash"`
}

type ArbitrumAccess struct {
	Type	string			`json:"type"`
	Read	bool			`json:"read"`
	Key		common.Hash		`json:"key"`
	Value	common.Hash		`json:"value,omitempty"`
}

type ArbitrumTransfer struct {
	From	common.Address					`json:"from"`
	To		common.Address					`json:"to"`
	Value	uint64							`json:"value"`
	Reason	tracing.BalanceChangeReason		`json:"reason"`
}

// 1 - StateAccess
// 2 - BalanceAccess
// 3 - NonceChange
// 4 - BlockHashRead 
// 5 - ArbitrumAccess
// 6 - ArbitrumTransfer
type Access struct {
	Type int	
	Access		*StateAccess		`json:"access,omitempty"`
	Balance		*BalanceAccess		`json:"balance,omitempty"`
	Nonce		*NonceChange		`json:"nonce,omitempty"`
	BlockHash	*BlockHashRead		`json:"blockhash,omitempty"`
	ArbState	*ArbitrumAccess		`json:"arbstate,omitempty"`
	ArbSend		*ArbitrumTransfer	`json:"arbsend,omitempty"`
}	


// TxTrace holds all state changes for a single transaction.
type TxTrace struct {
	BlockNumber *big.Int       `json:"blockNumber"`
	TxIndex     int            `json:"txIndex"`
	TxHash		common.Hash	   `json:"slot,omitempty"`
	//Changes     []*StateChange `json:"changes"` // This will be empty
	Acceses		[]*Access		`json:"acceses"`
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
	//tracers.Register("stateAccessTracer", newStateAccessTracer)
	fmt.Println("Registering storage tracer...")
	tracers.LiveDirectory.Register("stateAccessTracer", NewStateAccessTracer)
}

// newStateAccessTracer is the constructor called by the tracer framework.
//func NewStateAccessTracer(ctx *tracers.Context, cfg json.RawMessage) (tracers.Tracer, error) {
func NewStateAccessTracer(cfg json.RawMessage) (*tracing.Hooks, error) {
	fmt.Println("NewStateAccessTracer")
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
		OnBlockStart:		t.OnBlockStart,				// These two are onl called in core.ProcesBlock
		OnBlockEnd:			t.OnBlockEnd,				// and that is never called in Nitro so they're empty
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
func (t *StateAccessTracer) OnBalanceChange(addr common.Address, prev, new *big.Int, reason tracing.BalanceChangeReason) {
	fmt.Println("OnBalanceChange | address %v, pev %s, new %s", addr, prev.String(), new.String())
}

func (t *StateAccessTracer) OnNonceChangeV2(addr common.Address, prev, new uint64, reason tracing.NonceChangeReason) {
	fmt.Println("OnNonceChangeV2 | address %v, prev %d, new %d", addr, prev, new)
}

func (t *StateAccessTracer) OnCodeChange(addr common.Address, prevCodeHash common.Hash, prevCode []byte, codeHash common.Hash, code []byte) {
	fmt.Println("OnCodeChange | address %v, prev %v", addr, prevCodeHash)
}

func (t *StateAccessTracer) OnStorageChange(addr common.Address, slot common.Hash, prev, new common.Hash) {
	fmt.Println("OnStorageChange | address %v, key %v, prev %v, new %v", addr, slot, prev, new)
}

func (t *StateAccessTracer) OnBlockHashRead(blockNumber uint64, hash common.Hash) {
	fmt.Println("OnBlockHashRead | block number %d, hash %v", blockNumber, hash)
}

func (t *StateAccessTracer) CaptureArbitrumTransfer(from, to *common.Address, value *big.Int, before bool, reason tracing.BalanceChangeReason) {
	fmt.Println("ArbitrumTransfer | from %v, to %v, value %s", *from, *to, value.String())
}

func (t *StateAccessTracer) CaptureArbitrumStorageGet(key common.Hash, depth int, before bool) {
	fmt.Println("ArbitrumStorageGet | key %v", key)
}

func (t *StateAccessTracer) CaptureArbitrumStorageSet(key, value common.Hash, depth int, before bool) {
	fmt.Println("ArbitrumStorageSet | key %v, value %v", key, value)
}


// StateAccessTracer implements both tracers.Tracer and tracers.StructLogger.
type StateAccessTracer struct {
	config *StateAccessConfig
	mu     sync.RWMutex

	allTraces      map[common.Hash]*TxTrace // Map to hold traces *during* block processing
	blockTraceData []*TxTrace               // List to hold all *completed* tx traces for the block

	// Current tx state
	currentBlockNo *big.Int
	currentTxIndex int
	currentTrace   *TxTrace
}

// --- Implement tracers.Tracer Interface ---

// CaptureStart is called *before* the EVM execution of the top-level transaction.
func (t *StateAccessTracer) OnBlockStart(ev tracing.BlockEvent) { 
	fmt.Println("OnBlockStart | Block number %d", ev.Block.Number())
}

// CaptureEnd is the *block-level* hook.
// This is where we write the aggregated block file.
// **NOTE: This hook is NOT called by the Nitro L2 execution engine.**
//func (t *StateAccessTracer) OnBlockEnd(output []byte, gasUsed uint64, duration time.Duration, err error) {
func (t *StateAccessTracer) OnBlockEnd(err error) { 
	fmt.Println("OnBlockEnd")
}

func (t *StateAccessTracer) OnBlockEndMetrics(blockNumber uint64, blockInsertDuration time.Duration) { }

func (t *StateAccessTracer) OnTxStart(vm *tracing.VMContext, tx *types.Transaction, from common.Address) {
	fmt.Println("OnTxStart | Block number %d", vm.BlockNumber)
	//t.mu.Lock()
	//defer t.mu.Unlock()

	//// since OnBlockEnd won't be used, if the block numbe of this new transaction is different
	//// from the previous transaction then a block boundary is hit and save the previous block to file
	//if t.currentTrace != nil {
	//	currBlockNumber := vm.BlockNumber
	//	if currBlockNumber.Cmp(t.currentTrace.BlockNumber) != 0 {
	//		// this is a new block so commit the previous info to file
	//		if len(t.blockTraceData) == 0 {
	//			return // Nothing to write
	//		}
	//	
	//		// it shouldn't be the case that the block number isn't known
	//		// but check anyway and save the string as "unkown" in case
	//		blockNum := "unknown"
	//		//if t.ctx.BlockNumber != nil {
	//		if t.currentTrace.BlockNumber != nil {
	//			blockNum = t.currentTrace.BlockNumber.String()
	//		}

	//		// we don't care about the hash of the block on the block trace
	//		// it is useless data in this case
	//		blockTrace := BlockTrace{
	//			BlockNumber: currBlockNumber,
	//			Traces:      t.blockTraceData,
	//		}

	//		// Write to a block-specific file
	//		fileName := fmt.Sprintf("%s/state_trace_block_%s.json", t.config.OutputPath, blockNum)
	//		file, err := os.Create(fileName)
	//		if err != nil {
	//			fmt.Fprintf(os.Stderr, "[StateAccessTracer] Failed to create trace file %s: %v\n", fileName, err)
	//			return
	//		}
	//		defer file.Close()

	//		encoder := json.NewEncoder(file)
	//		encoder.SetIndent("", "  ")
	//		if err := encoder.Encode(blockTrace); err != nil {
	//			fmt.Fprintf(os.Stderr, "[StateAccessTracer] Failed to write trace to file %s: %v\n", fileName, err)
	//		}

	//		// all transactions are written to the file so clear everything to start again 
	//		// for this new transaction we are about to process after this if block ends
	//		t.allTraces = make(map[common.Hash]*TxTrace)
	//		t.blockTraceData = make([]*TxTrace, 0)
	//	}
	//	t.currentTrace = nil
	//	t.currentTxHash = common.Hash{}
	//}

	//hash := tx.Hash()
	//// Use allTraces map to safely determine the index
	//t.currentTxHash = hash
	//t.currentTxIndex = len(t.allTraces)

	//t.currentTrace = &TxTrace{
	//	BlockNumber: vm.BlockNumber,
	//	TxHash: 	 hash,
	//	TxIndex:     t.currentTxIndex,
	//	Changes:     make([]*StateChange, 0), // This will remain empty
	//}

	//t.allTraces[hash] = t.currentTrace

}

func IsStorageRead(opcode vm.OpCode) bool {
	return opcode == vm.SLOAD
}

func IsStorageWrite(opcode vm.OpCode) bool {
	return opcode == vm.SSTORE
}

func (t *StateAccessTracer) OnOpcode(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
	//t.mu.Lock()
	//defer t.mu.Unlock()
	opcode := vm.OpCode(op)
	stack := scope.StackData()
	stacklen := len(stack)
	if IsStorageRead(opcode) {
		fmt.Println("SLOAD | address %v, key %v", scope.Address(), common.Hash(stack[stacklen-1].Bytes32()))
		//slot := common.Hash(stack[stacklen-1].Bytes32())
	} else if IsStorageWrite(opcode) {
		fmt.Println("SSTORE | adress %v, key %v, value %v", scope.Address(), common.Hash(stack[stacklen-1].Bytes32()), common.Hash(stack[stacklen-2].Bytes32()))
	}
}

// CaptureTxEnd is called at the end of each transaction.
// We no longer write the file here. We just aggregate the data.
func (t *StateAccessTracer) OnTxEnd(receipt *types.Receipt, err error) {
	fmt.Println("OnTxEnd | Block number %d, Transaction index %d", receipt.BlockNumber, receipt.TransactionIndex)
	//t.mu.Lock()
	//defer t.mu.Unlock()

	//if t.currentTrace == nil {
	//	// Should not happen if OnTxStart was called, but good to check.
	//	return
	//}

	//// Finalize and append the trace to the block's list
	//t.blockTraceData = append(t.blockTraceData, t.currentTrace)

	// Clear current transaction state
	//t.currentTrace = nil
}

// --- REMOVED STATE HOOKS ---
// The following methods (CaptureStorageRead, CaptureBalanceWrite, etc.)
// do not exist on the tracers.StructLogger interface at commit 8a58712...
// and have been removed to allow the tracer to compile.

// --- Other StructLogger methods (No-Op) ---

func (t *StateAccessTracer) CaptureStart(evm *vm.EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	// No-op for this tracer (traces internal calls)
}
func (t *StateAccessTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {
	// No-op for this tracer (traces internal calls)
}
func (t *StateAccessTracer) CaptureEnter(typ vm.OpCode, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	// No-op
}
func (t *StateAccessTracer) CaptureExit(output []byte, gasUsed uint64, err error) {
	// No-op
}
func (t *StateAccessTracer) OnFault(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, depth int, err error) {
	// No-op
}
func (t *StateAccessTracer) CaptureLog(log *types.Log) {
	// No-op
}
