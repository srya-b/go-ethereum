
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


// TxTrace holds all state changes for a single transaction.
type VerboseTxTrace struct {
	BlockNumber *big.Int       `json:"blockNumber"`
	TxIndex     uint            `json:"txIndex"`
	TxHash		common.Hash	   `json:"slot,omitempty"`
	//Changes     []*StateChange `json:"changes"` // This will be empty
	Accesses	[]*Access		`json:"acceses"`
}

// BlockTrace is the final output file, containing all tx traces for a block.
type VerboseBlockTrace struct {
	BlockNumber *big.Int   `json:"blockNumber"`
	Traces      []*VerboseTxTrace  `json:"transactions"`
}

// VerboseStateAccessConfig holds the configuration for the tracer.
type VerboseStateAccessConfig struct {
	// OutputPath specifies the directory to write trace files to.
	OutputPath string `json:"path"`
}

// Register the tracer in the live tracer framework.
func init() {
	//tracers.Register("stateAccessTracer", newStateAccessTracer)
	fmt.Println("Registering verbose storage tracer...")
	tracers.LiveDirectory.Register("verboseStateAccessTracer", NewVerboseStateAccessTracer)
}

// newStateAccessTracer is the constructor called by the tracer framework.
//func NewStateAccessTracer(ctx *tracers.Context, cfg json.RawMessage) (tracers.Tracer, error) {
func NewVerboseStateAccessTracer(cfg json.RawMessage) (*tracing.Hooks, error) {
	fmt.Println("NewStateAccessTracer")
	var config VerboseStateAccessConfig
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

	t := &VerboseStateAccessTracer{
		config:         &config,
		allTraces:      make(map[common.Hash]*VerboseTxTrace),
		blockTraceData: make([]*VerboseTxTrace, 0),
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

func (t *VerboseStateAccessTracer) OnFault(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, depth int, err error) { }

// VerboseStateAccessTracer implements both tracers.Tracer and tracers.StructLogger.
type VerboseStateAccessTracer struct {
	config *VerboseStateAccessConfig
	mu     sync.RWMutex

	allTraces      map[common.Hash]*VerboseTxTrace // Map to hold traces *during* block processing
	blockTraceData []*VerboseTxTrace               // List to hold all *completed* tx traces for the block

	// Current tx state
	currentBlockNo *big.Int
	currentTxIndex uint
	currentTrace   *VerboseTxTrace
	currentTxHash  common.Hash
}

// CaptureStart is called *before* the EVM execution of the top-level transaction.
func (t *VerboseStateAccessTracer) OnBlockStart(ev tracing.BlockEvent) { 
	t.mu.Lock()
	defer t.mu.Unlock()
	log.Info("OnBlockStart", "Block number", ev.Block.Number())

	// validate that everything was cleared
	if t.currentTrace != nil || len(t.allTraces) != 0 || len(t.blockTraceData) != 0 {
		log.Error("Previous block's data not cleraed", "currentTrace", t.currentTrace != nil, "allTraces", len(t.allTraces), "blockTraceData", len(t.blockTraceData))
		panic("")
	}
	t.currentBlockNo = ev.Block.Number()
}

func (t *VerboseStateAccessTracer) OnTxStart(vm *tracing.VMContext, tx *types.Transaction, from common.Address) {
	t.mu.Lock()
	defer t.mu.Unlock()
	log.Info("OnTxStart", "Block number", vm.BlockNumber)

	// since OnBlockEnd won't be used, if the block numbe of this new transaction is different
	// from the previous transaction then a block boundary is hit and save the previous block to file
	if t.currentBlockNo.Cmp(vm.BlockNumber) != 0 {
		log.Error("Transaction not in the right block", "currentBlockNo", t.currentBlockNo.String(), "vm.BlockNumber", vm.BlockNumber.String())
	}

	hash := tx.Hash()
	// Use allTraces map to safely determine the index
	t.currentTxHash = hash
	t.currentTxIndex = uint(len(t.allTraces))

	t.currentTrace = &VerboseTxTrace{
		BlockNumber: vm.BlockNumber,
		TxHash: 	 hash,
		TxIndex:     t.currentTxIndex,
		//Changes:     make([]*StateChange, 0), // This will be filled with the changes
		Accesses:	 make([]*Access, 0),
	}

	t.allTraces[hash] = t.currentTrace
}


// 1 - StateAccess
// 2 - BalanceAccess
// 3 - NonceChange
// 4 - BlockHashRead 
// 5 - ArbitrumAccess
// 6 - ArbitrumTransfer
// 7 - CodeChange
type Access struct {
	Type int	
	Access		*StateAccess		`json:"access,omitempty"`
	Balance		*BalanceAccess		`json:"balance,omitempty"`
	Nonce		*NonceChange		`json:"nonce,omitempty"`
	BlockHash	*BlockHashRead		`json:"blockhash,omitempty"`
	ArbState	*ArbitrumAccess		`json:"arbstate,omitempty"`
	ArbSend		*ArbitrumTransfer	`json:"arbsend,omitempty"`
	Code		*CodeChange			`json:"codechange,omitempyy"`
}	

// StateAccess encompasses everything that touches the chain state excluding arbitrum state stuff (I think)
// We record opcode accesses and StorageChange accesses differently and the Type variable indicates which this is
// we record both to make sure we don't miss anything, because SSTORE to the same current value of the slot
// isn't captured in StorageChange
type StateAccess struct {
	Type     string         `json:"type"`
	Read     bool           `json:"read"`
	Address  common.Address `json:"address"`
	Slot     common.Hash    `json:"slot"`
	OldValue common.Hash     `json:"oldValue"`
	NewValue common.Hash     `json:"newValue"`
}

func (t *VerboseStateAccessTracer) OnOpcode(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	opcode := vm.OpCode(op)
	log.Info("OnOpcode", "address", scope.Address(), "opcode", opcode)

	if t.currentTrace == nil {
		log.Error("OnOpcode no OnTxStart", "opcode", opcode, "addr", scope.Address())
		panic("")
	}

	stack := scope.StackData()
	stacklen := len(stack)

	if IsStorageRead(opcode) {		// SLOAD
		s := &StateAccess {
				Type:		"opcode",
				Read:		true,
				Address:	scope.Address(),
				Slot:		common.Hash(stack[stacklen-1].Bytes32()),
		}

		a := &Access{
				Type:	1,
				Access:	s,
		}
		t.currentTrace.Accesses = append(t.currentTrace.Accesses, a)

	} else if IsStorageWrite(opcode) {		// SSTORE
		s := &StateAccess{
				Type:		"opcode",
				Read:		false,
				Address:	scope.Address(),
				Slot:		common.Hash(stack[stacklen-1].Bytes32()),
				NewValue:	common.Hash(stack[stacklen-2].Bytes32()),
		}

		a := &Access{
				Type:	1,
				Access: s,
		}
		t.currentTrace.Accesses = append(t.currentTrace.Accesses, a)
	} else if IsBalance(opcode) {	// BALANCE
		b := &BalanceAccess {
				Address:	common.Address(stack[stacklen-1].Bytes20()),
				Read:		true,
		}

		a := &Access{
				Type: 		2,
				Balance:	b,
		}
		t.currentTrace.Accesses = append(t.currentTrace.Accesses, a)
	}
}

func (t *VerboseStateAccessTracer) OnStorageChange(addr common.Address, slot common.Hash, prev, new common.Hash) {
	t.mu.Lock()
	defer t.mu.Unlock()
	log.Info("OnStorageChange", "address", addr)

	if t.currentTrace == nil {
		log.Error("OnStorageChange no OnTxStart", "addr", addr, "slot", slot)
		panic("")
	}

	s := &StateAccess{
			Type:		"hook",
			Read:		false,
			Address:	addr,
			Slot:		slot,
			OldValue:	prev,
			NewValue:   new,
	}

	a := &Access{
			Type:	1,
			Access: s,
	}
	t.currentTrace.Accesses = append(t.currentTrace.Accesses, a)
}

type BalanceAccess struct {
	Address common.Address	`json:"address"`
	Read	bool			`json:"read"`
	Prev	string			`json:"prev"`
	New		string			`json:"new"`
}

func (t *VerboseStateAccessTracer) OnBalanceChange(addr common.Address, prev, new *big.Int, reason tracing.BalanceChangeReason) {
	t.mu.Lock()
	defer t.mu.Unlock()
	log.Info("OnBalanceChange", "addr", addr, "prev", prev.String(), "new", new.String())

	if t.currentTrace == nil {
		log.Error("OnBalanceChange no OnTxStart", "addr", addr, "prev", prev.String(), "new", new.String(), "reason", reason)
		panic("")
	}

	b := &BalanceAccess{
		Address: addr,
		Read:	 false,
		Prev:	 prev.String(),
		New:	 new.String(),
	}

	a := &Access{
		Type:		2,
		Balance:	b,
	}

	t.currentTrace.Accesses = append(t.currentTrace.Accesses, a)
}

type NonceChange struct {
	Address common.Address	`json:"address"`
	Prev	uint64			`json:"prev"`		
	New		uint64			`json:"new"`
}

func (t *VerboseStateAccessTracer) OnNonceChangeV2(addr common.Address, prev, new uint64, reason tracing.NonceChangeReason) {
	t.mu.Lock()
	defer t.mu.Unlock()
	log.Info("OnNonceChangeV2", "addr", addr, "prev", prev, "new", new)
	if prev == new {
		// there are some nonce changes that happen between tranasction boundaries
		return
	}

	if t.currentTrace == nil {
		log.Error("OnNonceChangeV2 no OnTxStart", "addr", addr, "prev", prev, "new", new, "reason", reason)
		panic("")
	}

	n := &NonceChange{
		Address:	addr,
		Prev:		prev,
		New:		new,
	}

	a := &Access{
		Type: 	3,
		Nonce: 	n,
	}
	t.currentTrace.Accesses = append(t.currentTrace.Accesses, a)
}

// NOT USED FOR NOW
type BlockHashRead struct {
	BlockNumber uint64			`json:"number"`
	BlockHash	common.Hash		`json:"hash"`
}

func (t *VerboseStateAccessTracer) OnBlockHashRead(blockNumber uint64, hash common.Hash) {
	//fmt.Println(fmt.Sprintf("OnBlockHashRead | block number %d, hash %v", blockNumber, hash))
}

type ArbitrumAccess struct {
//	Type	string			`json:"type"`
	Read	bool			`json:"read"`
	Key		common.Hash		`json:"key"`
	Value	common.Hash		`json:"value"`
}

func (t *VerboseStateAccessTracer) CaptureArbitrumStorageGet(key common.Hash, depth int, before bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	log.Info("ArbStorageGet", "key", key)

	if t.currentTrace == nil {
		log.Error("CatureArbitrumStorageGet no OnTxStart", "key", key)
		panic("")
	}

	arb := &ArbitrumAccess{
		Read:	true,
		Key:	key,
	}

	a := &Access{
		Type:		5,
		ArbState:	arb,
	}

	t.currentTrace.Accesses = append(t.currentTrace.Accesses, a)
}

func (t *VerboseStateAccessTracer) CaptureArbitrumStorageSet(key, value common.Hash, depth int, before bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	log.Info("ArbStorageSet", "key", key)

	if t.currentTrace == nil {
		log.Error("CatureArbitrumStorageSet no OnTxStart", "key", key, "value", value)
		panic("")
	}

	arb := &ArbitrumAccess{
		Read:	false,
		Key:	key,
		Value:	value,
	}

	a := &Access{
		Type:		5,
		ArbState:	arb,
	}
	t.currentTrace.Accesses = append(t.currentTrace.Accesses, a)
}

type ArbitrumTransfer struct {
	From	common.Address					`json:"from"`
	To		common.Address					`json:"to"`
	Value	string							`json:"value"`
	Reason	tracing.BalanceChangeReason		`json:"reason"`
}

func (t *VerboseStateAccessTracer) CaptureArbitrumTransfer(from, to *common.Address, value *big.Int, before bool, reason tracing.BalanceChangeReason) {
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
	log.Info("ArbTransfer", "from", fromS, "to", toS)

	if t.currentTrace == nil {
		log.Error("CaptureArbitrumTransfer no OnTxStart", "from", fromS, "to", toS, "value", value.String())
		panic("")
	}


	arb := &ArbitrumTransfer{
		From:	fromS,
		To:		toS,
		Value: 	value.String(),
	}

	a := &Access{
		Type:		6,
		ArbSend:	arb,
	}

	t.currentTrace.Accesses = append(t.currentTrace.Accesses, a)
}

type CodeChange struct {
	Address		common.Address	`json:"address"`
	Prev		common.Hash		`json:"prev"`
	CodeHash	common.Hash		`json:"codehash"`
}

func (t *VerboseStateAccessTracer) OnCodeChange(addr common.Address, prevCodeHash common.Hash, prevCode []byte, codeHash common.Hash, code []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	log.Info("OnCodeChange", "addr", addr)

	if t.currentTrace == nil {
		log.Error("OnCodeChange no OnTxStart", "addr", addr)
		panic("")
	}

	c := &CodeChange{
		Address:	addr,
		Prev:		prevCodeHash,
		CodeHash:	codeHash,
	}

	a := &Access{
		Type:	7,
		Code:	c,
	}

	t.currentTrace.Accesses = append(t.currentTrace.Accesses, a)
}

// CaptureTxEnd is called at the end of each transaction.
// We no longer write the file here. We just aggregate the data.
func (t *VerboseStateAccessTracer) OnTxEnd(receipt *types.Receipt, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	log.Info("OnTxEnd", "block number", receipt.BlockNumber)

	if t.currentTrace == nil {
		// Should not happen if OnTxStart was called, but good to check.
		log.Error("Empty block...")
		return
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
	}

	t.blockTraceData = append(t.blockTraceData, t.currentTrace)
	t.currentTrace = nil
}

func (t *VerboseStateAccessTracer) OnBlockEnd(err error) {
	log.Info("OnBlockEnd")
}

// CaptureEnd is the *block-level* hook.
// This is where we write the aggregated block file.
// **NOTE: This hook is NOT called by the Nitro L2 execution engine.**
//func (t *VerboseStateAccessTracer) OnBlockEnd(output []byte, gasUsed uint64, duration time.Duration, err error) {
func (t *VerboseStateAccessTracer) OnBlockEndMetrics(blockNumber uint64, blockInsertDuration time.Duration) {
	log.Info("OnBlockEndMetrics", "block number", blockNumber)
	
	if t.currentBlockNo.Uint64() != blockNumber {
		log.Error("OnBlocENd block numbers differ", "ours", t.currentBlockNo.Uint64(), "hook", blockNumber)
		panic("")
	}

	// even if there are no transactions here, i.e. len(blockTraceData) = 0, we should log an empty block
	// just for completeness
	blockTrace := VerboseBlockTrace{
		BlockNumber: t.currentBlockNo,
		Traces: t.blockTraceData,
	}

	// Write to a block-specific file
	fileName := fmt.Sprintf("%s/state_trace_block_%s.json", t.config.OutputPath, t.currentBlockNo.String())
	file, err := os.Create(fileName)
	if err != nil {
		log.Error("[VerboseStateAccessTracer] Failed to create file", "name", fileName, "err", err)
		panic("")
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(blockTrace); err != nil {
		log.Error("[VerboseStateAccessTracer] failed to write json to file", "name", fileName, "err", err)
		panic("")
	}

	// all transactions are written to the file so clear everything to start again 
	// for this new transaction we are about to process after this if block ends
	t.allTraces = make(map[common.Hash]*VerboseTxTrace)
	t.blockTraceData = make([]*VerboseTxTrace, 0)

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
	//		blockTrace := VerboseBlockTrace{
	//			BlockNumber: currBlockNumber,
	//			Traces:      t.blockTraceData,
	//		}

	//		// Write to a block-specific file
	//		fileName := fmt.Sprintf("%s/state_trace_block_%s.json", t.config.OutputPath, blockNum)
	//		file, err := os.Create(fileName)
	//		if err != nil {
	//			fmt.Fprintf(os.Stderr, "[VerboseStateAccessTracer] Failed to create trace file %s: %v\n", fileName, err)
	//			return
	//		}
	//		defer file.Close()

	//		encoder := json.NewEncoder(file)
	//		encoder.SetIndent("", "  ")
	//		if err := encoder.Encode(blockTrace); err != nil {
	//			fmt.Fprintf(os.Stderr, "[VerboseStateAccessTracer] Failed to write trace to file %s: %v\n", fileName, err)
	//		}

	//		// all transactions are written to the file so clear everything to start again 
	//		// for this new transaction we are about to process after this if block ends
	//		t.allTraces = make(map[common.Hash]*VerboseTxTrace)
	//		t.blockTraceData = make([]*VerboseTxTrace, 0)
	//	}
	//	t.currentTrace = nil
	//	t.currentTxHash = common.Hash{}
	//}
}
