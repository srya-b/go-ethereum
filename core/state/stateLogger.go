package state

import (
	"bytes"
	_"errors"
	"fmt"
	_"maps"
	_"math/big"
	_"slices"
	_"sort"
	_"sync"
	_"sync/atomic"
	_"time"
	"encoding/json"
	_"os"

	"github.com/ethereum/go-ethereum/common"
	_"github.com/ethereum/go-ethereum/core/rawdb"
	_"github.com/ethereum/go-ethereum/core/state/snapshot"
	_"github.com/ethereum/go-ethereum/core/stateless"
	_"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	_"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	_"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
	_"github.com/ethereum/go-ethereum/trie/trienode"
	_"github.com/ethereum/go-ethereum/trie/utils"
	"github.com/ethereum/go-ethereum/rlp"
	_"github.com/holiman/uint256"
	_"golang.org/x/sync/errgroup"
)

func (s *StateDB) accountToBytes(addr common.Address) []byte {
	obj, exist := s.stateObjects[addr]
	if !exist {
		s.findGetCreates(addr)
		panic(fmt.Sprintf("Called accountToEncodeNode with address not in stateObjects: %v", addr))
	}
	return stateObjectToBytes(obj)
}

func (s *StateDB) findStorageChangeInJournal(addr common.Address, key common.Hash) {
	for _, lentry := range s.journal.logEntries {
		switch logEntry := (lentry.Entry).(type) {
		case storageChange:
			a := logEntry.account
			k := logEntry.key
			if (addr.Cmp(a) == 0 && key.Cmp(k) == 0) {
				obj, exists := s.stateObjects[a]
				if !exists {
					panic("doesn't exist")
				}
				newval := obj.GetState(k)
				log.Info("Target entry", "addr", addr, "key", key, "prevvalue", logEntry.prevvalue, "new", newval)
			}
		}
	}
}

func (s *StateDB) findGetSets(addr common.Address, key common.Hash) {
	for idx, lentry := range s.journal.logEntries {
		switch logEntry := (lentry.Entry).(type) {
		case getStorageEntry:
			a := logEntry.account
			k := logEntry.key
			if (addr.Cmp(a) == 0 && key.Cmp(k) == 0) {
				log.Info("Get target.", "idx", idx, "addr", a, "key", k, "value", logEntry.value)
			}
		case storageChange:
			a := logEntry.account
			k := logEntry.key
			if (addr.Cmp(a) == 0 && key.Cmp(k) == 0) {
				obj, exists := s.stateObjects[a]
				if !exists {
					panic("doesn't exist")
				}
				newval := obj.GetState(k)
				log.Info("Target entry", "idx", idx, "addr", addr, "key", key, "prevvalue", logEntry.prevvalue, "new", newval)
			}
		}
	}
}

func (s *StateDB) findGetCreates(addr common.Address) {
	for idx, lentry := range s.journal.logEntries {
		switch logEntry := (lentry.Entry).(type) {
		case getStateObjectEntry:
			a := logEntry.account
			if addr.Cmp(a) == 0 {
				log.Info("Get obj target", "idx", idx, "addr", a, "revert", lentry.Reverted)
			}
		case createObjectChange:
			a := logEntry.account
			if addr.Cmp(a) == 0 {
				_, exists := s.stateObjects[a]
				if !exists {
					log.Error("obj doesn't exist")
				}
				log.Info("create obj target", "idx", idx, "addr", a, "revert", lentry.Reverted)
			}
		case selfDestructChange:
			a := logEntry.account
			if addr.Cmp(a) == 0 {
				log.Info("Self destruct target", "idx", idx, "addr", a, "revert", lentry.Reverted)
				_, ok := s.stateObjects[a]
				if ok {
					log.Info("is in state objects")
				} else {
					log.Info("not in stateObjects")
				}
			}
		case createContractChange:
			a := logEntry.account
			if addr.Cmp(a) == 0 {
				log.Info("create contract change", "idx", idx, "addr", a, "revert", lentry.Reverted)
				_, ok := s.stateObjects[a]
				if ok {
					log.Info("is in state objects")
				} else {
					log.Info("is NOT in stateObjects")
				}
			}
		}
	}
}

// Finalize logger
func (s *StateDB) LogFinalize() (map[common.Address][]common.Hash, map[common.Hash][]byte, map[KeyKey][]common.Hash, map[common.Hash][]byte) {
	//totalKeysInTrie := 0
	//totalAccountsInTrie := 0
	accounts := make(map[common.Address][]common.Hash)
	accountNodes := make(map[common.Hash][]byte)
	keys := make(map[KeyKey][]common.Hash)
	keyNodes := make(map[common.Hash][]byte)
	for idx, lentry := range s.journal.logEntries {
		var addr *common.Address
		var key *common.Hash
		var keykey KeyKey
		switch logEntry := (lentry.Entry).(type) {
		case createObjectChange:
			// this is a new stateObject so log the hash the value node representation of the state
			addr = &(logEntry.account)
			_, ok := s.stateObjects[*addr]
			_, ok = s.stateObjectsDestruct[*addr]
			log.Info("crate: Address in stateObjects", "addr", *addr, "ok", ok)
			log.Info("craete: Address destructed", "addr", *addr, "ok", ok)
			log.Info("create object", "addr", *addr)
			//if isArbosAddress(*addr) {
			//	continue
			//}
			rawNode := s.accountToBytes(*addr)
			// the node has no hash so we store the key and value as the same
			// convert it into a hashNode	
			rawNodeHash := common.BytesToHash(rawNode)
			// set it to nil because this is a new account
			// for all accounts that don't have a path then we know it's a new one
			//s.accountsSeen[*addr] = nil
			accounts[*addr] = nil
			//s.nodesForAccount[rawNodeHash] = rawNode
			accountNodes[rawNodeHash] = rawNode
		case createContractChange:
			// need to check if this already exists, sometimes the object is created before
			// the contract is "created"
			addr = &(logEntry.account)
			//_, ok := s.accountsSeen[*addr]
			_, ok := accounts[*addr]
			if ok {
				// this object is created and then set as a contract
				log.Info("contract crearte of existing obj", "addr", *addr)
			}
			//if isArbosAddress(*addr) {
			//	continue
			//}
			rawNode := s.accountToBytes(*addr)
			rawNodeHash := common.BytesToHash(rawNode)
			//s.accountsSeen[*addr] = nil
			//s.nodesForAccount[rawNodeHash] = rawNode
			accounts[*addr] = nil
			accountNodes[rawNodeHash] = rawNode
		case getStateObjectEntry:
			addr = logEntry.Account()
			//if isArbosAddress(*addr) {
			//	continue
			//}
			//_, ok := s.accountsSeen[*addr]
			_, ok := accounts[*addr]
			if !ok {
				// we haven't seen it so we store the nodes on the path
				res, _, pathHashes, rawNodesOnPath, err := s.trie.GetAccountLogged(*addr)
				log.Error("GetAccountLogged", "addr", *addr, "idx", idx, "res", res)
				if err != nil || len(pathHashes) == 0 || len(rawNodesOnPath) == 0 {
					// try stateObjects
					_, ok := s.stateObjects[*addr]
					log.Info("Addr in stateObjects?", "addr", *addr, "ok", ok)
					// try reader
					acct, err := s.reader.Account(*addr)
					log.Info("Reader check", "acct", acct, "err", err)

					//panic(err)
					panic("")
				}
				// what about getting addresses that don't exist?
				if res != nil {
					log.Info("Account in trie", "addr", addr)
					//totalAccountsInTrie++
					s.accountsInTrie[*addr] = true
				} else {
					log.Info("Account not in trie", "addr", addr)
				}
				//s.accountsSeen[*addr] = pathHashes
				accounts[*addr] = pathHashes
				//s.nodesForAccount[*addr] = rawNodesOnPath
				for _, rn := range rawNodesOnPath {
					//if len(rn) <= 32 {
					//	log.Info("raw node is less than 32 bytes")
					//} else {
					//	log.Info("raw node is larger than 32")
					//}
					n, err := trie.PublicDecodeNode(nil, rn)
					//if err != nil {
					//	// this might have failed because it's a value of some kind
					//	panic(err)
					//}
					if err == nil {
						//log.Info("log", "addr", *addr)
						//log.Info("decoded node", "n", n)
						//s.findGetCreates(*addr)
						hn := trie.HashNode(n)
						//oldrn, ok := s.nodesForAccount[hn]
						oldrn, ok := accountNodes[hn]
						
						if ok {
							// then the raw nodes should be the same
							if bytes.Compare(rn, oldrn) != 0 {
								panic(fmt.Sprintf("Same hash %v has two different raw nodes.", hn))
							}
						} else {
							//s.nodesForAccount[hn] = rn
							accountNodes[hn] = rn
						}
					} else {
						// if this is an error, then we assume that this is the raw account and it can't be decoded
						// therefore we should save the raw node make sure that we can decode this to a state object
						ret := new(types.StateAccount)
						err = rlp.DecodeBytes(rn, ret)
						if err != nil {
							log.Info("couldn't decode account", "idx", idx, "addr", *addr)
							panic(err)
						}
						// now save this valueNode in the map
						hn := trie.HashData(rn)
						//oldrn, ok := s.nodesForAccount[hn]
						oldrn, ok := accountNodes[hn]
						if ok {
							if bytes.Compare(rn, oldrn) != 0 {
								panic(fmt.Sprintf("Same hash %v has two different accounts", hn))
							}
						} else {
							//s.nodesForAccount[hn] = rn
							accountNodes[hn] = rn
						}
					}
				}
			}
		case getStorageEntry:
			addr = logEntry.Account()
			//if isArbosAddress(*addr) {
			//	continue
			//}
			key = logEntry.Key()
			keykey = KeyKey{*addr, *key}
			// ASSERT that we've sene the account before
			//_, ok := s.accountsSeen[*addr]
			_, ok := accounts[*addr]
			if !ok {
				panic(fmt.Sprintf("getStorage(addr=%v, key=%v) but addr not in accountsSeen", *addr, *key))
			}
		
			//_, ok = s.keysSeen[keykey]
			_, ok = keys[keykey]
			if !ok {
				log.Info("Getstorage", "addr", *addr, "k", *key)
				// get the stateObject first it should be in stateObjects
				obj, exist := s.stateObjects[*addr]
				if !exist {
					panic(fmt.Sprintf("Address %v not in stateObejcts", *addr))
				}
				//_, pathHashes, rawNodesOnPath := obj.GetStateLogged(*key)
				trieVal, pathHashes, rawNodesOnPath := obj.GetTrieStateLogged(*key)
				var testVal common.Hash
				testVal.SetBytes(nil)
				if trieVal.Cmp(testVal) == 0 {
					log.Error("Get of something that doesn't exist.", "addr", *addr, "key", *key)
				} else {
					if len(pathHashes) > 0 && len(rawNodesOnPath) > 0 {
						//totalKeysInTrie++
						s.keysInTrie[keykey] = true
					}
				}
				if len(pathHashes) == 0 || len(rawNodesOnPath) == 0 {
					// this is only accepted behavior if the root is nil otherwise at least the root 
					// is always accessed.
					log.Info("Get keykey", "a", keykey.addr, "k", keykey.key, "b", logEntry.value)
					log.Info("Stateobject", "obj", obj.data, "root", obj.data.Root)
					if obj.data.Root.Cmp(types.EmptyRootHash) == 0 {
						// it is correct to log nothing for this key get, maybe we just skip it altogether?
						continue
					} else {
						//s.findStorageChangeInJournal(*addr, *key)
						s.findGetSets(*addr, *key)
						panic(fmt.Sprintf("GetStorageLogged(addr=%v, key=%v, idx=%v) gave no data", *addr, *key, idx))
					}
				}
				//s.keysSeen[keykey] = pathHashes
				keys[keykey] = pathHashes
				//s.nodesForKey[keykey] = rawNodesOnPath
				for _, rn := range rawNodesOnPath {
					n, err := trie.PublicDecodeNode(nil, rn)
					//if err != nil {
					//	panic(err)
					//}
					if err == nil {
						hn := trie.HashNode(n)
						//oldrn, ok := s.nodesForKey[hn]
						oldrn, ok := keyNodes[hn]
						if ok {
							if bytes.Compare(rn, oldrn) != 0 {
								panic(fmt.Sprintf("Same hash %v has two different raw nodes.", hn))
							}
						} else {
							//s.nodesForKey[hn] = rn
							keyNodes[hn] = rn
						}
					} else {
						// this is a valuenode we do the normal check that the hash is in there
						hn := trie.HashData(rn)
						//oldrn, ok := s.nodesForKey[hn]
						oldrn, ok := keyNodes[hn]
						if ok {
							if bytes.Compare(rn, oldrn) != 0 {
								panic(fmt.Sprintf("Same hash %v hash two different valuenodes. rn=%v, oldrn=%v", hn, rn, oldrn))
							}
						} else {
							//s.nodesForKey[hn] = rn
							keyNodes[hn] = rn
						}
					}
				}
			}
		case storageChange:
			// we only care about NEW state created so that we can log that we've seen it		
			//prev := *(logEntry.prevvalue)
			//trimmedPrev := common.TrimLeftZeroes(prev[:])
			var testVal common.Hash
			testVal.SetBytes(nil)
			if logEntry.prevvalue.Cmp(testVal) == 0 {
			//if logEntry.prevvalue == nil {
			//if len(trimmedPrev) == 0 {
				// log this as a change
				addr = &(logEntry.account)
				key = &(logEntry.key)
				log.Info("Storage change from nil", "addr", *addr, "key", *key)
				keykey = KeyKey{*addr, *key}
				//_, ok := s.accountsSeen[*addr]
				_, ok := accounts[*addr]
				if !ok {
					panic(fmt.Sprintf("getStorage(addr=%v, key=%v) but addr not in accountsSeen", *addr, *key))
				}
				//_, ok = s.keysSeen[keykey]
				_, ok = keys[keykey]
				if ok {
					// this could have been seen before if a get was attempted for a 0 value
					log.Error("New keykey seen with prev=nil", "addr", *addr, "key", *key)
					//panic("New keykey is already seen!")
				}
				obj, exist := s.stateObjects[*addr]
				if !exist {
					panic(fmt.Sprintf("Address %v not in stateObejcts", *addr))
				}
				// GetStateLogged is called here because there is no "miss" for the storage change from nil
				// GetStateLogged is just to check that the get short circuits and gives no paths or nodes
				_, pathHashes, rawNodesOnPath := obj.GetStateLogged(*key)
				if !(len(pathHashes) == 0 && len(rawNodesOnPath) == 0) {
					panic(fmt.Sprintf("GetStorageLogged(addr=%v, key=%v) for a new key gave data", *addr, *key))
				}
				//s.keysSeen[keykey] = nil
				keys[keykey] = nil
				log.Info("Keykey", "k", keykey)
				// what is the current value
				v := obj.GetState(*key)
				rawNode := valueToLeaf(v)
				//s.nodesForKey[v] = rawNode
				keyNodes[v] = rawNode
			}
			if logEntry.newvalue.Cmp(testVal) == 0 {
				_, ok := s.keysInTrie[keykey]
				if ok {
					delete(s.keysInTrie, keykey)
				}
			}	
		default:
		}
	}
	// no we've stored all the path hashes and the raw nodes for each key that is gotten
	// now we log all of this information
	// sanity checking: assert that all the raw nodes correspond to hashes in the other set
	inAccounts := 0
	notInAccounts := 0
	//for _, hashes := range s.accountsSeen {
	for _, hashes := range accounts {
		for _, hn := range hashes {
			//_, ok := s.nodesForAccount[hn]
			_, ok := accountNodes[hn]
			if ok {
				inAccounts++
			} else {
				notInAccounts++
			}
		}
	}
	log.Info("Sanity checks.", "inAccounts", inAccounts, "notInAccounts", notInAccounts)
	// we shouldn't cache these since they will apply to the next transaction as well
	// instead, we should mark when one transaction ends and another begins (but this is just the same as 
	
	// Q: do we have any conflicting keys between the two maps that aren't empty hashes?
	// A: no we don't so we can combine the two tries
	//for hn, _ := range s.nodesForAccount {
	for hn, _ := range accountNodes {
		//_, exists := s.nodesForKey[hn]
		_, exists := keyNodes[hn]
		if exists {
			log.Error("Same hash in account and state trie.", "k", hn)
			panic("Same hash")
		}
	}

	//for hn, _ := range s.nodesForKey {
	for hn, _ := range keyNodes {
		//_, exists := s.nodesForAccount[hn]
		_, exists := accountNodes[hn]
		if exists {
			log.Error("Same hash in account and state trie.", "k", hn)
			panic("Same hash")
		}
	}

	//log.Info("Hashes for account", "l", len(s.nodesForAccount))
	//log.Info("Hashes for key", "l", len(s.nodesForKey))
	//log.Info("Num accounts", "l", len(s.accountsSeen))
	//log.Info("Num keys", "l", len(s.keysSeen))
	//log.Info("Total accounts in trie", "n", totalAccountsInTrie)
	//log.Info("Total keys in tries", "n", totalKeysInTrie)
	log.Info("Hashes for account", "l", len(accountNodes))
	log.Info("Hashes for key", "l", len(keyNodes))
	log.Info("Num accounts", "l", len(accounts))
	log.Info("Num keys", "l", len(keys))
	log.Info("Total accounts in trie", "n", len(s.accountsInTrie))
	log.Info("Total keys in tries", "n", len(s.keysInTrie))

	// create a trie from this data
	rootHash, rootRaw := s.trie.RootBytes()
	if rootRaw != nil {
		rn, err := trie.PublicDecodeNode(nil, rootRaw)
		if err != nil {
			log.Error("Couldn't decode root from raw.", "hash", rootHash, "raw", rootRaw)
			panic("Failed to decode root")
		}
		// merge the hashes 
		testMap := make(map[common.Hash][]byte)
		//for hn, raw := range s.nodesForAccount {
		for hn, raw := range accountNodes {
			testMap[hn] = raw
		}
		//for hn, raw := range s.nodesForKey {
		for hn, raw := range keyNodes {
			testMap[hn] = raw
		}
		count := trie.TrieFromNodeCount(rn, testMap)
		log.Info("Crated hashes", "len", count)
	}
	return accounts, accountNodes, keys, keyNodes
}

func valueToLeaf(value common.Hash) []byte {
	trimmed := common.TrimLeftZeroes(value[:])
	return trimmed
}

func stateObjectToBytes(obj *stateObject) []byte {
	data, err := rlp.EncodeToBytes(&(obj.data))
	if err != nil {
		log.Error("Erroneous state object", "data", obj.data)
		panic(fmt.Sprintf("Failed to encode accound for %v, %v", obj.address, err))
	}
	return data
}
	

func isArbosAddress(addr common.Address) bool {
	isRandomAddress := addr.Cmp(common.HexToAddress("0xa4B00000000000000000000000000000000000F6")) == 0
	isRandomAddress2 := addr.Cmp(common.HexToAddress("0x11B57FE348584f042E436c6Bf7c3c3deF171de49")) == 0
	isEmptyAddress := addr.Cmp(common.HexToAddress("0x0000000000000000000000000000000000000000")) == 0
	isDevAddress := addr.Cmp(common.HexToAddress("0x3f1Eae7D46d88F08fc2F8ed27FCb2AB183EB2d0E")) == 0
	isStateAddress := (addr.Cmp(types.ArbosStateAddress) == 0)
	isOsAddress := (addr.Cmp(types.ArbosAddress) == 0)
	isSysAddress := (addr.Cmp(types.ArbSysAddress) == 0)
	isInfoAddress := (addr.Cmp(types.ArbInfoAddress) == 0)

	isTableAddress := (addr.Cmp(types.ArbAddressTableAddress) == 0)           
	isBLSAddress := (addr.Cmp(types.ArbBLSAddress) == 0)           
	isFTableAddress := (addr.Cmp(types.ArbFunctionTableAddress) == 0)        
	isTestAddress := (addr.Cmp(types.ArbosTestAddress) == 0)          
	isGasInfoAddress := (addr.Cmp(types.ArbGasInfoAddress) == 0)       
	isOwnerPublicAddress := (addr.Cmp(types.ArbOwnerPublicAddress) == 0)   
	isAggregatorAddress := (addr.Cmp(types.ArbAggregatorAddress) == 0)    
	isRetryableAddress := (addr.Cmp(types.ArbRetryableTxAddress) == 0)     
	isStatAddress := (addr.Cmp(types.ArbStatisticsAddress) == 0)          
	isOwnerAddress := (addr.Cmp(types.ArbOwnerAddress) == 0)         
	isWasmAddress := (addr.Cmp(types.ArbWasmAddress) == 0)          
	isCacheAddress := (addr.Cmp(types.ArbWasmCacheAddress) == 0)         
	isInterfaceAddress := (addr.Cmp(types.NodeInterfaceAddress) == 0)     
	isDebugAddress := (addr.Cmp(types.ArbDebugAddress) == 0)         
	isInterfaceDebugAddress := (addr.Cmp(types.NodeInterfaceDebugAddress) == 0)


	if (isStateAddress || isOsAddress || isSysAddress || isInfoAddress ||
		isTableAddress || isBLSAddress || isFTableAddress || isTestAddress || 
		isGasInfoAddress || isOwnerPublicAddress || isAggregatorAddress || 
		isRetryableAddress || isStatAddress || isStateAddress || isOwnerAddress || 
		isWasmAddress || isCacheAddress || isInterfaceAddress || isDebugAddress || 
		isInterfaceDebugAddress || isRandomAddress || isDevAddress || isEmptyAddress ||
		isRandomAddress2) {
		return true
	} else {
		return false
	}
}

// without any mutations caused in the current execution.
func (s *StateDB) logGetState(addr common.Address, key common.Hash, value common.Hash, node []byte, pathsTaken []common.Hash) {
	s.opsCalled = append(s.opsCalled, OP{op: OpGetState, addr: addr, key: key, value: value, node: node})
	s.pathsTaken = append(s.pathsTaken, pathsTaken)
	s.totalOps = s.totalOps + 1
}

func (s *StateDB) logGetStorage(addr common.Address, key common.Hash, value common.Hash, node []byte, pathsTaken []common.Hash) {
	s.opsCalled = append(s.opsCalled, OP{op: OpGetStorage, addr: addr, key: key, value: value, node: node})
	s.pathsTaken = append(s.pathsTaken, pathsTaken)
	s.totalOps = s.totalOps + 1
}
	
func (s *StateDB) logGetStorageMiss(addr common.Address, key common.Hash, value common.Hash, node []byte, pathsTaken []common.Hash) {
	s.opsCalled = append(s.opsCalled, OP{op: OpGetStorageMiss, addr: addr, key: key, value: value, node: node})
	s.pathsTaken = append(s.pathsTaken, pathsTaken)
	s.totalOps = s.totalOps + 1
}


func (s *StateDB) logSetCode(addr common.Address, codeHash []byte) {
	s.opsCalled = append(s.opsCalled, OP{op: OpSetCode, addr: addr, key: emptyHash, value: emptyHash, node: codeHash})
	s.pathsTaken = append(s.pathsTaken, []common.Hash{})
	s.totalOps = s.totalOps + 1
}

func (s *StateDB) logSetStateCreate(addr common.Address, key common.Hash, value common.Hash, node []byte, pathsTaken []common.Hash) {
	s.opsCalled = append(s.opsCalled, OP{op: OpSetStateCreate, addr: addr, key: key, value: value, node: node})
	s.pathsTaken = append(s.pathsTaken, pathsTaken)
	s.totalOps = s.totalOps + 1
}

func (s *StateDB) logSetState(addr common.Address, key common.Hash, value common.Hash, node []byte, pathsTaken []common.Hash) {
	s.opsCalled = append(s.opsCalled, OP{op: OpSetStateCreate, addr: addr, key: key, value: value, node: node})
	s.pathsTaken = append(s.pathsTaken, pathsTaken)
	s.totalOps = s.totalOps + 1
}


//func (s *StateDB) getStateObject2(addr common.Address) *stateObject {
//	// Prefer live objects if any is available
//	if obj := s.stateObjects[addr]; obj != nil {
//		//log.Info("Live stateobject", "addr", addr)
//		s.journal.append(getStateObjectEntry{account: &addr})
//		return obj
//	}
//	// Short circuit if the account is already destructed in this block.
//	if _, ok := s.stateObjectsDestruct[addr]; ok {
//		// let it return here because a destruted object is always known and instantly checked
//		// eventually the advice or whatever can inform that something is destroyed, and we don't
//		// want to cache anything explored here
//		s.journal.append(getStateObjectEntry{account: &addr})
//		return nil
//	}
//	// If no live objects are available, attempt to use snapshots
//	var data *types.StateAccount
//	if s.snap != nil {
//		//log.Info("Searching in snapshot", "addr", addr)
//		start := time.Now()
//		acc, err := s.snap.Account(crypto.HashData(s.hasher, addr.Bytes()))
//		s.SnapshotAccountReads += time.Since(start)
//
//		if err == nil {
//			if acc == nil {
//				return nil
//			}
//			data = &types.StateAccount{
//				Nonce:    acc.Nonce,
//				Balance:  acc.Balance,
//				CodeHash: acc.CodeHash,
//				Root:     common.BytesToHash(acc.Root),
//			}
//			if len(data.CodeHash) == 0 {
//				data.CodeHash = types.EmptyCodeHash.Bytes()
//			}
//			if data.Root == (common.Hash{}) {
//				data.Root = types.EmptyRootHash
//			}
//		}
//	}
//	// If snapshot unavailable or reading from it failed, load from the database
//	if data == nil {
//		//log.Info("Not in snapshot", "addr", addr)
//		start := time.Now()
//		var err error
//		data, err = s.trie.GetAccount(addr)
//		s.AccountReads += time.Since(start)
//
//		if err != nil {
//			s.setError(fmt.Errorf("getDeleteStateObject (%x) error: %w", addr.Bytes(), err))
//			return nil
//		}
//		if data == nil {
//			//log.Info("data == nil")
//			return nil
//		}
//	}
//	// Insert into the live set
//	//log.Info("logging and creating a new object from data", "addr", addr)
//	//log.Info("appending to journal")
//	s.journal.append(getStateObjectEntry{account: &addr})
//	//log.Info("done appending")
//	obj := newObject(s, addr, data)
//	s.setStateObject(obj)
//	return obj
//}



/// Journal stuff

type generic struct {
	Type string `json:"type"`
	Data json.RawMessage `json:"data"`
}

var createObjectChangeS string = "createObjectChange"
var createZombieChangeS string = "createZombieChange"
var createContractChangeS string = "createContractChange"
var selfDestructChangeS string = "selfDestructChange"
var balanceChangeS string = "balanceChange"
var nonceChangeS string = "nonceChange"
var storageChangeS string = "storageChange"
var codeChangeS string = "codeChange"
var refundChangeS string = "refundChange"
var addLogChangeS string = "addLogChange"
//var addPreimageChangeS string = "addPreimageChange"
var touchChangeS string = "touchChange"
var accessListAddAccountChangeS string = "accessListAddAccountChange"
var accessListAddSlotChangeS string = "accessListAddSlotChange"
var transientStorageChangeS string = "transientStorageChange"
var getStateObjectEntryS string = "getStateObjectEntry"
var getStorageEntryS string = "getStorageEntryS"
var wasmActivationS string = "wasmActivation"
var CacheWasmS string = "CacheWasm"
var EvictWasmS string = "EvictWasm"


func (l LogJournalEntry) MarshalJSON() ([]byte, error) {
	switch entry := (l.Entry).(type) {
	case createObjectChange:
		d, err := entry.MarshalJSON()
		if err == nil {
			return json.Marshal(&generic{
				Type: createObjectChangeS,
				Data: d,
			})
		} else {
			panic(err)
		}
	case createZombieChange:
		d, err := entry.MarshalJSON()
		if err == nil {
			return json.Marshal(&generic{
				Type: createZombieChangeS,
				Data: d,
			})
		} else {
			panic(err)
		}
	case createContractChange:
		d, err := entry.MarshalJSON()
		if err == nil {
			return json.Marshal(&generic{
				Type: createContractChangeS,
				Data: d,
			})
		} else {
			panic(err)
		}
		return entry.MarshalJSON()
	case selfDestructChange:
		d, err := entry.MarshalJSON()
		if err == nil {
			return json.Marshal(&generic{
				Type: selfDestructChangeS,
				Data: d,
			})
		} else {
			panic(err)
		}
		return entry.MarshalJSON()
	case balanceChange:
		d, err := entry.MarshalJSON()
		if err == nil {
			return json.Marshal(&generic{
				Type: balanceChangeS,
				Data: d,
			})
		} else {
			panic(err)
		}
		return entry.MarshalJSON()
	case nonceChange:
		d, err := entry.MarshalJSON()
		if err == nil {
			return json.Marshal(&generic{
				Type: nonceChangeS,
				Data: d,
			})
		} else {
			panic(err)
		}
		return entry.MarshalJSON()
	case storageChange:
		d, err := entry.MarshalJSON()
		if err == nil {
			return json.Marshal(&generic{
				Type: storageChangeS,
				Data: d,
			})
		} else {
			panic(err)
		}
		return entry.MarshalJSON()
	case codeChange:
		d, err := entry.MarshalJSON()
		if err == nil {
			return json.Marshal(&generic{
				Type: codeChangeS,
				Data: d,
			})
		} else {
			panic(err)
		}
		return entry.MarshalJSON()
	case refundChange:
		d, err := entry.MarshalJSON()
		if err == nil {
			return json.Marshal(&generic{
				Type: refundChangeS,
				Data: d,
			})
		} else {
			panic(err)
		}
		return entry.MarshalJSON()
	case addLogChange:
		d, err := entry.MarshalJSON()
		if err == nil {
			return json.Marshal(&generic{
				Type: addLogChangeS,
				Data: d,
			})
		} else {
			panic(err)
		}
		return entry.MarshalJSON()
	//case addPreimageChange:
	//	d, err := entry.MarshalJSON()
	//	if err == nil {
	//		return json.Marshal(&generic{
	//			Type: addPreimageChangeS,
	//			Data: d,
	//		})
	//	} else {
	//		panic(err)
	//	}
	//	return entry.MarshalJSON()
	case touchChange:
		d, err := entry.MarshalJSON()
		if err == nil {
			return json.Marshal(&generic{
				Type: touchChangeS,
				Data: d,
			})
		} else {
			panic(err)
		}
		return entry.MarshalJSON()
	case accessListAddAccountChange:
		d, err := entry.MarshalJSON()
		if err == nil {
			return json.Marshal(&generic{
				Type: accessListAddAccountChangeS,
				Data: d,
			})
		} else {
			panic(err)
		}
		return entry.MarshalJSON()
	case accessListAddSlotChange:
		d, err := entry.MarshalJSON()
		if err == nil {
			return json.Marshal(&generic{
				Type: accessListAddSlotChangeS,
				Data: d,
			})
		} else {
			panic(err)
		}
		return entry.MarshalJSON()
	case transientStorageChange:
		d, err := entry.MarshalJSON()
		if err == nil {
			return json.Marshal(&generic{
				Type: transientStorageChangeS,
				Data: d,
			})
		} else {
			panic(err)
		}
		return entry.MarshalJSON()
	case getStateObjectEntry:
		d, err := entry.MarshalJSON()
		if err == nil {
			return json.Marshal(&generic{
				Type: getStateObjectEntryS,
				Data: d,
			})
		} else {
			panic(err)
		}
		return entry.MarshalJSON()
	case getStorageEntry:
		d, err := entry.MarshalJSON()
		if err == nil {
			return json.Marshal(&generic{
				Type: getStorageEntryS,
				Data: d,
			})
		} else {
			panic(err)
		}
		return entry.MarshalJSON()
	case wasmActivation:
		d, err := entry.MarshalJSON()
		if err == nil {
			return json.Marshal(&generic{
				Type: wasmActivationS,
				Data: d,
			})
		} else {
			panic(err)
		}
		return entry.MarshalJSON()
	case CacheWasm:
		d, err := entry.MarshalJSON()
		if err == nil {
			return json.Marshal(&generic{
				Type: CacheWasmS,
				Data: d,
			})
		} else {
			panic(err)
		}
		return entry.MarshalJSON()
	case EvictWasm:
		d, err := entry.MarshalJSON()
		if err == nil {
			return json.Marshal(&generic{
				Type: EvictWasmS,
				Data: d,
			})
		} else {
			panic(err)
		}
		return entry.MarshalJSON()
	default:
		return nil, nil
	}
}

func (l *LogJournalEntry) UnmarshalJSON(b []byte) error {
	var out generic
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}

	//switch entry := (l.Entry).(type) {
	switch out.Type {
	case createObjectChangeS:
		var res createObjectChange
		if err := res.UnmarshalJSON(out.Data); err != nil {
			panic(err)
		}
		l.Entry = res	
	case createZombieChangeS:
		var res createZombieChange
		if err := res.UnmarshalJSON(out.Data); err != nil {
			panic(err)
		}
		l.Entry = res
	case createContractChangeS:
		var res createContractChange
		if err := res.UnmarshalJSON(out.Data); err != nil {
			panic(err)
		}
		l.Entry = res
	case selfDestructChangeS:
		var res selfDestructChange
		if err := res.UnmarshalJSON(out.Data); err != nil {
			panic(err)
		}
		l.Entry = res
	case balanceChangeS:
		var res balanceChange
		if err := res.UnmarshalJSON(out.Data); err != nil {
			panic(err)
		}
		l.Entry = res
	case nonceChangeS:
		var res nonceChange
		if err := res.UnmarshalJSON(out.Data); err != nil {
			panic(err)
		}
		l.Entry = res
	case storageChangeS:
		var res storageChange
		if err := res.UnmarshalJSON(out.Data); err != nil {
			panic(err)
		}
		l.Entry = res
	case codeChangeS:
		var res codeChange
		if err := res.UnmarshalJSON(out.Data); err != nil {
			panic(err)
		}
		l.Entry = res
	case refundChangeS:
		var res refundChange
		if err := res.UnmarshalJSON(out.Data); err != nil {
			panic(err)
		}
		l.Entry = res
	case addLogChangeS:
		var res addLogChange
		if err := res.UnmarshalJSON(out.Data); err != nil {
			panic(err)
		}
		l.Entry = res
	//case addPreimageChangeS:
	//	var res addPreimageChange
	//	if err := res.UnmarshalJSON(out.Data); err != nil {
	//		panic(err)
	//	}
	//	l.Entry = res
	case touchChangeS:
		var res touchChange
		if err := res.UnmarshalJSON(out.Data); err != nil {
			panic(err)
		}
		l.Entry = res
	case accessListAddAccountChangeS:
		var res accessListAddAccountChange
		if err := res.UnmarshalJSON(out.Data); err != nil {
			panic(err)
		}
		l.Entry = res
	case accessListAddSlotChangeS:
		var res accessListAddSlotChange
		if err := res.UnmarshalJSON(out.Data); err != nil {
			panic(err)
		}
		l.Entry = res
	case transientStorageChangeS:
		var res transientStorageChange
		if err := res.UnmarshalJSON(out.Data); err != nil {
			panic(err)
		}
		l.Entry = res
	case getStateObjectEntryS:
		var res getStateObjectEntry
		if err := res.UnmarshalJSON(out.Data); err != nil {
			panic(err)
		}
		l.Entry = res
	case getStorageEntryS:
		var res getStorageEntry
		if err := res.UnmarshalJSON(out.Data); err != nil {
			panic(err)
		}
		l.Entry = res
	case wasmActivationS:
		var res wasmActivation
		if err := res.UnmarshalJSON(out.Data); err != nil {
			panic(err)
		}
		l.Entry = res
	case CacheWasmS:
		var res CacheWasm
		if err := res.UnmarshalJSON(out.Data); err != nil {
			panic(err)
		}
		l.Entry = res
	case EvictWasmS:
		var res EvictWasm
		if err := res.UnmarshalJSON(out.Data); err != nil {
			panic(err)
		}
		l.Entry = res
	default:
		return nil
	}
	return nil
}

