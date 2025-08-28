package state

import (
	"bytes"
	"fmt"
	"slices"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/rlp"
)

func (s *StateDB) accountToBytes(addr common.Address) (bool, []byte) {
	obj, exist := s.stateObjects[addr]
	if !exist {
		s.findGetCreates(addr)
		//panic(fmt.Sprintf("Called accountToEncodeNode with address not in stateObjects: %v", addr))
		log.Error(fmt.Sprintf("Called accountToEncodeNode with address not in stateObjects: %v", addr))
		return false, nil
	}
	return true, stateObjectToBytes(obj)
}

// getStateObject retrieves a state object given by the address, returning nil if
// the object is not found or was deleted in this execution context.
// this function is called from the different revert functions in journal
// because we don't want a revert operation to add things to the journal in
// the middle because it messes up the accounting, the access is always logged
// previously by operation that is being reverted.
func (s *StateDB) getStateObjectNoLog(addr common.Address) *stateObject {
	// Prefer live objects if any is available
	//log.Info("getStateObject", "addr", addr)
	if obj := s.stateObjects[addr]; obj != nil {
		//log.Info("In stateObjects")
		//s.journal.getState(addr)
		return obj
	}
	// Short circuit if the account is already destructed in this block.
	if _, ok := s.stateObjectsDestruct[addr]; ok {
		log.Debug("destructed")
		// let it return here because a destruted object is always known and instantly checked
		// eventually the advice or whatever can inform that something is destroyed, and we don't
		// want to cache anything explored here
		return nil
	}
	s.AccountLoaded++

	start := time.Now()
	//log.Info("Get reader")
	acct, err := s.reader.Account(addr)

	//s.journal.getState(addr)

	if err != nil {
		s.setError(fmt.Errorf("getStateObject (%x) error: %w", addr.Bytes(), err))
		return nil
	}
	s.AccountReads += time.Since(start)

	// Short circuit if the account is not found
	if acct == nil {
		return nil
	}
	// Schedule the resolved account for prefetching if it's enabled.
	if s.prefetcher != nil {
		if err = s.prefetcher.prefetch(common.Hash{}, s.originalRoot, common.Address{}, []common.Address{addr}, nil, true); err != nil {
			log.Error("Failed to prefetch account", "addr", addr, "err", err)
		}
	}
	// Insert into the live set
	obj := newObject(s, addr, acct)
	s.setStateObject(obj)
	return obj
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
				log.Debug("Target entry", "addr", addr, "key", key, "prevvalue", logEntry.prevvalue, "new", newval)
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
				log.Debug("Get target.", "idx", idx, "addr", a, "key", k, "value", logEntry.value)
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
				log.Debug("Target entry", "idx", idx, "addr", addr, "key", key, "prevvalue", logEntry.prevvalue, "new", newval)
			}
		}
	}
}

func PublicFindGetSets(addr common.Address, key common.Hash, j [][]LogJournalEntry) {
	for _, jn := range j {
	//for idx, lentry := range s.journal.logEntries {
		for idx, e := range jn {
			//switch logEntry := (lentry.Entry).(type) {
			switch logEntry := (e.Entry).(type) {
			case getStorageEntry:
				a := logEntry.account
				k := logEntry.key
				//if (addr.Cmp(a) == 0 && key.Cmp(k) == 0) {
				if (addr.Cmp(a) == 0) {
					log.Debug("Get target.", "idx", idx, "addr", a, "key", k, "value", logEntry.value)
				}
			case storageChange:
				a := logEntry.account
				//k := logEntry.key
				//if (addr.Cmp(a) == 0 && key.Cmp(k) == 0) {
				if (addr.Cmp(a) == 0) {
					//obj, exists := s.stateObjects[a]
					//if !exists {
					//	panic("doesn't exist")
					//}
					//newval := obj.GetState(k)
					log.Debug("Target entry", "idx", idx, "addr", addr, "key", key, "prevvalue", logEntry.prevvalue, "new", logEntry.newvalue)
				}
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
				log.Debug("Get obj target", "idx", idx, "addr", a, "revert", lentry.Reverted)
			}
		case createObjectChange:
			a := logEntry.account
			if addr.Cmp(a) == 0 {
				_, exists := s.stateObjects[a]
				if !exists {
					log.Error("obj doesn't exist")
				}
				log.Debug("create obj target", "idx", idx, "addr", a, "revert", lentry.Reverted)
			}
		case selfDestructChange:
			a := logEntry.account
			if addr.Cmp(a) == 0 {
				log.Debug("Self destruct target", "idx", idx, "addr", a, "revert", lentry.Reverted)
				_, ok := s.stateObjects[a]
				if ok {
					log.Debug("is in state objects")
				} else {
					log.Debug("not in stateObjects")
				}
			}
		case createContractChange:
			a := logEntry.account
			if addr.Cmp(a) == 0 {
				log.Debug("create contract change", "idx", idx, "addr", a, "revert", lentry.Reverted)
				_, ok := s.stateObjects[a]
				if ok {
					log.Debug("is in state objects")
				} else {
					log.Debug("is NOT in stateObjects")
				}
			}
        case getStorageEntry:
            a := logEntry.account
            key := logEntry.key
            value := logEntry.value
            if addr.Cmp(a) == 0 {
                log.Debug("get storage entry", "idx", idx, "addr", a, "key", key, "val", value, "revert", lentry.Reverted)
            }
		}
	}
}

func PublicFindAll(addr common.Address, j [][]LogJournalEntry) {
	seenKeys := make(map[KeyKey]bool)
	for jidx, journ := range j {
		for idx, lentry := range journ {
			switch logEntry := (lentry.Entry).(type) {
			case getStorageEntry:
				a := logEntry.account
				k := logEntry.key
				_, seen := seenKeys[KeyKey{a, k}]
				if addr.Cmp(a) == 0 {
					//log.Debug("Found a match")
					if !seen {
						log.Debug("Get storage target", "journal", jidx, "idx", idx, "addr", a, "key", k, "revert", lentry.Reverted)
						seenKeys[KeyKey{a, k}] = true
					}
				}
			case getStateObjectEntry:
				a := logEntry.account
				if addr.Cmp(a) == 0 {
					log.Debug("Get obj target", "journal", jidx, "idx", idx, "addr", a, "revert", lentry.Reverted)
				}
			case createObjectChange:
				a := logEntry.account
				if addr.Cmp(a) == 0 {
					log.Debug("create obj target", "journal", jidx, "idx", idx, "addr", a, "revert", lentry.Reverted)
				}
			case selfDestructChange:
				a := logEntry.account
				if addr.Cmp(a) == 0 {
					log.Debug("Self destruct target", "journal", jidx, "idx", idx, "addr", a, "revert", lentry.Reverted)
				}
			case createContractChange:
				a := logEntry.account
				if addr.Cmp(a) == 0 {
					log.Debug("create contract change", "journal", jidx, "idx", idx, "addr", a, "revert", lentry.Reverted)
				}
			default:
			}
		}
	}
}

func PublicFindAllHashKeyKey(hkk HashedKeyKey, j [][]LogJournalEntry) {
    log.Debug(fmt.Sprintf("PublicFIndAllHashKeyKey(%v)", hkk))
	for jidx, journ := range j {
		for idx, lentry := range journ {
			switch logEntry := (lentry.Entry).(type) {
			case getStorageEntry:
				a := logEntry.account
                ha := common.BytesToHash(trie.PublicHashKey(a.Bytes()))
				k := logEntry.key
                hk := common.BytesToHash(trie.PublicHashKey(k.Bytes()))
				//if addr.Cmp(a) == 0 {
                if ha.Cmp(hkk.HashAddr()) == 0 && hk.Cmp(hkk.Key()) == 0 {
					//log.Debug("Found a match")
					log.Debug("Get storage target", "journal", jidx, "idx", idx, "addr", a, "key", k, "val", logEntry.value, "revert", lentry.Reverted)
				}
            case storageChange:
                a := logEntry.account
                k := logEntry.key
                ha := common.BytesToHash(trie.PublicHashKey(a.Bytes()))
                hk := common.BytesToHash(trie.PublicHashKey(k.Bytes()))
                if ha.Cmp(hkk.HashAddr()) == 0 && hk.Cmp(hkk.Key()) == 0 {
                    log.Debug("Storage change target", "journal", jidx, "idx", idx, "addr", a, "key", k, "prevvalue", logEntry.prevvalue, "originvalue", logEntry.origvalue, "newvalue", logEntry.newvalue)
                }
			default:
			}
		}
	}
}


func PublicFindAllHashKeyStorage(addr common.Hash, j [][]LogJournalEntry) {
	seenKeys := make(map[KeyKey]bool)
	for jidx, journ := range j {
		for idx, lentry := range journ {
			switch logEntry := (lentry.Entry).(type) {
			case getStorageEntry:
				a := logEntry.account
                ha := common.BytesToHash(trie.PublicHashKey(a.Bytes()))
				k := logEntry.key
				_, seen := seenKeys[KeyKey{a, k}]
				//if addr.Cmp(a) == 0 {
                if ha.Cmp(addr) == 0 {
					//log.Debug("Found a match")
					if !seen {
						log.Debug("Get storage target", "journal", jidx, "idx", idx, "addr", a, "key", k, "revert", lentry.Reverted)
						seenKeys[KeyKey{a, k}] = true
					}
				}
            case storageChange:
                a := logEntry.account
                ha := common.BytesToHash(trie.PublicHashKey(a.Bytes()))
                if ha.Cmp(addr) == 0 {
                    log.Debug("storage Change", "journal", jidx, "idx", idx, "addr", a, "revert", lentry.Reverted, "origvalue", logEntry.origvalue, "newvalue", logEntry.newvalue)
                }
			default:
			}
		}
	}
}



func PublicFindAllHashKey(addr common.Hash, j [][]LogJournalEntry) {
	seenKeys := make(map[KeyKey]bool)
	for jidx, journ := range j {
		for idx, lentry := range journ {
			switch logEntry := (lentry.Entry).(type) {
			case getStorageEntry:
				a := logEntry.account
                ha := common.BytesToHash(trie.PublicHashKey(a.Bytes()))
				k := logEntry.key
				_, seen := seenKeys[KeyKey{a, k}]
				//if addr.Cmp(a) == 0 {
                if ha.Cmp(addr) == 0 {
					//log.Debug("Found a match")
					if !seen {
						log.Debug("Get storage target", "journal", jidx, "idx", idx, "addr", a, "key", k, "revert", lentry.Reverted)
						seenKeys[KeyKey{a, k}] = true
					}
				}
			case getStateObjectEntry:
				a := logEntry.account
                ha := common.BytesToHash(trie.PublicHashKey(a.Bytes()))
				//if addr.Cmp(a) == 0 {
                if ha.Cmp(addr) == 0 {
					log.Debug("Get obj target", "journal", jidx, "idx", idx, "addr", a, "revert", lentry.Reverted)
				}
			case createObjectChange:
				a := logEntry.account
                ha := common.BytesToHash(trie.PublicHashKey(a.Bytes()))
				//if addr.Cmp(a) == 0 {
                if ha.Cmp(addr) == 0 {
					log.Debug("create obj target", "journal", jidx, "idx", idx, "addr", a, "revert", lentry.Reverted)
				}
			case selfDestructChange:
				a := logEntry.account
                ha := common.BytesToHash(trie.PublicHashKey(a.Bytes()))
				//if addr.Cmp(a) == 0 {
                if ha.Cmp(addr) == 0 {
					log.Debug("Self destruct target", "journal", jidx, "idx", idx, "addr", a, "revert", lentry.Reverted)
				}
			case createContractChange:
				a := logEntry.account
                ha := common.BytesToHash(trie.PublicHashKey(a.Bytes()))
				//if addr.Cmp(a) == 0 {
                if ha.Cmp(addr) == 0 {
					log.Debug("create contract change", "journal", jidx, "idx", idx, "addr", a, "revert", lentry.Reverted)
				}
			default:
			}
		}
	}
}


func PublicFindAllHashKeyCount(addr common.Hash, j [][]LogJournalEntry) int {
	seenKeys := make(map[KeyKey]bool)
    //outStr := []string{}
    out := 0
	for _, journ := range j {
		for _, lentry := range journ {
			switch logEntry := (lentry.Entry).(type) {
			case getStorageEntry:
				a := logEntry.account
                ha := common.BytesToHash(trie.PublicHashKey(a.Bytes()))
				k := logEntry.key
				_, seen := seenKeys[KeyKey{a, k}]
				//if addr.Cmp(a) == 0 {
                if ha.Cmp(addr) == 0 {
					//log.Debug("Found a match")
					if !seen {
						//log.Debug("Get storage target", "journal", jidx, "idx", idx, "addr", a, "key", k, "revert", lentry.Reverted)
                        out++
						seenKeys[KeyKey{a, k}] = true
					}
				}
			case getStateObjectEntry:
				a := logEntry.account
                ha := common.BytesToHash(trie.PublicHashKey(a.Bytes()))
				//if addr.Cmp(a) == 0 {
                if ha.Cmp(addr) == 0 {
					//log.Debug("Get obj target", "journal", jidx, "idx", idx, "addr", a, "revert", lentry.Reverted)
				}
			case createObjectChange:
				a := logEntry.account
                ha := common.BytesToHash(trie.PublicHashKey(a.Bytes()))
				//if addr.Cmp(a) == 0 {
                if ha.Cmp(addr) == 0 {
					//log.Debug("create obj target", "journal", jidx, "idx", idx, "addr", a, "revert", lentry.Reverted)
                    out++
				}
			case selfDestructChange:
				a := logEntry.account
                ha := common.BytesToHash(trie.PublicHashKey(a.Bytes()))
				//if addr.Cmp(a) == 0 {
                if ha.Cmp(addr) == 0 {
					//log.Debug("Self destruct target", "journal", jidx, "idx", idx, "addr", a, "revert", lentry.Reverted)
                    out++
				}
			case createContractChange:
				a := logEntry.account
                ha := common.BytesToHash(trie.PublicHashKey(a.Bytes()))
				//if addr.Cmp(a) == 0 {
                if ha.Cmp(addr) == 0 {
					//log.Debug("create contract change", "journal", jidx, "idx", idx, "addr", a, "revert", lentry.Reverted)
                    out++
				}
			default:
			}
		}
	}
    return out
}

func (s *StateDB) findAll(addr common.Address) {
	seenKeys := make(map[KeyKey]bool)
	for idx, lentry := range s.journal.logEntries {
		switch logEntry := (lentry.Entry).(type) {
		case getStorageEntry:
			a := logEntry.account
			k := logEntry.key
			_, seen := seenKeys[KeyKey{a, k}]
			if !seen && addr.Cmp(a) == 0 {
				log.Debug("Get storage target", "idx", idx, "addr", a, "key", k, "revert", lentry.Reverted)
				seenKeys[KeyKey{a, k}] = true
			}
		case getStateObjectEntry:
			a := logEntry.account
			if addr.Cmp(a) == 0 {
				log.Debug("Get obj target", "idx", idx, "addr", a, "revert", lentry.Reverted)
			}
		case createObjectChange:
			a := logEntry.account
			if addr.Cmp(a) == 0 {
				_, exists := s.stateObjects[a]
				if !exists {
					log.Error("obj doesn't exist")
				}
				log.Debug("create obj target", "idx", idx, "addr", a, "revert", lentry.Reverted)
			}
		case selfDestructChange:
			a := logEntry.account
			if addr.Cmp(a) == 0 {
				log.Debug("Self destruct target", "idx", idx, "addr", a, "revert", lentry.Reverted)
				_, ok := s.stateObjects[a]
				if ok {
					log.Debug("is in state objects")
				} else {
					log.Debug("not in stateObjects")
				}
			}
		case createContractChange:
			a := logEntry.account
			if addr.Cmp(a) == 0 {
				log.Debug("create contract change", "idx", idx, "addr", a, "revert", lentry.Reverted)
				_, ok := s.stateObjects[a]
				if ok {
					log.Debug("is in state objects")
				} else {
					log.Debug("is NOT in stateObjects")
				}
			}
		}
	}
}

func (s *StateDB) getAccountLogs(deletedAddrs []common.Address) (bool, map[common.Address][]common.Hash, map[common.Hash][]byte) {
	nilAccounts := []common.Address{}
	accounts := make(map[common.Address][]common.Hash)
	accountNodes := make(map[common.Hash][]byte)
	for addr := range s.accountsSeen {
		// get the path for this account
		//log.Info("getaccountlogs GetAccount Log call", "addr", addr)
		res, _, pathHashes, rawNodesOnPath, err := s.trie.GetAccountLogged(addr)
		//log.Info("getaccountlogs GetAccount Log return", "addr", addr)
		if err != nil {
			log.Error("getAccountLogs [243] Address get account threw error", "addr", addr, "err", err)
			return false, nil, nil
			//panic(err)
		}
		if len(pathHashes) == 0 || len(rawNodesOnPath) == 0 {
			log.Error("getAccountLogs [248] Address get gave no paths", "addr", addr, "err", err)
			return false, nil, nil
			//panic("No Paths")
		}

		if res == nil {
			// this is an account that was deleted or created and destroyed in the same block
			nilAccounts = append(nilAccounts, addr)
			_, ok := s.stateObjectsDestruct[addr]
			if !ok {
				log.Error("Addr not in stateObjectsDestruct", "addr", addr)
				log.Error("getAccountLogs [259] Is it in deleted addrs?", "exists", slices.Contains(deletedAddrs, addr), "err", err)
				return false, nil, nil
				//panic("Acount returned nil but isn't self destructed")
			}
		}

		// nothing to save here but create a new accounts dict
		accounts[addr] = pathHashes
		for _, rn := range rawNodesOnPath {
			//log.Info("Addr raw nodes", "addr", addr, "rn", rn)
			var hn common.Hash
			n, err := trie.PublicDecodeNode(nil, rn)
			if err != nil {
				//log.Info("Decode err not nil", "err", err)
				// if this is an error, then we assume that this is the raw account and it can't be decoded
				// therefore we should save the raw node make sure that we can decode this to a state object
				ret := new(types.StateAccount)
				err = rlp.DecodeBytes(rn, ret)
				if err != nil {
					log.Debug("couldn't decode account", "addr", addr)
					log.Error("getAccountLogs", "err", err)
					return false, nil, nil
					//panic(err)
				}
				hn = trie.HashData(rn)
			} else {
				hn = trie.HashNode(n)
			}
				
			oldrn, ok := accountNodes[hn]
			if ok {
				// then the raw nodes should be the same
				if bytes.Compare(rn, oldrn) != 0 {
					//panic(fmt.Sprintf("Same hash %v has two different raw nodes.", hn))
					log.Error(fmt.Sprintf("getAccountLogs [293] Same hash %v has two different raw nodes.", hn))
					return false, nil, nil
				}
			} else {
				accountNodes[hn] = rn
			}
		}
	}
	return true, accounts, accountNodes
}

func (s *StateDB) getKeyLogs() (bool, map[KeyKey][]common.Hash, map[common.Hash][]byte) {
	keys := make(map[KeyKey][]common.Hash)
	keyNodes := make(map[common.Hash][]byte)
	for keykey := range s.keysSeen {
		addr := keykey.addr
		key := keykey.key

		obj, exist := s.stateObjects[addr]
		if !exist {
			log.Debug("Getting the key of account that doesn't exist", "addr", addr)
			// TODO: should we still get these nodes?
			// keys that aren't in the maps anymore means they are of a deleted node
			// add them as nil
			keys[keykey] = nil
			continue
		}

		success, _, pathHashes, rawNodesOnPath := obj.GetTrieStateLoggedPostUpdate(key)
		if !success {
			log.Error("getKeyLogs: GetTrieStateLoggedPostUpdate PANIC")
			return false, nil, nil
		}

		if len(pathHashes) == 0 || len(rawNodesOnPath) == 0 {
			// should never get no path unless the root of the account is now empty
			if obj.data.Root.Cmp(types.EmptyRootHash) == 0 {
				// it is correct to log nothing for this key get, maybe we just skip it altogether?
				//panic("This happened again?")
				log.Error("getKeyLogs [327] this happened again?")
				return false, nil, nil
				continue
			} else {
				//s.findGetSets(*addr, *key)
				//panic(fmt.Sprintf("GetStorageLogged(addr=%v, key=%v) gave no data", addr, key))
				log.Error(fmt.Sprintf("GetStorageLogged(addr=%v, key=%v) gave no data", addr, key))
				return false, nil, nil
			}
		}

		keys[keykey] = pathHashes
		for _, rn := range rawNodesOnPath {
			n, err := trie.PublicDecodeNode(nil, rn)
			var hn common.Hash
			if err != nil {
				// this is a valuenode we do the normal check that the hash is in there
				hn = trie.HashData(rn)
				// TODO: uncomment this and confirm
				//oldrn, ok := keyNodes[hn]
				//if ok {
				//	if bytes.Compare(rn, oldrn) != 0 {
				//		panic(fmt.Sprintf("Same hash %v hash two different valuenodes. rn=%v, oldrn=%v", hn, rn, oldrn))
				//	}
				//} else {
				//	keyNodes[hn] = rn
				//}
			} else {
				hn = trie.HashNode(n)
			}
			//hn := trie.HashNode(n)
			oldrn, ok := keyNodes[hn]
			if ok {
				if bytes.Compare(rn, oldrn) != 0 {
					log.Debug("conflict", "rn", rn, "oldrn", oldrn)
					//panic(fmt.Sprintf("Same hash %v has two different raw nodes.", hn))
					log.Error(fmt.Sprintf("Same hash %v has two different raw nodes.", hn))
					return false, nil, nil
				}
			} else {
				keyNodes[hn] = rn
			}
		}
		
	}
	return true, keys, keyNodes
}

// in the logged data, every trie path that doesn't end in a valueNode is considered a get request that failed
// because this means that the return value was nil
// when a new trie path is created we know which addrs exist now, we can save that

// Finalize logger
func (s *StateDB) LogFinalize() (bool, []common.Address, map[common.Address][]common.Hash, map[common.Hash][]byte, map[KeyKey][]common.Hash, map[common.Hash][]byte, map[common.Address]bool, map[common.Address]bool) {
	accounts := make(map[common.Address][]common.Hash)
	accountNodes := make(map[common.Hash][]byte)
	keys := make(map[KeyKey][]common.Hash)
	keyNodes := make(map[common.Hash][]byte)

	// NOTE: sanity check that that a specific root is accessible
	//targetHash := common.HexToHash("0x89082f5e6d4eddbd37e6ebdaf57ea3e05e151027dc189c132cea608b6c19d85e")
	//obj, exists := s.stateObjects[target]
	//if exists {
	//	if targetHash.Cmp(obj.Root()) == 0 {
	//		log.Info("Target has target root hash")
	//		// see if the trie exists
	//		obj.TryToGetTrie()
	//	}
	//	log.Info("[Check] got through no problem")
	//}


	emptys := []common.Address{}
	// check which accounts are now emptyy
	for addr, _ := range s.journal.dirties {
		obj, exist := s.stateObjects[addr]
		if !exist {
			continue 
		}
		if obj.empty() {
			emptys = append(emptys, addr)
		}
	}

    // This map tracks the accounts that are created but aren't in stateObjects
    // because they are deleted (i.e. the createObjectChange isn't reverted). When
    // the createObject is seen the accounts value in createdAndDeleted is true. 
    // When the corresponding delete is seen, its value is set to false.
	createdAndDeleted := make(map[common.Address]bool)
    revertedCreateObject := make(map[common.Address]bool)


    // This tracks the accounts that were created in this transactions and will exist
    // afterwards. Accounts that have a createObjectChange entry and are found in
    // stateObjects will be stored here and never removed. 
    created := make(map[common.Address]bool)

	for idx, lentry := range s.journal.logEntries {
		var addr *common.Address
		var key *common.Hash
		var keykey KeyKey
		switch logEntry := (lentry.Entry).(type) {
		case createObjectChange:
            // It doesn't matter if this address was seen in accounts (is OK) because 
            // any getStateObject request for this address returns nil and the search 
            // path down the trie. If this is the first time we're seeing this address
            // be created, we still need to log the new leaf that is created.
            //
            // The only check to make is that the object is in stateObjects. If it isn't
            // then this item is either deleted some time in the future by a selfDestruct
            // or the createObjectChange was reverted.
			addr = &(logEntry.account)
			log.Debug("coc: Is this marked as reverted??", "addr", *addr, "reverted", lentry.Reverted)
			exists, rawNode := s.accountToBytes(*addr)

            if !exists {
                // If the createObject wasn't reverted, then it must be deleted later
                // in the journal so let's log it and wait for it to be deleted.
                if !lentry.Reverted {
                    // deleted this from stateObjects
                    log.Debug("coc: Could be that the object gets deleted later", "addr", *addr) 
				    prev, ok := createdAndDeleted[*addr]
				    if ok {
				    	log.Error("coc: Account was already seen as created", "addr", *addr)
				    	if prev {
                            // If the value in the map is still true means we saw a createObjectChange
                            // and are seeing this one without a delete in between so something is amiss.
				    		log.Error("coc: this thing was prev created sna created again without a delete", "addr", *addr)
                            panic("")
                            continue
				    		//return false, nil, nil, nil, nil, nil
				    	} 
                        // if prev = false than this is another create that will eventually
				    }
                    // set the value in createdAndDeleted to true
				    createdAndDeleted[*addr] = true
                    log.Debug("coc: Object isn't in stateObjects and its createObjectChange wasn't reverted")
                    //panic("log finalize 488")
                } else {
                    // else if it is reverted, then we store it in this map instead and
                    // we don't care to log this since there is not trie traversal
                    revertedCreateObject[*addr] = true
                }
                // regardless of which case (1. or 2.) we should continue and not process this any further
                continue
            }
    
            // otherwise this object is here to stay so can remove it from these maps
            // it could be that this createObject will be deleted and another happens
            // before the end of the journal. It doesn't really matter beacuse
            // selfDesturct here is only used to manage createdAndDeleted
            _, wasCreated := createdAndDeleted[*addr]
            _, revertCreated := revertedCreateObject[*addr]
            _, willExist := created[*addr]
            if wasCreated {
                delete(createdAndDeleted, *addr)
            }
            if revertCreated {
                delete(revertedCreateObject, *addr)
            }

            if !willExist {
                created[*addr] = true
            }

			rawNodeHash := trie.HashValueNode(rawNode)

            // If there was a getStateObject before this create, then accounts
            // logs the path that was searched looking for this account. accountNodes
            // stores the hashes and raw bytes of each node on that path, but this never
            // includes the hash of this leaf. If this object is already in accounts, then
            // we don't update accounts because we preserve the trie search. In this case,
            // only store the hash and preimage of this account.
			_, ok := accounts[*addr]
			if ok {
                // created twice is OK
				log.Debug("LogFinalize: Created twice", "account", *addr)
			} else {
                // There wasn't a previous getStateObject for this address so we 
                // just store this the raw bytes of this leaf as the search path because
                // no future getStateObject will ever search the trie since it's created.
			    accounts[*addr] = []common.Hash{rawNodeHash}
            }
			accountNodes[rawNodeHash] = rawNode
		case createContractChange:
            // createContractChange only sets a flag in the object associated with this
            // account, and it's always preceded by a getStateObject entry. Therefore,
            // there's nothing to do here. The account is assumed to exist and previous
            // entries in the journal will log everything about it. Just do some sanity
            // checks for no reason lol.
			addr = &(logEntry.account)
			_, ok := accounts[*addr]
            _, maybeDeleted := createdAndDeleted[*addr]
            _, createReverted := revertedCreateObject[*addr]
			found, _ := s.accountToBytes(*addr)
			if !ok {
                // A reverted getstate doesn't matter. This should always already be in accounts
                // there is no reason to not be in account, we should panic here because a major
                // assumption of getStateObject before createContract is violated and it doesn't
                // mae sense.
                if found || createReverted {
                    // this should never happen: this means that we haven't seen this yet in the jornal
                    // but a createObjectEntry is always preceded by a getStateObject
                    log.Error("We havent seen address before, but it IS in stateObjects. This MUST hve been logged already", "addr", *addr)
                    panic("Log finalize, createContractChange found")
                }
                if !lentry.Reverted && !maybeDeleted {
                    if !createReverted {
                        log.Debug("createContractCHange was reverted, but not in createReverted")
                    }
                    // this is a reason to panic 
                    log.Error("Address fr createContractChange isn't in stateObjects and isn't reverted or createdAndDeleted", "addr", *addr)
                    panic("Log finalize createContractChange")
                }
                // otherwise one of those must be true and we're good we can just skip this
                // we don't even need to add to createdAndDelete because a previous entry definitely already did. Check that:
                //_, ok := createdAndDeleted[*addr]
                if !maybeDeleted { panic("err") }
				log.Debug("LogFinalize: contract crearte of existing obj", "addr", *addr)
                log.Info("Access", "addr", *addr)
                panic("create contract should always be in ok becuase getStateObject happens first")
                continue
			}
            // if it WAS found in means a previous access found it in stateObjects and it wasn't createdAndDeleted.
            // Check that no:
            if maybeDeleted {
                log.Error("It WAS in accounts[addr] but is also in createdAndDeleted, but if it was deleted it shouldn't be in here", "addr", *addr)
                panic("Log finalize createContractChange in accounts")
            }
		case getStateObjectEntry:
			addr = logEntry.Account()
            // if the account is in accounts that means it was already processed
            // and so must exist after this transaction is over otherwise we would've
            // put it into createdAndDeleted or Reverted. If this acount was deleted
            // it doesn't matter because selfDesturct always gets the object first
            // meaning that if it was in accounts we logged it regardless.

            // If the account is in createdAndDeleted or Reverted, this means
            // this account was created in this block and deleted. It is possible
            // that this is in either of these two maps, and still accessed (i.e.
            // in the map accounts. Since both of these correspond to a create event
            // we can ignore doing anything here. If the sequence was: perform a get
            // request and then create one if nothing exists, then that get request
            // will come first and we'll catch and log the trie search according to that.
            // Once the create operation is seen we don't do anything else. Other accounts
            // that are created (and persist) will be saved in accounts and we'll also
            // get their path in IntermediateRoot's logging.
            //_, candd := createdAndDeleted[*addr]
            //_, revd := revertedCreateObject[*addr]
            //_, createdForGood := created[*addr]
			_, ok := accounts[*addr]

            // if this was createdForGood we still want to log the search path down
            // the trie at least once. We're possible doing an extra search/check for this
            // account than we need to because create could come first and then every future
            // get will short circuit and skip the trie, but oh well we just want this data
			//if !ok && !candd && !revd {
            if !ok {
				// we haven't seen it so we store the nodes on the path
				res, _, pathHashes, rawNodesOnPath, err := s.trie.GetAccountLogged(*addr)
				log.Debug("LogFinalize: account access", "addr", *addr)
				if err != nil || len(pathHashes) == 0 || len(rawNodesOnPath) == 0 {
                    // trie get should never give nothing in return, it should always
                    // at least return the path down to where this account would have been 
                    // if it hasn't been committed to the trie yet
                    // get account info from the different databases
					_, ok := s.stateObjects[*addr]
					log.Debug("Addr in stateObjects?", "addr", *addr, "ok", ok)
					acct, err := s.reader.Account(*addr)
					log.Debug("Reader check", "acct", acct, "err", err)
					log.Error("LogFinalise [454]: FAILURE")
                    panic("")
					return false, nil, nil, nil, nil, nil, nil, nil
				}

                // if we got a leaf back then this account def existed before this tranasction
                // even before this block because it was commited into the trie
				if res != nil {
					s.accountsInTrie[*addr] = true
				}

                // save the pathHashes and do some sanity checks on what we got
				accounts[*addr] = pathHashes
				for _, rn := range rawNodesOnPath {
					n, err := trie.PublicDecodeNode(nil, rn)
					if err == nil {
                        // only add a hash -> rawNode to the map if it's one
                        // we haven't already seen
						hn := trie.HashNode(n)
						_, ok := accountNodes[hn]
						if !ok {
							accountNodes[hn] = rn
						}
					} else {
						// if this is an error, then we assume that this is the raw account and it can't be decoded
						// therefore we should save the raw node make sure that we can decode this to a state object
						ret := new(types.StateAccount)
						err = rlp.DecodeBytes(rn, ret)
						if err != nil {
							log.Error("LogFinalize [483] couldn't decode account", "idx", idx, "addr", *addr)
							panic(err)
							return false, nil, nil, nil, nil, nil, nil, nil
						}
						// now save this valueNode in the map
						hn := trie.HashData(rn)
						_, ok := accountNodes[hn]
						if !ok {
							accountNodes[hn] = rn
						}
					}
				}
			}
		case getStorageEntry:
			addr = logEntry.Account()
			key = logEntry.Key()
			keykey = KeyKey{*addr, *key}
			// ASSERT that we've sene the account before
            //_, candd := createdAndDeleted[*addr]
            //_, revd := revertedCreateObject[*addr]
			_, ok := accounts[*addr]
            // this account acn be in createdAndDeleted and still be in accounts if
            // it is created more than once and finally persists
            //if candd || revd {
            //    // this was created and deleted in this same transaction so we can ignore this
            //    if ok {
            //        log.Error("This account was createdAndDeleted but is in acccounts??", "addr", *addr, "candd", candd, "revd", revd)
            //        panic("logFinalize getStateObject error")
            //    }
            //}
			if !ok {
				panic(fmt.Sprintf("getStorage(addr=%v, key=%v) but addr not in accountsSeen", *addr, *key))
				log.Error(fmt.Sprintf("LogFinalize [513] getStorage(addr=%v, key=%v) but addr not in accountsSeen", *addr, *key))
				return false, nil, nil, nil, nil, nil, nil, nil
			}
		
			//_, ok = s.keysSeen[keykey]
			_, ok = keys[keykey]
			if !ok {
				// get the stateObject first it should be in stateObjects
				obj, exist := s.stateObjects[*addr]
				if !exist {
                    // if it doesn't exist that means this is a getStorage for an account
                    // that was created and then un-created in this transaction. There is 
                    // NO trie paths to get, and there is nothing to log.
                    continue
					//panic(fmt.Sprintf("Address %v not in stateObejcts", *addr))
					//log.Error(fmt.Sprintf("LogFinalize [524] Address %v not in stateObejcts", *addr))
					//return false, nil, nil, nil, nil, nil, nil, nil
				}
				//log.Info("log finalize storage entry CALL", "addr", *addr, "key", *key)
				log.Debug("LogFinalize: key access", "addr", *addr, "key", *key)
				success, trieVal, pathHashes, rawNodesOnPath := obj.GetTrieStateLogged(*key)
				if !success {
					return false, nil, nil, nil, nil, nil, nil, nil
				}
				//log.Info("log finalize storage entry", "addr", *addr, "key", *key)
				var testVal common.Hash
				testVal.SetBytes(nil)
				if trieVal.Cmp(testVal) != 0 {
					if len(pathHashes) > 0 && len(rawNodesOnPath) > 0 {
						s.keysInTrie[keykey] = trieVal
					}
				}
				if len(pathHashes) == 0 || len(rawNodesOnPath) == 0 {
					// this is only accepted behavior if the root is nil otherwise at least the root 
					// is always accessed.
					// OR the root node is a short node and there is only 1 key in the trie
					if (obj.data.Root.Cmp(types.EmptyRootHash) == 0) {
						// it is correct to log nothing for this key get, maybe we just skip it altogether?
						continue
					} else {
						s.findAll(*addr)	
						//s.findGetCreates(*addr)
						s.findGetSets(*addr, *key)
						m, _ := accounts[*addr]
						log.Error("Account information", "hashes", m)
						panic(fmt.Sprintf("GetStorageLogged(addr=%v, key=%v, idx=%v) gave no data", *addr, *key, idx))
						log.Error(fmt.Sprintf("LogFinalize [552] GetStorageLogged(addr=%v, key=%v, idx=%v) gave no data", *addr, *key, idx))
						return false, nil, nil, nil, nil, nil, nil, nil
					}
				}
				keys[keykey] = pathHashes
				for _, rn := range rawNodesOnPath {
					n, err := trie.PublicDecodeNode(nil, rn)
					if err == nil {
						hn := trie.HashNode(n)
						_, ok := keyNodes[hn]
                        if !ok {
							keyNodes[hn] = rn
						}
					} else {
						// this is a valuenode we do the normal check that the hash is in there
						hn := trie.HashData(rn)
						_, ok := keyNodes[hn]
                        if !ok {
							keyNodes[hn] = rn
						}
					}
				}
			}
		case storageChange:
			// we only care about NEW state created so that we can log that we've seen it		
			var testVal common.Hash
			testVal.SetBytes(nil)
			if logEntry.prevvalue.Cmp(testVal) == 0 {
				// log this as a change
				addr = &(logEntry.account)
				key = &(logEntry.key)
				keykey = KeyKey{*addr, *key}
				_, ok := accounts[*addr]
				if !ok {
					panic(fmt.Sprintf("getStorage(addr=%v, key=%v) but addr not in accountsSeen", *addr, *key))
					log.Error(fmt.Sprintf("LogFinalize [599] getStorage(addr=%v, key=%v) but addr not in accountsSeen", *addr, *key))
					return false, nil, nil, nil, nil, nil, nil, nil
				}
				obj, exist := s.stateObjects[*addr]
				if !exist {
                    // if this is something that doesn't exist then it was created and un-created
                    // in the same block, so we ignore these changes
                    continue
					//panic(fmt.Sprintf("Address %v not in stateObejcts", *addr))
					//log.Error(fmt.Sprintf("LogFinalize [605] Address %v not in stateObejcts", *addr))
					//return false, nil, nil, nil, nil, nil, nil, nil
				}
				// GetStateLogged is called here because there is no "miss" for the storage change from nil
				// GetStateLogged is just to check that the get short circuits and gives no paths or nodes
				success, _, pathHashes, rawNodesOnPath := obj.GetStateLogged(*key)
				if !success {
					log.Error("LogFinalize: GetStateLogged PANIC")
					return false, nil, nil, nil, nil, nil, nil, nil
				}

				if !(len(pathHashes) == 0 && len(rawNodesOnPath) == 0) {
					panic(fmt.Sprintf("GetStorageLogged(addr=%v, key=%v) for a new key gave data", *addr, *key))
					log.Error(fmt.Sprintf("LogFinalize [613] GetStorageLogged(addr=%v, key=%v) for a new key gave data", *addr, *key))
					return false, nil, nil, nil, nil, nil, nil, nil
				}
				//keys[keykey] = nil
				log.Debug("LogFinalize: storage write", "addr", *addr, "key", *key, "prev", logEntry.prevvalue, "new", logEntry.newvalue)
				v := obj.GetState(*key)
				rawNode := valueToLeaf(v)
				rawNodeHash := trie.HashLeaf(rawNode)
				keys[keykey] = []common.Hash{rawNodeHash}
				// what is the current value
				keyNodes[rawNodeHash] = rawNode
			}
        case selfDestructChange:
            // here we check off the ones that are in createdAndDeleted.
            // The way deletes work is that the "origin" field of an account that was created
            // will be nil. When it is time to commit and flush to the db, these deletes 
            // are ignored because it is a nil -> nil transition in the backing database
            addr := &(logEntry.account)
            _, ok := createdAndDeleted[*addr]
            if ok {
                // we can now mark this entry as FALSE
                createdAndDeleted[*addr] = false
            }
		default:
		}
	}

    // now we sanity check that all the accounts we thought were created and deleted
    // in the same block were ones where we saw a selfDestruct
    for addr, checked := range createdAndDeleted {
        if checked {
            // this means we never saw a selfDestruct for it because 
            // that's the only reason that it wouldn't be in stateObjects if 
            // it wasn't reverted
            log.Error("Account in createdAndDeleted didn't have a corresponding selfDestruct", "addr", addr)
            panic("log finalize createdAndDeleted sanity check Failed!")
        }
    }
    
	// no we've stored all the path hashes and the raw nodes for each key that is gotten
	// now we log all of this information
	// sanity checking: assert that all the raw nodes correspond to hashes in the other set
	inAccounts := 0
	notInAccounts := 0
	for _, hashes := range accounts {
		for _, hn := range hashes {
			_, ok := accountNodes[hn]
			if ok {
				inAccounts++
			} else {
				notInAccounts++
			}
		}
	}
	//log.Info("Sanity checks.", "inAccounts", inAccounts, "notInAccounts", notInAccounts)
	// we shouldn't cache these since they will apply to the next transaction as well
	// instead, we should mark when one transaction ends and another begins (but this is just the same as 
	if conflict(accountNodes, keyNodes) {
		panic("Conflict in the two maps")
		log.Error("Conflict in the two maps")
		return false, nil, nil, nil, nil, nil, nil, nil
	}
	
	return true, emptys, accounts, accountNodes, keys, keyNodes, createdAndDeleted, revertedCreateObject
}

func conflict(m1 map[common.Hash][]byte, m2 map[common.Hash][]byte) bool {
	// Q: do we have any conflicting keys between the two maps that aren't empty hashes?
	// A: no we don't so we can combine the two tries
	for hn, _ := range m1 {
		_, exists := m2[hn]
		if exists {
			log.Error("Same hash in account and state trie.", "k", hn)
			return true
		}
	}

	for hn, _ := range m2 {
		_, exists := m1[hn]
		if exists {
			log.Error("Same hash in account and state trie.", "k", hn)
			return true
		}
	}
	return false
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



