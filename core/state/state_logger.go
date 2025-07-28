package state

import (
	"bytes"
	"fmt"
	"slices"

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
		panic(fmt.Sprintf("Called accountToEncodeNode with address not in stateObjects: %v", addr))
		//log.Error(fmt.Sprintf("Called accountToEncodeNode with address not in stateObjects: %v", addr))
		//return false, nil
	}
	return true, stateObjectToBytes(obj)
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
					log.Info("Get target.", "idx", idx, "addr", a, "key", k, "value", logEntry.value)
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
					log.Info("Target entry", "idx", idx, "addr", addr, "key", key, "prevvalue", logEntry.prevvalue, "new", logEntry.newvalue)
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
					log.Info("Found a match")
					if !seen {
						log.Info("Get storage target", "journal", jidx, "idx", idx, "addr", a, "key", k, "revert", lentry.Reverted)
						seenKeys[KeyKey{a, k}] = true
					}
				}
			case getStateObjectEntry:
				a := logEntry.account
				if addr.Cmp(a) == 0 {
					log.Info("Get obj target", "journal", jidx, "idx", idx, "addr", a, "revert", lentry.Reverted)
				}
			case createObjectChange:
				a := logEntry.account
				if addr.Cmp(a) == 0 {
					log.Info("create obj target", "journal", jidx, "idx", idx, "addr", a, "revert", lentry.Reverted)
				}
			case selfDestructChange:
				a := logEntry.account
				if addr.Cmp(a) == 0 {
					log.Info("Self destruct target", "journal", jidx, "idx", idx, "addr", a, "revert", lentry.Reverted)
				}
			case createContractChange:
				a := logEntry.account
				if addr.Cmp(a) == 0 {
					log.Info("create contract change", "journal", jidx, "idx", idx, "addr", a, "revert", lentry.Reverted)
				}
			default:
			}
		}
	}
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
				log.Info("Get storage target", "idx", idx, "addr", a, "key", k, "revert", lentry.Reverted)
				seenKeys[KeyKey{a, k}] = true
			}
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
					log.Info("couldn't decode account", "addr", addr)
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
			log.Info("Getting the key of account that doesn't exist", "addr", addr)
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
					log.Info("conflict", "rn", rn, "oldrn", oldrn)
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
func (s *StateDB) LogFinalize() (bool, []common.Address, map[common.Address][]common.Hash, map[common.Hash][]byte, map[KeyKey][]common.Hash, map[common.Hash][]byte) {
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

	//createdAndDeleted := map[common.Address]bool

	for idx, lentry := range s.journal.logEntries {
		var addr *common.Address
		var key *common.Hash
		var keykey KeyKey
		switch logEntry := (lentry.Entry).(type) {
		case createObjectChange:
			// this is a new stateObject so log the hash the value node representation of the state
			addr = &(logEntry.account)
			log.Info("Is this marked as reverted??", "addr", *addr, "reverted", lentry.Reverted)
			_, rawNode := s.accountToBytes(*addr)
			// the node has no hash so we store the key and value as the same
			// convert it into a hashNode	
			//if len(rawNode) > common.HashLength {
			//	log.Error("Doing a BytesToHash of a rawNode that is too big", "rawNode", len(rawNode))
			//	panic("soundness error")
			//}
			//rawNodeHash := common.BytesToHash(rawNode)
			rawNodeHash := trie.HashValueNode(rawNode)
			// set it to nil because this is a new account
			// for all accounts that don't have a path then we know it's a new one
			//accounts[*addr] = nil
			_, ok := accounts[*addr]
			if ok {
				log.Info("LogFinalize: Created twice", "account", *addr)
			}
			accounts[*addr] = []common.Hash{rawNodeHash}
			accountNodes[rawNodeHash] = rawNode
		case createContractChange:
			// need to check if this already exists, sometimes the object is created before
			// the contract is "created"
			addr = &(logEntry.account)
			_, ok := accounts[*addr]
			if ok {
				// this object is created and then set as a contract
				log.Info("LogFinalize: contract crearte of existing obj", "addr", *addr)
			}
			_, rawNode := s.accountToBytes(*addr)
			//if !found {
			//	log.Info("createContractChange: account not in stateObjects means it must have been deleted in the same transaction or the same block after this event.", "addr", *addr)
			//	// keep an eye on this and wait for a delete to happen
			//	prev, ok := createdAndDeleted[*addr]
			//	if ok {
			//		// should be false, should delete before another create
			//		log.Error("Account was already seen as created", "addr", *addr)
			//		if prev {
			//			log.Error("this thing was prev created sna created again without a delete", "addr", *addr)
			//			return false, nil, nil, nil, nil, nil
			//		}
			//	}
			//	createdAndDeleted[*addr] = true
			//	continue
			//}
			//rawNodeHash := common.BytesToHash(rawNode)
			rawNodeHash := trie.HashValueNode(rawNode)
			//accounts[*addr] = nil
			accounts[*addr] = []common.Hash{rawNodeHash}
			accountNodes[rawNodeHash] = rawNode
		case getStateObjectEntry:
			addr = logEntry.Account()
			_, ok := accounts[*addr]
			if !ok {
				// we haven't seen it so we store the nodes on the path
				res, _, pathHashes, rawNodesOnPath, err := s.trie.GetAccountLogged(*addr)
				log.Info("LogFinalize: account access", "addr", *addr)
				if err != nil || len(pathHashes) == 0 || len(rawNodesOnPath) == 0 {
					// try stateObjects
					_, ok := s.stateObjects[*addr]
					log.Info("Addr in stateObjects?", "addr", *addr, "ok", ok)
					// try reader
					acct, err := s.reader.Account(*addr)
					log.Info("Reader check", "acct", acct, "err", err)
					log.Error("LogFinalise [454]: FAILURE")
					return false, nil, nil, nil, nil, nil
					//panic("")
				}
				// what about getting addresses that don't exist?
				if res != nil {
					s.accountsInTrie[*addr] = true
				}

				accounts[*addr] = pathHashes
				for _, rn := range rawNodesOnPath {
					n, err := trie.PublicDecodeNode(nil, rn)
					if err == nil {
						hn := trie.HashNode(n)
						oldrn, ok := accountNodes[hn]
						
						if ok {
							// then the raw nodes should be the same
							if bytes.Compare(rn, oldrn) != 0 {
								//panic(fmt.Sprintf("Same hash %v has two different raw nodes.", hn))
								log.Error(fmt.Sprintf("LogFinalize [474] Same hash %v has two different raw nodes.", hn))
								return false, nil, nil, nil, nil, nil
							}
						} else {
							accountNodes[hn] = rn
						}
					} else {
						// if this is an error, then we assume that this is the raw account and it can't be decoded
						// therefore we should save the raw node make sure that we can decode this to a state object
						ret := new(types.StateAccount)
						err = rlp.DecodeBytes(rn, ret)
						if err != nil {
							log.Error("LogFinalize [483] couldn't decode account", "idx", idx, "addr", *addr)
							return false, nil, nil, nil, nil, nil
							//panic(err)
						}
						// now save this valueNode in the map
						hn := trie.HashData(rn)
						oldrn, ok := accountNodes[hn]
						if ok {
							if bytes.Compare(rn, oldrn) != 0 {
								//panic(fmt.Sprintf("Same hash %v has two different accounts", hn))
								log.Error(fmt.Sprintf("LogFinalize [496] Same hash %v has two different accounts", hn))
								return false, nil, nil, nil, nil, nil
							}
						} else {
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
			_, ok := accounts[*addr]
			if !ok {
				//panic(fmt.Sprintf("getStorage(addr=%v, key=%v) but addr not in accountsSeen", *addr, *key))
				log.Error(fmt.Sprintf("LogFinalize [513] getStorage(addr=%v, key=%v) but addr not in accountsSeen", *addr, *key))
				return false, nil, nil, nil, nil, nil
			}
		
			//_, ok = s.keysSeen[keykey]
			_, ok = keys[keykey]
			if !ok {
				// get the stateObject first it should be in stateObjects
				obj, exist := s.stateObjects[*addr]
				if !exist {
					//panic(fmt.Sprintf("Address %v not in stateObejcts", *addr))
					log.Error(fmt.Sprintf("LogFinalize [524] Address %v not in stateObejcts", *addr))
					return false, nil, nil, nil, nil, nil
				}
				//log.Info("log finalize storage entry CALL", "addr", *addr, "key", *key)
				log.Info("LogFinalize: key access", "addr", *addr, "key", *key)
				success, trieVal, pathHashes, rawNodesOnPath := obj.GetTrieStateLogged(*key)
				if !success {
					return false, nil, nil, nil, nil, nil
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
						//panic(fmt.Sprintf("GetStorageLogged(addr=%v, key=%v, idx=%v) gave no data", *addr, *key, idx))
						log.Error(fmt.Sprintf("LogFinalize [552] GetStorageLogged(addr=%v, key=%v, idx=%v) gave no data", *addr, *key, idx))
						return false, nil, nil, nil, nil, nil
					}
				}
				keys[keykey] = pathHashes
				for _, rn := range rawNodesOnPath {
					n, err := trie.PublicDecodeNode(nil, rn)
					if err == nil {
						hn := trie.HashNode(n)
						oldrn, ok := keyNodes[hn]
						if ok {
							if bytes.Compare(rn, oldrn) != 0 {
								//panic(fmt.Sprintf("Same hash %v has two different raw nodes.", hn))
								log.Error(fmt.Sprintf("LogFinalize [565] Same hash %v has two different raw nodes.", hn))
								return false, nil, nil, nil, nil, nil
							}
						} else {
							keyNodes[hn] = rn
						}
					} else {
						// this is a valuenode we do the normal check that the hash is in there
						hn := trie.HashData(rn)
						oldrn, ok := keyNodes[hn]
						if ok {
							if bytes.Compare(rn, oldrn) != 0 {
								//panic(fmt.Sprintf("Same hash %v hash two different valuenodes. rn=%v, oldrn=%v", hn, rn, oldrn))
								log.Error(fmt.Sprintf("LogFinalize [578] Same hash %v hash two different valuenodes. rn=%v, oldrn=%v", hn, rn, oldrn))
								return false, nil, nil, nil, nil, nil
							}
						} else {
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
					//panic(fmt.Sprintf("getStorage(addr=%v, key=%v) but addr not in accountsSeen", *addr, *key))
					log.Error(fmt.Sprintf("LogFinalize [599] getStorage(addr=%v, key=%v) but addr not in accountsSeen", *addr, *key))
					return false, nil, nil, nil, nil, nil
				}
				obj, exist := s.stateObjects[*addr]
				if !exist {
					//panic(fmt.Sprintf("Address %v not in stateObejcts", *addr))
					log.Error(fmt.Sprintf("LogFinalize [605] Address %v not in stateObejcts", *addr))
					return false, nil, nil, nil, nil, nil
				}
				// GetStateLogged is called here because there is no "miss" for the storage change from nil
				// GetStateLogged is just to check that the get short circuits and gives no paths or nodes
				success, _, pathHashes, rawNodesOnPath := obj.GetStateLogged(*key)
				if !success {
					log.Error("LogFinalize: GetStateLogged PANIC")
					return false, nil, nil, nil, nil, nil
				}

				if !(len(pathHashes) == 0 && len(rawNodesOnPath) == 0) {
					//panic(fmt.Sprintf("GetStorageLogged(addr=%v, key=%v) for a new key gave data", *addr, *key))
					log.Error(fmt.Sprintf("LogFinalize [613] GetStorageLogged(addr=%v, key=%v) for a new key gave data", *addr, *key))
					return false, nil, nil, nil, nil, nil
				}
				//keys[keykey] = nil
				log.Info("LogFinalize: storage write", "addr", *addr, "key", *key, "prev", logEntry.prevvalue, "new", logEntry.newvalue)
				v := obj.GetState(*key)
				rawNode := valueToLeaf(v)
				rawNodeHash := trie.HashLeaf(rawNode)
				keys[keykey] = []common.Hash{rawNodeHash}
				// what is the current value
				keyNodes[rawNodeHash] = rawNode
			}
		default:
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
		//panic("Conflict in the two maps")
		log.Error("Conflict in the two maps")
		return false, nil, nil, nil, nil, nil
	}
	
	return true, emptys, accounts, accountNodes, keys, keyNodes
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



