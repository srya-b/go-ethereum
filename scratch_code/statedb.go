func (s *StateDB) SetState(addr common.Address, key, value common.Hash) {
	var stateObject *stateObject
	//var pathHashes []common.Hash
	//var rawNodesOnPath [][]byte
	//var valNodeBytes []byte
	//var prevValue common.Hash
	//var created bool
	//if s.logState {
	//	// TODO when is stateobject nil
	//	stateObject, valNodeBytes, pathHashes, rawNodesOnPath, created = s.getOrNewStateObjectLogged(addr)
	//	if created {
	//		// new object so nothing to log except the new value
	//		if pathHashes != nil || rawNodesOnPath != nil || valNodeBytes != nil {
	//			panic("SetState: creating a new object but somehow received a path!")
	//		}
	//		s.logSetStateCreate(addr, key, value, nil, []common.Hash{})
	//	} else {
	//		// created is False here!!
	//		if pathHashes != nil && rawNodesOnPath != nil {
	//			if valNodeBytes == nil {
	//				panic("SetState: not a create and never seen this before and valNode is nil")
	//			}
	//			// this is the first time we're getting this slot so we have to save that
	//			// information
	//			s.logGetState(addr, key, value, valNodeBytes, pathHashes)
	//		} else if pathHashes == nil && rawNodesOnPath == nil {
	//			// NOT created and SEEN BEFORE
	//			s.logGetState(addr, key, value, nil, []common.Hash{})
	//		} else {
	//			// it wasn't created and only one of them is nil
	//			if s.pathsTaken == nil {
	//				panic("SetState: pathHashes is nil but rawNodes isn't.")
	//			} else {
	//				panic("SetState: rawNodes is nil but pathHashes isn't.")
	//			}
	//		}
	//	}
	//	if stateObject != nil {
	//		prevValue, pathHashes, rawNodesOnPath = stateObject.SetStateLogged(key, value)
	//		if pathHashes == nil && rawNodesOnPath == nil {
	//			// we've seen this before so just log the new update we already know what the old value is
	//			// no new pathhashes and no valnode created for it
	//			s.logSetStorage(addr, key, value, nil, []common.Hash{})
	//		} else if pathHashes != nil && rawNodesOnPath != nil {
	//			// this means the getStateLogged call accessed something for the first time (this implies it's NOT DIRTY)
	//			// so we need to log an OpGetStorage with the value `prevValue` and then a setState with the nwe value
	//			s.logGetStorage(addr, key, prevValue, nil, pathHashes)
	//			// now we log the change to the key
	//			s.logSetStorage(addr, key, value, nil, []common.Hash{})
	//		} else {
	//			if s.pathsTaken == nil {
	//				panic("SetState: pathHashes is nil but rawNodes isn't.")
	//			} else {
	//				panic("SetState: rawNodes is nil but pathHashes isn't.")
	//			}
	//		}
	//	}
	//} else {
	stateObject = s.getOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetState(key, value)
	}
	//}
}

func (s *StateDB) SetCode(addr common.Address, code []byte) {
	//var stateObject *stateObject
	//var pathHashes []common.Hash
	//var rawNodesOnPath [][]byte
	//var valNodeBytes []byte
	////var prevValue common.Hash
	//var created bool
	//if s.logState {
	//	stateObject, valNodeBytes, pathHashes, rawNodesOnPath, created = s.getOrNewStateObjectLogged(addr)
	//	if created {
	//		// new account created that must be credited
	//		if pathHashes != nil || rawNodesOnPath != nil || valNodeBytes != nil {
	//			panic("SetState: creating a new object but somehow received a path!")
	//		}
	//		s.logSetStateCreate(addr, emptyHash, emptyHash, nil, []common.Hash{})
	//		//s.logAddBalance(addr, amount)
	//	} else {
	//		// created is False here!!
	//		if pathHashes != nil && rawNodesOnPath != nil {
	//			if valNodeBytes == nil {
	//				panic("SetState: not a create and never seen this before and valNode is nil")
	//			}
	//			// this is the first time we're getting this slot so we have to save that
	//			// information
	//			s.logGetState(addr, emptyHash, emptyHash, valNodeBytes, pathHashes)
	//			//s.logAddBalance(addr, amount)
	//		} else if pathHashes == nil && rawNodesOnPath == nil {
	//			// NOT created and SEEN BEFORE
	//			s.logGetState(addr, emptyHash, emptyHash, nil, []common.Hash{})
	//			//s.logAddBalance(addr, amount)
	//		} else {
	//			// it wasn't created and only one of them is nil
	//			if s.pathsTaken == nil {
	//				panic("SetState: pathHashes is nil but rawNodes isn't.")
	//			} else {
	//				panic("SetState: rawNodes is nil but pathHashes isn't.")
	//			}
	//		}
	//	}
	//	if stateObject != nil {
	//		stateObject.SetCode(crypto.Keccak256Hash(code), code)
	//		// TODO: for now we don't store the real code just the hash
	//		s.logSetCode(addr, crypto.Keccak256Hash(code).Bytes())
	//	}
	//} else {
	stateObject := s.getOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetCode(crypto.Keccak256Hash(code), code)
	}
	//}
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

func (s *StateDB) logSetStorageCreate(addr common.Address, key common.Hash, value common.Hash, node []byte, pathsTaken []common.Hash) {
	s.opsCalled = append(s.opsCalled, OP{op: OpSetStorageCreate, addr: addr, key: key, value: value, node: node})
	s.pathsTaken = append(s.pathsTaken, pathsTaken)
	s.totalOps = s.totalOps + 1
}

func (s *StateDB) logSetStorage(addr common.Address, key common.Hash, value common.Hash, node []byte, pathsTaken []common.Hash) {
	s.opsCalled = append(s.opsCalled, OP{op: OpSetStorage, addr: addr, key: key, value: value, node: node})
	s.pathsTaken = append(s.pathsTaken, pathsTaken)
	s.totalOps = s.totalOps + 1
}

func (s *StateDB) SelfDestruct(addr common.Address) {
	//var stateObject *stateObject
	//var pathHashes []common.Hash
	//var rawNodesOnPath [][]byte
	//var valNodeBytes []byte
	//if s.logState {
	//	stateObject, pathHashes, valNodeBytes, rawNodesOnPath = s.getStateObjectLogged(addr)
	//	if pathHashes == nil && rawNodesOnPath == nil {
	//		// this means this is a live object so we don't have to do anything but log this access
	//		s.logGetState(addr, emptyHash, emptyHash, emptyHash.Bytes(), []common.Hash{})
	//	} else {
	//		// add this op to the list of ops
	//		s.logGetState(addr, emptyHash, emptyHash, valNodeBytes, pathHashes)
	//	}
	//	if stateObject == nil {
	//		// log destruct something that doesn't exist
	//		s.logSelfDestruct(common.MaxAddress, []common.Hash{})
	//		return
	//	}
	//	var (
	//		prev = new(uint256.Int).Set(stateObject.Balance())
	//		n    = new(uint256.Int)
	//	)
	//	s.journal.append(selfDestructChange{
	//		account:     &addr,
	//		prev:        stateObject.selfDestructed,
	//		prevbalance: prev,
	//	})

	//	if s.logger != nil && s.logger.OnBalanceChange != nil && prev.Sign() > 0 {
	//		s.logger.OnBalanceChange(addr, prev.ToBig(), n.ToBig(), tracing.BalanceDecreaseSelfdestruct)
	//	}
	//	s.logSelfDestruct(addr, []common.Hash{})
	//	stateObject.markSelfdestructed()
	//	s.arbExtraData.unexpectedBalanceDelta.Sub(s.arbExtraData.unexpectedBalanceDelta, stateObject.data.Balance.ToBig())
	//	stateObject.data.Balance = n
	//} else {
	stateObject := s.getStateObject(addr)
	if stateObject == nil {
		return
	}
	var (
		prev = new(uint256.Int).Set(stateObject.Balance())
		n    = new(uint256.Int)
	)
	s.journal.append(selfDestructChange{
		account:     &addr,
		prev:        stateObject.selfDestructed,
		prevbalance: prev,
	})

	if s.logger != nil && s.logger.OnBalanceChange != nil && prev.Sign() > 0 {
		s.logger.OnBalanceChange(addr, prev.ToBig(), n.ToBig(), tracing.BalanceDecreaseSelfdestruct)
	}
	stateObject.markSelfdestructed()
	s.arbExtraData.unexpectedBalanceDelta.Sub(s.arbExtraData.unexpectedBalanceDelta, stateObject.data.Balance.ToBig())
	stateObject.data.Balance = n
	//}
}

func (s *StateDB) GetState(addr common.Address, hash common.Hash) common.Hash {
	var stateObject *stateObject
	//var pathHashes []common.Hash
	//var rawNodesOnPath [][]byte
	//var valNodeBytes []byte
	//if s.logState {
	//	stateObject, pathHashes, valNodeBytes, rawNodesOnPath = s.getStateObjectLogged(addr)
	//	if pathHashes == nil && rawNodesOnPath == nil {
	//		// this means this is a live object so we don't have to do anything but log this access
	//		s.logGetState(addr, hash, types.EmptyCodeHash, types.EmptyCodeHash.Bytes(), []common.Hash{})
	//	} else {
	//		// add this op to the list of ops
	//		s.logGetState(addr, hash, types.EmptyCodeHash, valNodeBytes, pathHashes)
	//	}
	//	if stateObject != nil {
	//		var storageObject common.Hash
	//		storageObject, pathHashes, rawNodesOnPath = stateObject.GetStateLogged(hash)
	//		if pathHashes == nil && rawNodesOnPath == nil {
	//			s.logGetStorage(addr, hash, types.EmptyCodeHash, nil, []common.Hash{})
	//		} else {
	//			s.logGetStorage(addr, hash, storageObject, nil, pathHashes)
	//		}
	//		return storageObject
	//	} else {
	//		// maybe we didn't find anything, in this case we should record the path taken for validation and that the key wasn't found  
	//		if pathHashes == nil || rawNodesOnPath == nil {
	//			panic("GetState: stateObject no found and nothing traversed?")
	//		}
	//		s.logGetStorageMiss(addr, hash, types.EmptyCodeHash, nil, pathHashes)
	//	}
	//} else {
	stateObject = s.getStateObject(addr)
	
	if stateObject != nil {
		return stateObject.GetState(hash)
	}
	//}
	return common.Hash{}
}

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

func (s *StateDB) logAddBalance(addr common.Address, amt uint256.Int) {
	s.opsCalled = append(s.opsCalled, OP{op: OpAddBalance, addr: addr, key: types.EmptyCodeHash, value: types.EmptyCodeHash, node: nil, amt: amt})
	s.pathsTaken = append(s.pathsTaken, []common.Hash{})
	s.totalOps = s.totalOps + 1
}

func (s *StateDB) logSubBalance(addr common.Address, amt uint256.Int) {
	s.opsCalled = append(s.opsCalled, OP{op: OpSubBalance, addr: addr, key: types.EmptyCodeHash, value: types.EmptyCodeHash, node: nil, amt: amt})
	s.pathsTaken = append(s.pathsTaken, []common.Hash{})
	s.totalOps = s.totalOps + 1
}

func (s *StateDB) logSetBalance(addr common.Address, amt uint256.Int) {
	s.opsCalled = append(s.opsCalled, OP{op: OpSetBalance, addr: addr, key: types.EmptyCodeHash, value: types.EmptyCodeHash, node: nil, amt: amt})
	s.pathsTaken = append(s.pathsTaken, []common.Hash{})
	s.totalOps = s.totalOps + 1
}

func (s *StateDB) AddBalance(addr common.Address, amount *uint256.Int, reason tracing.BalanceChangeReason) {
	//var stateObject *stateObject
	//var pathHashes []common.Hash
	//var rawNodesOnPath [][]byte
	//var valNodeBytes []byte
	////var prevValue common.Hash
	//var created bool
	//if s.logState {
	//	stateObject, valNodeBytes, pathHashes, rawNodesOnPath, created = s.getOrNewStateObjectLogged(addr)
	//	if created {
	//		// new account created that must be credited
	//		if pathHashes != nil || rawNodesOnPath != nil || valNodeBytes != nil {
	//			panic("SetState: creating a new object but somehow received a path!")
	//		}
	//		s.logSetStateCreate(addr, emptyHash, emptyHash, nil, []common.Hash{})
	//		//s.logAddBalance(addr, amount)
	//	} else {
	//		// created is False here!!
	//		if pathHashes != nil && rawNodesOnPath != nil {
	//			if valNodeBytes == nil {
	//				panic("SetState: not a create and never seen this before and valNode is nil")
	//			}
	//			// this is the first time we're getting this slot so we have to save that
	//			// information
	//			s.logGetState(addr, emptyHash, emptyHash, valNodeBytes, pathHashes)
	//			//s.logAddBalance(addr, amount)
	//		} else if pathHashes == nil && rawNodesOnPath == nil {
	//			// NOT created and SEEN BEFORE
	//			s.logGetState(addr, emptyHash, emptyHash, nil, []common.Hash{})
	//			//s.logAddBalance(addr, amount)
	//		} else {
	//			// it wasn't created and only one of them is nil
	//			if s.pathsTaken == nil {
	//				panic("SetState: pathHashes is nil but rawNodes isn't.")
	//			} else {
	//				panic("SetState: rawNodes is nil but pathHashes isn't.")
	//			}
	//		}
	//	}
	//	
	//	if stateObject != nil {
	//		// update the balance
	//		// looks like this just logs all the balance deltas that happen in statedb
	//		s.arbExtraData.unexpectedBalanceDelta.Add(s.arbExtraData.unexpectedBalanceDelta, amount.ToBig())
	//		s.logAddBalance(addr, *amount)
	//		stateObject.AddBalanceLogged(amount, reason)
	//	} else {
	//		panic("AddBalance: stateObject shouldnever be nil, it is created if nil")
	//	}
	//} else {
	stateObject := s.getOrNewStateObject(addr)
	if stateObject != nil {
		s.arbExtraData.unexpectedBalanceDelta.Add(s.arbExtraData.unexpectedBalanceDelta, amount.ToBig())
		stateObject.AddBalance(amount, reason)
	}
	//}
}
func (s *StateDB) SubBalance(addr common.Address, amount *uint256.Int, reason tracing.BalanceChangeReason) {
	//var stateObject *stateObject
	//var pathHashes []common.Hash
	//var rawNodesOnPath [][]byte
	//var valNodeBytes []byte
	////var prevValue common.Hash
	//var created bool
	//if s.logState {
	//	stateObject, valNodeBytes, pathHashes, rawNodesOnPath, created = s.getOrNewStateObjectLogged(addr)
	//	if created {
	//		// new account created that must be credited
	//		if pathHashes != nil || rawNodesOnPath != nil || valNodeBytes != nil {
	//			panic("SetState: creating a new object but somehow received a path!")
	//		}
	//		s.logSetStateCreate(addr, emptyHash, emptyHash, nil, []common.Hash{})
	//		//s.logAddBalance(addr, amount)
	//	} else {
	//		// created is False here!!
	//		if pathHashes != nil && rawNodesOnPath != nil {
	//			if valNodeBytes == nil {
	//				panic("SetState: not a create and never seen this before and valNode is nil")
	//			}
	//			// this is the first time we're getting this slot so we have to save that
	//			// information
	//			s.logGetState(addr, emptyHash, emptyHash, valNodeBytes, pathHashes)
	//			//s.logAddBalance(addr, amount)
	//		} else if pathHashes == nil && rawNodesOnPath == nil {
	//			// NOT created and SEEN BEFORE
	//			s.logGetState(addr, emptyHash, emptyHash, nil, []common.Hash{})
	//			//s.logAddBalance(addr, amount)
	//		} else {
	//			// it wasn't created and only one of them is nil
	//			if s.pathsTaken == nil {
	//				panic("SetState: pathHashes is nil but rawNodes isn't.")
	//			} else {
	//				panic("SetState: rawNodes is nil but pathHashes isn't.")
	//			}
	//		}
	//	}
	//	
	//	if stateObject != nil {
	//		// update the balance
	//		// looks like this just logs all the balance deltas that happen in statedb
	//		s.arbExtraData.unexpectedBalanceDelta.Sub(s.arbExtraData.unexpectedBalanceDelta, amount.ToBig())
	//		s.logSubBalance(addr, *amount)
	//		stateObject.SubBalance(amount, reason)
	//	} else {
	//		panic("AddBalance: stateObject shouldnever be nil, it is created if nil")
	//	}
	//} else {
	stateObject := s.getOrNewStateObject(addr)
	if stateObject != nil {
		s.arbExtraData.unexpectedBalanceDelta.Sub(s.arbExtraData.unexpectedBalanceDelta, amount.ToBig())
		stateObject.SubBalance(amount, reason)
	}
	//}
}
func (s *StateDB) SetBalance(addr common.Address, amount *uint256.Int, reason tracing.BalanceChangeReason) {
	//var stateObject *stateObject
	//var pathHashes []common.Hash
	//var rawNodesOnPath [][]byte
	//var valNodeBytes []byte
	////var prevValue common.Hash
	//var created bool
	//if s.logState {
	//	stateObject, valNodeBytes, pathHashes, rawNodesOnPath, created = s.getOrNewStateObjectLogged(addr)
	//	if created {
	//		// new account created that must be credited
	//		if pathHashes != nil || rawNodesOnPath != nil || valNodeBytes != nil {
	//			panic("SetState: creating a new object but somehow received a path!")
	//		}
	//		s.logSetStateCreate(addr, emptyHash, emptyHash, nil, []common.Hash{})
	//		//s.logAddBalance(addr, amount)
	//	} else {
	//		// created is False here!!
	//		if pathHashes != nil && rawNodesOnPath != nil {
	//			if valNodeBytes == nil {
	//				panic("SetState: not a create and never seen this before and valNode is nil")
	//			}
	//			// this is the first time we're getting this slot so we have to save that
	//			// information
	//			s.logGetState(addr, emptyHash, emptyHash, valNodeBytes, pathHashes)
	//			//s.logAddBalance(addr, amount)
	//		} else if pathHashes == nil && rawNodesOnPath == nil {
	//			// NOT created and SEEN BEFORE
	//			s.logGetState(addr, emptyHash, emptyHash, nil, []common.Hash{})
	//			//s.logAddBalance(addr, amount)
	//		} else {
	//			// it wasn't created and only one of them is nil
	//			if s.pathsTaken == nil {
	//				panic("SetState: pathHashes is nil but rawNodes isn't.")
	//			} else {
	//				panic("SetState: rawNodes is nil but pathHashes isn't.")
	//			}
	//		}
	//	}
	//	if stateObject != nil {
	//		if amount == nil {
	//			amount = uint256.NewInt(0)
	//		}
	//		prevBalance := stateObject.Balance()
	//		s.arbExtraData.unexpectedBalanceDelta.Add(s.arbExtraData.unexpectedBalanceDelta, amount.ToBig())
	//		s.arbExtraData.unexpectedBalanceDelta.Sub(s.arbExtraData.unexpectedBalanceDelta, prevBalance.ToBig())
	//		s.logSetBalance(addr, *amount)
	//		stateObject.SetBalance(amount, reason)
	//	}
	//} else {
	stateObject := s.getOrNewStateObject(addr)
	if stateObject != nil {
		if amount == nil {
			amount = uint256.NewInt(0)
		}
		prevBalance := stateObject.Balance()
		s.arbExtraData.unexpectedBalanceDelta.Add(s.arbExtraData.unexpectedBalanceDelta, amount.ToBig())
		s.arbExtraData.unexpectedBalanceDelta.Sub(s.arbExtraData.unexpectedBalanceDelta, prevBalance.ToBig())
		stateObject.SetBalance(amount, reason)
	}
	//}
}
func (s *StateDB) SetNonce(addr common.Address, nonce uint64) {
	//var stateObject *stateObject
	//var pathHashes []common.Hash
	//var rawNodesOnPath [][]byte
	//var valNodeBytes []byte
	////var prevValue common.Hash
	//var created bool
	//if s.logState {
	//	stateObject, valNodeBytes, pathHashes, rawNodesOnPath, created = s.getOrNewStateObjectLogged(addr)
	//	if created {
	//		// new account created that must be credited
	//		if pathHashes != nil || rawNodesOnPath != nil || valNodeBytes != nil {
	//			panic("SetState: creating a new object but somehow received a path!")
	//		}
	//		s.logSetStateCreate(addr, emptyHash, emptyHash, nil, []common.Hash{})
	//		//s.logAddBalance(addr, amount)
	//	} else {
	//		// created is False here!!
	//		if pathHashes != nil && rawNodesOnPath != nil {
	//			if valNodeBytes == nil {
	//				panic("SetState: not a create and never seen this before and valNode is nil")
	//			}
	//			// this is the first time we're getting this slot so we have to save that
	//			// information
	//			s.logGetState(addr, emptyHash, emptyHash, valNodeBytes, pathHashes)
	//			//s.logAddBalance(addr, amount)
	//		} else if pathHashes == nil && rawNodesOnPath == nil {
	//			// NOT created and SEEN BEFORE
	//			s.logGetState(addr, emptyHash, emptyHash, nil, []common.Hash{})
	//			//s.logAddBalance(addr, amount)
	//		} else {
	//			// it wasn't created and only one of them is nil
	//			if s.pathsTaken == nil {
	//				panic("SetState: pathHashes is nil but rawNodes isn't.")
	//			} else {
	//				panic("SetState: rawNodes is nil but pathHashes isn't.")
	//			}
	//		}
	//	}
	//	if stateObject != nil {
	//		stateObject.SetNonce(nonce)
	//		s.logSetNonce(addr, *(uint256.NewInt(nonce)))
	//	}
	//} else {
	stateObject := s.getOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetNonce(nonce)
	}
	//}
}
func (s *StateDB) logSetCode(addr common.Address, codeHash []byte) {
	s.opsCalled = append(s.opsCalled, OP{op: OpSetCode, addr: addr, key: emptyHash, value: emptyHash, node: codeHash})
	s.pathsTaken = append(s.pathsTaken, []common.Hash{})
	s.totalOps = s.totalOps + 1
}

func (s *StateDB) getStateObjectLogged(addr common.Address) (*stateObject, []common.Hash, []byte, [][]byte) {
	// Prefer live objects if any is available
	if obj := s.stateObjects[addr]; obj != nil {
		return obj, nil, nil, nil
	}
	// Short circuit if the account is already destructed in this block.
	// TODO what to do here?
	if _, ok := s.stateObjectsDestruct[addr]; ok {
		// let it return here because a destruted object is always known and instantly checked
		// eventually the advice or whatever can inform that something is destroyed, and we don't
		// want to cache anything explored here
		return nil, nil, nil, nil
	}
	// If no live objects are available, attempt to use snapshots
	// NOTE: snapshot reads are out of the question
	var data *types.StateAccount
	//if s.snap != nil {
	//	log.Info("Went through the snapshot")
	//	start := time.Now()
	//	acc, err := s.snap.Account(crypto.HashData(s.hasher, addr.Bytes()))
	//	s.SnapshotAccountReads += time.Since(start)

	//	if err == nil {
	//		if acc == nil {
	//			return nil, nil, nil
	//		}
	//		data = &types.StateAccount{
	//			Nonce:    acc.Nonce,
	//			Balance:  acc.Balance,
	//			CodeHash: acc.CodeHash,
	//			Root:     common.BytesToHash(acc.Root),
	//		}
	//		if len(data.CodeHash) == 0 {
	//			data.CodeHash = types.EmptyCodeHash.Bytes()
	//		}
	//		if data.Root == (common.Hash{}) {
	//			data.Root = types.EmptyRootHash
	//		}
	//	}
	//}
	// If snapshot unavailable or reading from it failed, load from the database
	var pathHashes []common.Hash
	var rawNodesOnPath [][]byte
	var valNodeBytes []byte
	if data == nil {
		log.Info("Looking in the trie")
		start := time.Now()
		var err error
		data, valNodeBytes, pathHashes, rawNodesOnPath, err = s.trie.GetAccountLogged(addr)
		s.AccountReads += time.Since(start)

		// TODO: what to do here
		if err != nil {
			s.setError(fmt.Errorf("getDeleteStateObject (%x) error: %w", addr.Bytes(), err))
			return nil, nil, nil, nil
		}
		if data == nil {
			return nil, nil, nil, nil
		}
	}
	// Insert into the live set
	obj := newObject(s, addr, data)
	s.setStateObject(obj)
	return obj, pathHashes, valNodeBytes, rawNodesOnPath
	//return obj
}


func (s *StateDB) getOrNewStateObjectLogged(addr common.Address) (*stateObject, []byte, []common.Hash, [][]byte, bool) {
	//obj, pathHashes, rawNodesOnPath := s.getStateObjectLogged(addr)
	obj, pathHashes, valNodeBytes, rawNodesOnPath := s.getStateObjectLogged(addr)
	if obj == nil {
		if pathHashes != nil || rawNodesOnPath != nil {
			panic("No state object, but getStateObjectLogged returns a path")
		}
		// in the case of create object, there's nothing to add to the logger
		obj = s.createObjectLogged(addr)
		return obj, nil, nil, nil, true
	}
	return obj, valNodeBytes, pathHashes, rawNodesOnPath, false
}

func (s *StateDB) createObjectLogged(addr common.Address) *stateObject {
	obj := newObject(s, addr, nil)
	s.journal.append(createObjectChange{account: &addr})
	s.setStateObject(obj)
	return obj
}

func (s *StateDB) logCreateAccount(addr common.Address) {
	s.opsCalled = append(s.opsCalled, OP{op: OpCreateAccount, addr: addr, key: emptyHash, value: emptyHash, node: nil})
	s.pathsTaken = append(s.pathsTaken, []common.Hash{})
	s.totalOps = s.totalOps + 1
}

func (s *StateDB) logCreateContract(addr common.Address) {
	s.opsCalled = append(s.opsCalled, OP{op: OpCreateContract, addr: addr, key: emptyHash, value: emptyHash, node: nil})
	s.pathsTaken = append(s.pathsTaken, []common.Hash{})
	s.totalOps = s.totalOps + 1
}


func (s *StateDB) CreateContract(addr common.Address) {
	//var stateObject *stateObject
	//var pathHashes []common.Hash
	//var rawNodesOnPath [][]byte
	//var valNodeBytes []byte
	//if s.logState {
	//	stateObject, pathHashes, valNodeBytes, rawNodesOnPath = s.getStateObjectLogged(addr)
	//	if pathHashes == nil && rawNodesOnPath == nil {
	//		// this path is already Live
	//		s.logGetState(addr, emptyHash, emptyHash, emptyHash.Bytes(), []common.Hash{})
	//	} else {
	//		// add this op to the list of ops
	//		s.logGetState(addr, emptyHash, emptyHash, valNodeBytes, pathHashes)
	//	}
	//	if !obj.newContract {
	//		obj.newContract = true	
	//		s.journal.append(createContractChange{account: addr})
	//	}
	//} else {
	obj := s.getStateObject(addr)
	if !obj.newContract {
		obj.newContract = true
		s.journal.append(createContractChange{account: addr})
	}
	//}
}
func (s *StateDB) CreateAccount(addr common.Address) {
	if s.logState {
		_ = s.createObjectLogged(addr)
		s.logCreateAccount(addr)
	} else {
		s.createObject(addr)
	}
}

func (s *StateDB) logSetNonce(addr common.Address, amt uint256.Int) {
	s.opsCalled = append(s.opsCalled, OP{op: OpSetBalance, addr: addr, key: types.EmptyCodeHash, value: types.EmptyCodeHash, node: nil, amt: amt})
	s.pathsTaken = append(s.pathsTaken, []common.Hash{})
	s.totalOps = s.totalOps + 1
}

func (s *StateDB) logSelfDestruct(addr common.Address, pathsTaken []common.Hash) {
	s.opsCalled = append(s.opsCalled, OP{op: OpSelfDestruct, addr: addr, key: emptyHash, value: emptyHash, node: nil})
	s.pathsTaken = append(s.pathsTaken, pathsTaken)
	s.totalOps = s.totalOps + 1
}


