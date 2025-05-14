package trie


import (
	"fmt"
	"bytes"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	_"github.com/ethereum/go-ethereum/trie/trienode"
	_"github.com/ethereum/go-ethereum/triedb/database"
	"github.com/ethereum/go-ethereum/log"
)

// Secure trie /  State trie

func (t *StateTrie) RootString() string {
	n, ok := t.trie.root.(*fullNode)
	if (!ok) {
		panic("Couldn't turn root node to fullNode")
	}
	return n.String()
}

func (t *StateTrie) RootBytes() (common.Hash, []byte) {
	return t.trie.RootBytes()
}

func (t *StateTrie) GetStorageLogged(_ common.Address, key []byte) ([]byte, []common.Hash, [][]byte, error) {
	enc, pathHashes, rawNodesOnPath, err := t.trie.GetLogged(t.hashKey(key))
	if err != nil { //|| len(enc) == 0 {
		log.Info("getstorage err")
		return nil, nil, nil, err
	}
	if len(enc) == 0 {
		//log.Info("enc == 0", "pathHashes", len(pathHashes))
		return nil, pathHashes, rawNodesOnPath, err
	}
	_, content, _, err := rlp.Split(enc)
	//log.Info("return content", "value", common.BytesToHash(content), "pathHashes", len(pathHashes))
	return content, pathHashes, rawNodesOnPath, err
}

func (t *StateTrie) GetAccountLogged(address common.Address) (*types.StateAccount, []byte, []common.Hash, [][]byte, error) {
	res, pathHashes, rawNodesOnPath, err := t.trie.GetLogged(t.hashKey(address.Bytes()))
	//log.Info("GetAccountLogged", "addr", address, "p", len(pathHashes), "err", err)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if res == nil {
		return nil, nil, pathHashes, rawNodesOnPath, err
	}
	ret := new(types.StateAccount)
	err = rlp.DecodeBytes(res, ret)
	//log.Info("GetAccountLogged decode", "addr", address, "red", res, "err", err)
	return ret, res, pathHashes, rawNodesOnPath, err
}

func (t *StateTrie) UpdateStorageLogged(_ common.Address, key, value []byte) error {
	hk := t.hashKey(key)
	v, _ := rlp.EncodeToBytes(value)
	err := t.trie.UpdateLogged(hk, v)
	if err != nil {
		return err
	}
	t.getSecKeyCache()[string(hk)] = common.CopyBytes(key)
	return nil
}

func (t *StateTrie) UpdateAccountLogged(address common.Address, acc *types.StateAccount, _ int) error {
	hk := t.hashKey(address.Bytes())
	data, err := rlp.EncodeToBytes(acc)
	if err != nil {
		return err
	}
	if err := t.trie.UpdateLogged(hk, data); err != nil {
		return err
	}
	t.getSecKeyCache()[string(hk)] = address.Bytes()
	return nil
}

func (t *StateTrie) UpdateContractCodeLogged(_ common.Address, _ common.Hash, _ []byte) error {
	return nil
}

func (t *StateTrie) DeleteStorageLogged(_ common.Address, key []byte) error {
	hk := t.hashKey(key)
	delete(t.getSecKeyCache(), string(hk))
	return t.trie.DeleteLogged(hk)
}

func (t *StateTrie) DeleteAccountLogged(address common.Address) error {
	hk := t.hashKey(address.Bytes())
	delete(t.getSecKeyCache(), string(hk))
	return t.trie.DeleteLogged(hk)
}

// TODO
func (t *StateTrie) GetKeyLogged(shaKey []byte) []byte {
	if key, ok := t.getSecKeyCache()[string(shaKey)]; ok {
		return key
	}
	if t.preimages == nil {
		return nil
	}
	//return t.db.Preimage(common.BytesToHash(shaKey))
	return t.preimages.Preimage(common.BytesToHash(shaKey))
}

/// Trie 

func PublicHashKey(key []byte) []byte {
	var hashKeyBuf [common.HashLength]byte
	h := newHasher(false)
	h.sha.Reset()
	h.sha.Write(key)
	h.sha.Read(hashKeyBuf[:])
	returnHasherToPool(h)
	return hashKeyBuf[:]
}

// returns teh byte encoding of the root node and its hash
func (t *Trie) RootBytes() (common.Hash, []byte) {
	switch n := (t.root).(type) {
	case *shortNode:
		// encode normally
		newsn := &shortNode{Key: hexToCompact(n.Key), Val: n.Val}
		newrawn, err := rlp.EncodeToBytes(newsn)
		if err != nil {
			panic(err)
		}
		return HashNode(newsn), newrawn
	case *fullNode:
		var hChildren [17]node
		for i, c := range &n.Children {
			if c != nil {
				switch cn := c.(type) {
				case *shortNode:
					//hChildren[i] = HashNodeAsHashNode( &shortNode{Key: hexToCompact(cn.Key), Val: cn.Val} )
					hChildren[i] = HashNodeAsHashNode( &shortNode{Key: cn.Key, Val: cn.Val} )
				default:
					hChildren[i] = HashNodeAsHashNode(c)
				}
			} else {
				hChildren[i] = nil
			}
		}		
		newfn := &fullNode{hChildren, nodeFlag{dirty: false}}
		rawnewfn, err := rlp.EncodeToBytes(newfn)
		if err != nil {
			panic(err)
		}
		return HashNode(newfn), rawnewfn
	case nil: 
		return types.EmptyCodeHash, nil
	//if t.root == nil {
	//	return hashNode(types.EmptyRootHash.Bytes()), nil
	//}
	default:
		panic(fmt.Sprintf("Root should only be shortNode, fullNode, or nil. It is actually: %v", t.root))
	}
}
	
func (t *Trie) RootString() string {
	n, ok := t.root.(*fullNode)
	if (!ok) {
		panic("Root couldn't be a fullNode")
	}
	return n.String()
}

func (t *Trie) GetLogged(key []byte) ([]byte, []common.Hash, [][]byte, error) {
	//log.Info("***************************GetLogged")
	// Short circuit if the trie is already committed and not usable.
	if t.committed {
		//log.Info("GetLogged committed", "key", common.BytesToHash(key))
		return nil, nil, nil, ErrCommitted
	}
	value, pathHashes, rawNodesOnPath, newroot, didResolve, err := t.getLogged(t.root, keybytesToHex(key), 0)
	if value == nil {
		//log.Info("Getlogged, empty value", "k", common.BytesToHash(key), "paths", len(pathHashes), "raw", len(rawNodesOnPath))
	}
	//log.Info("GetLogged", "p", pathHashes)
	if err == nil && didResolve {
		t.root = newroot
	}
	//log.Info("GetLogged return", "k", common.BytesToHash(key), "paths", len(pathHashes), "raw", len(rawNodesOnPath))
	return value, pathHashes, rawNodesOnPath, err
}

func asHex(buf []byte) string {
	return fmt.Sprintf("%x", buf)
}

func CleanNode(origNode node) node {
	switch n := origNode.(type) {
	case *shortNode:
		return &shortNode{Key: hexToCompact(n.Key), Val: n.Val}
	default:
		return n
	}
}
// for now return the hashes of all the nodes visited, then we can use the root string to confirm and check
func (t *Trie) getLogged(origNode node, key []byte, pos int) (value []byte, pathHashes []common.Hash, nodes [][]byte, newnode node, didResolve bool, err error) {
	switch n := (origNode).(type) {
	case nil:
		//log.Info("getLogged nil")
		pathHashes = []common.Hash{}
		nodes = [][]byte{}
		return nil, pathHashes, nodes, nil, false, nil
	case valueNode:
		//log.Warn("Value node", "n", n)
		trimmed := common.TrimLeftZeroes(n[:])
		//pathHashes = []common.Hash{HashNode(n)}
		h := newHasher(false)
		defer func() {
			returnHasherToPool(h)
			//t.unhashed = 0
		}()
		hash := h.hashData(trimmed[:])
		pathHashes = []common.Hash{common.BytesToHash(hash)}

		// can we find state accounts?
		// acc := new(types.StateAccount)
		// err := rlp.DecodeBytes(n, acc)
		// if err == nil {
		// 	log.Info("This valueNode is an account:", "acc", acc, "v", n)
		// }
		nodes = [][]byte{trimmed}
		return n, pathHashes, nodes, n, false, nil
	case *shortNode:
		//log.Info("getLogged shortNode", "n", n)
		// new short node 
		newsn := &shortNode{Key: hexToCompact(n.Key), Val: n.Val}
		//newsn := &shortNode{Key: n.Key, Val: n.Val}
		newrawn, err := rlp.EncodeToBytes(newsn)
		//log.Info("Both hashes", "n", HashNode(n), "newn", HashNode(newsn))
		//uncleanrawn, err := rlp.EncodeToBytes( &shortNode{Key: n.Key, Val: n.Val} )
		if err != nil {
			panic(err)
		}
		_, err = PublicDecodeNode(nil, newrawn)
		if err != nil {
			log.Error("failed to decode encoded shortNode", "rawn", fmt.Sprintf("%x", newrawn), "n", n)
		}
		//log.Info("testn", "n", testn)

		if len(key)-pos < len(n.Key) || !bytes.Equal(n.Key, key[pos:pos+len(n.Key)]) {
			// key not found in trie
			// still return something here, that you accessed this shortNode
			pathHashes = []common.Hash{HashNode( &shortNode{Key: n.Key, Val: n.Val} )}
			nodes = [][]byte{newrawn}
			return nil, pathHashes, nodes, n, false, nil
		}
		value, pathHashes, nodes, newnode, didResolve, err = t.getLogged(n.Val, key, pos+len(n.Key))

		//switch t := (n.Val).(type) {
		//case valueNode:
		//	acc := new(types.StateAccount)
		//	err := rlp.DecodeBytes(common.TrimLeftZeroes(t[:]), acc)
		//	if err == nil {
		//		// if this is a state account check that the root hash is the same
		//		log.Info("Hash of the root of storage account", "root", acc.Root)
		//	} else {
		//		log.Info("Not an account", "n", t)
		//	}
		//}

		//testraw := nodeToBytes(&shortNode{Key: hexToCompact(n.Key), Val: n.Val})
		//log.Info("testing", "n", n, "newsn", newsn, "testraw", asHex(testraw), "newrawn", asHex(newrawn))
		//if bytes.Compare(testraw, newrawn) == 0 {
		//	log.Info("testraw == newrawn")
		//} else {
		//	log.Info("testraw != newrawn")
		//}

		//testDecode, err := PublicDecodeNode(nil, testraw)
		//if err != nil {
		//	log.Info("nodeToBytes doesn't decode", "err", err)
		//} else {
		//	log.Info("nodeToBytes dos decode", "n", n, "testDecode", testDecode)
		//}

		nodes = append([][]byte{newrawn}, nodes...)
		pathHashes = append([]common.Hash{HashNode( &shortNode{Key: n.Key, Val: n.Val} )}, pathHashes...)
		//pathHashes = append([]common.Hash{HashNode(newsn)}, pathHashes...)
		// below a hashNode might become another node if resolved
		if err == nil && didResolve {
			n = n.copy()
			n.Val = newnode
		}
		//log.Info("new shortNode")
		return value, pathHashes, nodes, n, didResolve, err
	case *fullNode:
		//log.Info("Full Node string", "n", n.String())
		//log.Info("Full Node Hash", "h", HashNode(n))
		value, pathHashes, nodes, newnode, didResolve, err = t.getLogged(n.Children[key[pos]], key, pos+1)
		// convert all children to hashnodes
		var hChildren [17]node
		//hChildren = make([]node, 17)
		for i, c := range &n.Children {
			if c != nil {
				switch cn := c.(type) {
				case *shortNode:
					//hChildren[i] = HashNodeAsHashNode( &shortNode{Key: hexToCompact(cn.Key), Val: cn.Val} )
					hChildren[i] = HashNodeAsHashNode( &shortNode{Key: cn.Key, Val: cn.Val} )
				default:
					hChildren[i] = HashNodeAsHashNode(c)
				}
			} else {
				hChildren[i] = nil
			}
		}		
		newfn := &fullNode{hChildren, nodeFlag{dirty: false}}
		//log.Info("Full Node Hash", "h", HashNode(newfn), "n", newfn)
		rawnewfn, err := rlp.EncodeToBytes(newfn)
		if err != nil {
			panic(err)
		}
		//testraw := nodeToBytes(n)
		//if bytes.Compare(testraw, rawnewfn) == 0 {
		//	log.Info("testraw == newrawfn")
		//} else {
		//	log.Info("testraw != newrawfn")
		//}
		_, err = PublicDecodeNode(nil, rawnewfn)
		//if err != nil {
		//	log.Error("failed to decode encoded fullNode", "rawn", fmt.Sprintf("%x", rawnewfn), "n", n)
		//}
		//log.Info("testn", "n", testn)
		pathHashes = append([]common.Hash{HashNode(newfn)}, pathHashes...)
		nodes = append([][]byte{rawnewfn}, nodes...)
		if err == nil && didResolve {
			n = n.copy()
			n.Children[key[pos]] = newnode
		}
		//h, _ := t.hashRoot()
		//log.Info("roothash", "h", h)
		return value, pathHashes, nodes, n, didResolve, err
	case hashNode:
		// skip hashNodes because they're just references
		child, err := t.resolveAndTrack(n, key[:pos])
		if err != nil {
			log.Info("Couldn't resolve node", "n", common.BytesToHash(n[:]))
			return nil, nil, nil, n, true, err
		}
		value, pathHashes, nodes, newnode, _, err := t.getLogged(child, key, pos)
		return value, pathHashes, nodes, newnode, true, err
	default:
		panic(fmt.Sprintf("%T: invalid node: %v", origNode, origNode))
		return nil, nil, nil, nil, false, err
	}
}

func (t *Trie) UpdateLogged(key, value []byte) error {
	// Short circuit if the trie is already committed and not usable.
	if t.committed {
		return ErrCommitted
	}
	return t.updateLogged(key, value)
}

func (t *Trie) updateLogged(key, value []byte) error {
	t.unhashed++
	k := keybytesToHex(key)
	if len(value) != 0 {
		//_, n, _, err := t.insertLogged(t.root, nil, k, valueNode(value))
		_, n, err := t.insert(t.root, nil, k, valueNode(value))
		if err != nil {
			return err
		}
		t.root = n
	} else {
		_, n, err := t.delete(t.root, nil, k)
		if err != nil {
			return err
		}
		t.root = n
	}
	return nil
}

////func (t *Trie) insertLogged(n node, prefix, key []byte, value node) (bool, node, error) {
//func (t *Trie) insertLogged(n node, prefix, key []byte, value node) (bool, node, [][]common.Hash, error) {
//	if len(key) == 0 {
//		if v, ok := n.(valueNode); ok {
//			// NOTE: if the value doesn't change then return nothing
//			return !bytes.Equal(v, value.(valueNode)), value, make([][]common.Hash, 2), nil
//		}
//		// NOTE: if this node isn't a value, node then we return a new valueNode and nothing to return
//		return true, value, nil, nil
//	}
//	switch n := n.(type) {
//	case *shortNode:
//		matchlen := prefixLen(key, n.Key)
//		// If the whole key matches, keep this short node as is
//		// and only update the value.
//		if matchlen == len(n.Key) {
//			// NOTE: of there are changes that are made, then nothing should change now
//			// if n.Val was a fullNode then on of its children were updated so this node remains unchanged
//			dirty, nn, changes, err := t.insertLogged(n.Val, append(prefix, key[:matchlen]...), key[matchlen:], value)
//			if !dirty && len(changes) > 0 {
//				panic("dirty result shortNode and still some changes")
//			}
//			if !dirty || err != nil {
//				// NOTE: if the node doesn't change or there is an error then return nothing as well
//				return false, n, nil, err
//			}
//			// NOTE: dirty = True but we don't know whether a value node existed already or a new one was created
//			// it doesn't matter we don't log anything here since the shortNode remains the same
//			return true, &shortNode{n.Key, nn, t.newFlag()}, changes, nil
//		}
//		// Otherwise branch out at the index where they differ.
//		branch := &fullNode{flags: t.newFlag()}
//		var err error
//		_, branch.Children[n.Key[matchlen]], _, err = t.insertLogged(nil, append(prefix, n.Key[:matchlen+1]...), n.Key[matchlen+1:], n.Val)
//		if err != nil {
//			return false, nil, nil, err
//		}
//		_, branch.Children[key[matchlen]], _, err = t.insertLogged(nil, append(prefix, key[:matchlen+1]...), key[matchlen+1:], value)
//		if err != nil {
//			return false, nil, nil, err
//		}
//		// Replace this shortNode with the branch if it occurs at index 0.
//		if matchlen == 0 {
//			return true, branch, nil, nil
//		}
//		// New branch node is created as a child of the original short node.
//		// Track the newly inserted node in the tracer. The node identifier
//		// passed is the path from the root node.
//		t.tracer.onInsert(append(prefix, key[:matchlen]...))
//
//		// Replace it with a short node leading up to the branch.
//		return true, &shortNode{key[:matchlen], branch, t.newFlag()}, nil, nil
//
//	case *fullNode:
//		dirty, nn, _, err := t.insertLogged(n.Children[key[0]], append(prefix, key[0]), key[1:], value)
//		if !dirty || err != nil {
//			return false, n, nil, err
//		}
//		n = n.copy()
//		n.flags = t.newFlag()
//		n.Children[key[0]] = nn
//		return true, n, nil, nil
//
//	case nil:
//		// New short node is created and track it in the tracer. The node identifier
//		// passed is the path from the root node. Note the valueNode won't be tracked
//		// since it's always embedded in its parent.
//		t.tracer.onInsert(prefix)
//
//		return true, &shortNode{key, value, t.newFlag()}, nil, nil
//
//	case hashNode:
//		// We've hit a part of the trie that isn't loaded yet. Load
//		// the node and insert into it. This leaves all child nodes on
//		// the path to the value in the trie.
//		rn, err := t.resolveAndTrack(n, prefix)
//		if err != nil {
//			return false, nil, nil, err
//		}
//		dirty, nn, err := t.insert(rn, prefix, key, value)
//		if !dirty || err != nil {
//			return false, rn, nil, err
//		}
//		return true, nn, nil, nil
//
//	default:
//		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
//	}
//}

func (t *Trie) DeleteLogged(key []byte) error {
	// Short circuit if the trie is already committed and not usable.
	if t.committed {
		return ErrCommitted
	}
	t.unhashed++
	k := keybytesToHex(key)
	_, n, err := t.delete(t.root, nil, k)
	if err != nil {
		return err
	}
	t.root = n
	return nil
}

