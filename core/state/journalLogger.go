package state

import (   
    "encoding/json"
)

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


