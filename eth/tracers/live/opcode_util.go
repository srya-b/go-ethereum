package live

import (
	"github.com/ethereum/go-ethereum/core/vm"
)

func IsStorageRead(opcode vm.OpCode) bool {
	return opcode == vm.SLOAD
}

func IsStorageWrite(opcode vm.OpCode) bool {
	return opcode == vm.SSTORE
}

func IsBalance(opcode vm.OpCode) bool {
	return opcode == vm.BALANCE
}

