// (c) 2019-2020, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package precompile

import (
	"math/big"

	"github.com/ava-labs/subnet-evm/vmerrs"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
)

var (
	_ StatefulPrecompileConfig = &ContractXChainECRecoverConfig{}
	// Singleton StatefulPrecompiledContract for minting native assets by permissioned callers.
	ContractXChainECRecoverPrecompile StatefulPrecompiledContract = createXChainECRecoverPrecompile(ContractXchainECRecoverAddress)

	xChainECRecoverSignature     = CalculateFunctionSelector("xChainECRecover(string)") // address, amount
	xChainECRecoverReadSignature = CalculateFunctionSelector("getXChainECRecover(bytes32,uint8,bytes32,bytes32)")
)

// ContractXChainECRecoverConfig wraps [AllowListConfig] and uses it to implement the StatefulPrecompileConfig
// interface while adding in the contract deployer specific precompile address.
type ContractXChainECRecoverConfig struct {
	BlockTimestamp *big.Int `json:"blockTimestamp"`
}

// Address returns the address of the native minter contract.
func (c *ContractXChainECRecoverConfig) Address() common.Address {
	return ContractXchainECRecoverAddress
}

// Contract returns the singleton stateful precompiled contract to be used for the native minter.
func (c *ContractXChainECRecoverConfig) Contract() StatefulPrecompiledContract {
	return ContractXChainECRecoverPrecompile
}

// Configure configures [state] with the desired admins based on [c].
func (c *ContractXChainECRecoverConfig) Configure(state StateDB) {

}

func (c *ContractXChainECRecoverConfig) Timestamp() *big.Int { return c.BlockTimestamp }

// createXChainECRecover checks if the caller is permissioned for minting operation.
// The execution function parses the [input] into native coin amount and receiver address.
func createXChainECRecover(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	log.Info("Reached 1 1")
	if remainingGas, err = deductGas(suppliedGas, MintGasCost); err != nil {
		return nil, 0, err
	}

	if readOnly {
		return nil, remainingGas, vmerrs.ErrWriteProtection
	}

	log.Info("Reached 1 2")
	log.Info(string(input[:]))

	// hm := "dc36a737379e605d3693aaf1a1b2d0284f50685b0bd007d9322487c980026548"
	// r := "a13aebac14028b7ccd8b387ac26e768672ccabcbfe98d48d4f4e1cb6c44d0b8f"
	// s := "3cc002d4735c604c841af644d3e8ae3829ce9a74b6a722d2f1595fb05ce9e1d4"
	// v := strconv.Itoa(1)
	// i2 := hm + v + r + s
	// log.Info(i2)
	// const ecRecoverInputLength = 128
	// o2, err := hex.DecodeString(i2)
	// in := common.RightPadBytes(o2, ecRecoverInputLength)
	// log.Info(hex.EncodeToString(in))
	// var test string
	// test = "abcdefghijklmnopqrstuvwxyzabcdef"
	input2 := append(input[:], input[:]...)
	log.Info("2nd input")
	log.Info(string(input2[:]))
	return input2[:], remainingGas, nil
}

func allZero(b []byte) bool {
	for _, byte := range b {
		if byte != 0 {
			return false
		}
	}
	return true
}

// createReadAllowList returns an execution function that reads the allow list for the given [precompileAddr].
// The execution function parses the input into a single address and returns the 32 byte hash that specifies the
// designated role of that address
func getXChainECRecover(precompileAddr common.Address) RunStatefulPrecompileFunc {
	return func(evm PrecompileAccessibleState, callerAddr common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) (ret []byte, remainingGas uint64, err error) {
		if remainingGas, err = deductGas(suppliedGas, ReadAllowListGasCost); err != nil {
			return nil, 0, err
		}
		// const ecRecoverInputLength = 128

		// input = common.RightPadBytes(input, ecRecoverInputLength)

		// // "input" is (hash, v, r, s), each 32 bytes
		// // but for ecrecover we want (r, s, v)

		// r := new(big.Int).SetBytes(input[64:96])
		// s := new(big.Int).SetBytes(input[96:128])
		// v := input[63]

		// // tighter sig s values input homestead only apply to tx sigs
		// if !allZero(input[32:63]) || !crypto.ValidateSignatureValues(v, r, s, false) {
		// 	return nil, remainingGas, nil
		// }

		// We must make sure not to modify the 'input', so placing the 'v' along with
		// the signature needs to be done on a new allocation

		// sig := make([]byte, 65)
		// copy(sig, input[64:128])
		// sig[64] = v

		// v needs to be at the end for libsecp256k1
		// pubk, err := crypto.SigToPub(input[:32], sig)
		// publicKey := crypto.CompressPubkey(pubk)

		// make sure the public key is a valid one
		// if err != nil {
		// 	return nil, remainingGas, nil
		// }

		// sha := sha256.Sum256(publicKey)
		// ripemd := ripemd160.New()
		// ripemd.Write(sha[:])
		// ripe := ripemd.Sum(nil)

		// conv, err := bech32.ConvertBits(ripe, 8, 5, true)
		// if err != nil {
		// 	log.Info("Error:", err)
		// }
		// encoded, err := bech32.Encode("fuji", conv)
		// xchain := "X-" + encoded
		// log.Info(xchain)

		// if err != nil {
		// 	log.Info("Error:", err)
		// }

		// out := []byte("abcdefghijklmnopqrstuvwxyzabcdef")
		// out := []byte(string(xchain[:]))
		// log.Info("Out")
		// log.Info(string(out))
		// out := []byte("X-fuji1vz07fz48qwrd6ulyxwr5sl4mnnzy5tz478uh8s")
		// o2 := hex.EncodeToString(input[64:96])
		// log.Info(o2)
		return input, remainingGas, nil
	}
}

// createXChainECRecoverPrecompile returns a StatefulPrecompiledContract with R/W control of an allow list at [precompileAddr] and a native coin minter.
func createXChainECRecoverPrecompile(precompileAddr common.Address) StatefulPrecompiledContract {
	log.Info("Reached 1")
	xChainECRecover := newStatefulPrecompileFunction(xChainECRecoverSignature, createXChainECRecover)
	_getXChainECRecover := newStatefulPrecompileFunction(xChainECRecoverReadSignature, getXChainECRecover(precompileAddr))

	// Construct the contract with no fallback function.
	contract := newStatefulPrecompileWithFunctionSelectors(nil, []*statefulPrecompileFunction{xChainECRecover, _getXChainECRecover})
	return contract
}
