// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package ECDSAAccount

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// PackedUserOperation is an auto generated low-level Go binding around an user-defined struct.
type PackedUserOperation struct {
	Sender             common.Address
	Nonce              *big.Int
	InitCode           []byte
	CallData           []byte
	AccountGasLimits   [32]byte
	PreVerificationGas *big.Int
	GasFees            [32]byte
	PaymasterAndData   []byte
	Signature          []byte
}

// ECDSAAccountMetaData contains all meta data concerning the ECDSAAccount contract.
var ECDSAAccountMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[{\"name\":\"_newEntryPoint\",\"type\":\"address\",\"internalType\":\"contractIEntryPoint\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"receive\",\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"UPGRADE_INTERFACE_VERSION\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"addDeposit\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"entryPoint\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"contractIEntryPoint\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"entryPointAddress\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"contractIEntryPoint\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"execute\",\"inputs\":[{\"name\":\"dest\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"func\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"executeBatch\",\"inputs\":[{\"name\":\"dest\",\"type\":\"address[]\",\"internalType\":\"address[]\"},{\"name\":\"func\",\"type\":\"bytes[]\",\"internalType\":\"bytes[]\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"executeBatch\",\"inputs\":[{\"name\":\"dest\",\"type\":\"address[]\",\"internalType\":\"address[]\"},{\"name\":\"value\",\"type\":\"uint256[]\",\"internalType\":\"uint256[]\"},{\"name\":\"func\",\"type\":\"bytes[]\",\"internalType\":\"bytes[]\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"getDeposit\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getNonce\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"initialize\",\"inputs\":[{\"name\":\"_newOwner\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"isValidSignature\",\"inputs\":[{\"name\":\"hash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"signature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"onERC1155BatchReceived\",\"inputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"\",\"type\":\"uint256[]\",\"internalType\":\"uint256[]\"},{\"name\":\"\",\"type\":\"uint256[]\",\"internalType\":\"uint256[]\"},{\"name\":\"\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"onERC1155Received\",\"inputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"onERC721Received\",\"inputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"owner\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"pause\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"paused\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"proxiableUUID\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"renounceOwnership\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"supportsInterface\",\"inputs\":[{\"name\":\"interfaceId\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"tokensReceived\",\"inputs\":[{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"from\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"to\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"userData\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"operatorData\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"transferOwnership\",\"inputs\":[{\"name\":\"newOwner\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"unpause\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"upgradeToAndCall\",\"inputs\":[{\"name\":\"newImplementation\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"validateUserOp\",\"inputs\":[{\"name\":\"userOp\",\"type\":\"tuple\",\"internalType\":\"structPackedUserOperation\",\"components\":[{\"name\":\"sender\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"nonce\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"initCode\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"callData\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"accountGasLimits\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"preVerificationGas\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"gasFees\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"paymasterAndData\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"signature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]},{\"name\":\"userOpHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"missingAccountFunds\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"validationData\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"withdrawDepositTo\",\"inputs\":[{\"name\":\"withdrawAddress\",\"type\":\"address\",\"internalType\":\"addresspayable\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"event\",\"name\":\"AccountReceivedNativeToken\",\"inputs\":[{\"name\":\"sender\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"Initialized\",\"inputs\":[{\"name\":\"version\",\"type\":\"uint64\",\"indexed\":false,\"internalType\":\"uint64\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"OwnershipTransferred\",\"inputs\":[{\"name\":\"previousOwner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"newOwner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"Paused\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"indexed\":false,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"Unpaused\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"indexed\":false,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"Upgraded\",\"inputs\":[{\"name\":\"implementation\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"error\",\"name\":\"AddressEmptyCode\",\"inputs\":[{\"name\":\"target\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"ERC1967InvalidImplementation\",\"inputs\":[{\"name\":\"implementation\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"ERC1967NonPayable\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"EnforcedPause\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"ExpectedPause\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"FailedInnerCall\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"InvalidInitialization\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"NotInitializing\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"OwnableInvalidOwner\",\"inputs\":[{\"name\":\"owner\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"OwnableUnauthorizedAccount\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"UUPSUnauthorizedCallContext\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"UUPSUnsupportedProxiableUUID\",\"inputs\":[{\"name\":\"slot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]}]",
	Bin: "0x60c034620000c257601f62001a2738819003918201601f19168301916001600160401b03831184841017620000c757808492602094604052833981010312620000c257516001600160a01b0381168103620000c25760805262000061620000dd565b3060a0526200006f620000dd565b6040516118aa90816200017d82396080518181816102f5015281816105a2015281816107b70152818161086101528181610d8801528181610f51015261139c015260a0518181816109070152610a400152f35b600080fd5b634e487b7160e01b600052604160045260246000fd5b7ff0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00805460ff8160401c166200016a576001600160401b036002600160401b0319828216016200012b57505050565b6001600160401b031990911681179091556040519081527fc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d290602090a1565b60405163f92ee8a960e01b8152600490fdfe60806040526004361015610023575b361561001957600080fd5b61002161124b565b005b60003560e01c806223de29146101bd57806301ffc9a7146101b857806306dc245c14610168578063150b7a02146101b35780631626ba7e146101ae57806318dfb3c7146101a957806319822f7c146101a45780633f4ba83a1461019f57806347e1da2a1461019a5780634a58db19146101955780634d44560d146101905780634f1ef2861461018b57806352d1902d146101865780635c975abb14610181578063715018a61461017c5780638456cb59146101775780638da5cb5b14610172578063ad3cb1cc1461016d578063b0d691fe14610168578063b61d27f614610163578063bc197c811461015e578063c399ec8814610159578063c4d66de814610154578063d087d2881461014f578063f23a6e611461014a5763f2fde38b0361000e57611016565b610fbc565b610f1e565b610de9565b610d5c565b610ccd565b610c70565b6102df565b610c18565b610ba2565b610b33565b610ac8565b610a98565b610a2d565b6108c5565b610828565b6107a0565b6106ca565b61065e565b61056c565b6104bd565b61043d565b610324565b610271565b610205565b6001600160a01b038116036101d357565b600080fd5b9181601f840112156101d3578235916001600160401b0383116101d357602083818601950101116101d357565b346101d35760c03660031901126101d3576102216004356101c2565b61022c6024356101c2565b6102376044356101c2565b6001600160401b036084358181116101d3576102579036906004016101d8565b505060a4359081116101d3576100219036906004016101d8565b346101d35760203660031901126101d35760043563ffffffff60e01b81168091036101d357602090630a85bd0160e11b81149081156102ce575b81156102bd575b506040519015158152f35b6301ffc9a760e01b149050386102b2565b630271189760e51b811491506102ab565b346101d35760003660031901126101d3576040517f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03168152602090f35b346101d35760803660031901126101d3576103406004356101c2565b61034b6024356101c2565b6064356001600160401b0381116101d35761036a9036906004016101d8565b5050604051630a85bd0160e11b8152602090f35b634e487b7160e01b600052604160045260246000fd5b6001600160401b0381116103a757604052565b61037e565b90601f801991011681019081106001600160401b038211176103a757604052565b6001600160401b0381116103a757601f01601f191660200190565b9291926103f4826103cd565b9161040260405193846103ac565b8294818452818301116101d3578281602093846000960137010152565b9080601f830112156101d35781602061043a933591016103e8565b90565b346101d35760403660031901126101d3576024356001600160401b0381116101d35761047a610472602092369060040161041f565b600435611043565b6040516001600160e01b03199091168152f35b9181601f840112156101d3578235916001600160401b0383116101d3576020808501948460051b0101116101d357565b346101d35760403660031901126101d3576001600160401b036004358181116101d3576104ee90369060040161048d565b916024359081116101d35761050790369060040161048d565b9190610511611367565b610519611392565b6105248385146110b5565b60005b84811061053057005b80610566610541600193888761110d565b3561054b816101c2565b610560610559848988611154565b36916103e8565b9061142d565b01610527565b346101d3576003196060368201126101d357600435906001600160401b0382116101d3576101209082360301126101d3576044357f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03163303610619576105e36105fb9260243590600401611497565b90806105ff575b506040519081529081906020820190565b0390f35b600080808093338219f15061061261150f565b50386105ea565b60405162461bcd60e51b815260206004820152601c60248201527f6163636f756e743a206e6f742066726f6d20456e747279506f696e74000000006044820152606490fd5b346101d35760003660031901126101d35761067761153f565b61067f6115b6565b6106876115b6565b60008051602061183583398151915260ff1981541690557f5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa6020604051338152a1005b346101d35760603660031901126101d3576001600160401b036004358181116101d3576106fb90369060040161048d565b6024358381116101d35761071390369060040161048d565b936044359081116101d35761072c90369060040161048d565b92610735611367565b61073d611392565b6107488482146110b5565b6107538682146110b5565b60005b81811061075f57005b8061079a610770600193858a61110d565b3561077a816101c2565b610785838b8961110d565b35610794610559858b8a611154565b91611464565b01610756565b600080600319360112610825576107b5611367565b7f00000000000000000000000000000000000000000000000000000000000000006001600160a01b031681813b156108255760405163b760faf960e01b8152306004820152918290602490829034905af1801561082057610814575080f35b61081d90610394565b80f35b61116f565b80fd5b346101d3576000604036600319011261082557600435610847816101c2565b61084f61153f565b610857611367565b6001600160a01b037f0000000000000000000000000000000000000000000000000000000000000000811691839190833b156108c15760449083604051958694859363040b850f60e31b855216600484015260243560248401525af1801561082057610814575080f35b8280fd5b60403660031901126101d35760048035906108df826101c2565b6024356001600160401b0381116101d3576108fd903690830161041f565b6001600160a01b037f00000000000000000000000000000000000000000000000000000000000000008116308114908115610a11575b50610a0057906020839261094561153f565b6040516352d1902d60e01b8152938491829088165afa600092816109cf575b50610992575050604051634c9c8ce360e01b81526001600160a01b0390921690820190815281906020010390fd5b838360008051602061181583398151915284036109b357610021838361161e565b604051632a87526960e21b815290810184815281906020010390fd5b6109f291935060203d6020116109f9575b6109ea81836103ac565b81019061117b565b9138610964565b503d6109e0565b60405163703e46dd60e11b81528390fd5b9050816000805160206118158339815191525416141538610933565b346101d35760003660031901126101d3577f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03163003610a865760206040516000805160206118158339815191528152f35b60405163703e46dd60e11b8152600490fd5b346101d35760003660031901126101d357602060ff60008051602061183583398151915254166040519015158152f35b346101d35760008060031936011261082557610ae261153f565b6000805160206117f583398151915280546001600160a01b0319811690915581906001600160a01b03167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e08280a380f35b346101d35760003660031901126101d357610b4c61153f565b610b54611367565b610b5c611367565b600080516020611835833981519152600160ff198254161790557f62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a2586020604051338152a1005b346101d35760003660031901126101d3576000805160206117f5833981519152546040516001600160a01b039091168152602090f35b919082519283825260005b848110610c04575050826000602080949584010152601f8019910116010190565b602081830181015184830182015201610be3565b346101d35760003660031901126101d35760405160408101908082106001600160401b038311176103a7576105fb9160405260058152640352e302e360dc1b6020820152604051918291602083526020830190610bd8565b346101d35760603660031901126101d357600435610c8d816101c2565b604435906001600160401b0382116101d357610cc3610cb36100219336906004016101d8565b610cbb611367565b610559611392565b9060243590611464565b346101d35760a03660031901126101d357610ce96004356101c2565b610cf46024356101c2565b6001600160401b036044358181116101d357610d1490369060040161048d565b50506064358181116101d357610d2e90369060040161048d565b50506084359081116101d357610d489036906004016101d8565b505060405163bc197c8160e01b8152602090f35b346101d35760003660031901126101d3576040516370a0823160e01b81523060048201526020816024817f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03165afa801561082057602091600091610dcc575b50604051908152f35b610de39150823d84116109f9576109ea81836103ac565b38610dc3565b346101d35760203660031901126101d357600435610e06816101c2565b60008051602061185583398151915254906001600160401b0360ff8360401c1615921680159081610f16575b6001149081610f0c575b159081610f03575b50610ef157600080516020611855833981519152805467ffffffffffffffff19166001179055610e789082610ec75761118a565b610e7e57005b600080516020611855833981519152805460ff60401b19169055604051600181527fc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d290602090a1005b600080516020611855833981519152805460ff60401b19166801000000000000000017905561118a565b60405163f92ee8a960e01b8152600490fd5b90501538610e44565b303b159150610e3c565b839150610e32565b346101d35760003660031901126101d357604051631aab3f0d60e11b8152306004820152600060248201526020816044817f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03165afa8015610820576105fb91600091610f9d57506040519081529081906020820190565b610fb6915060203d6020116109f9576109ea81836103ac565b386105ea565b346101d35760a03660031901126101d357610fd86004356101c2565b610fe36024356101c2565b6084356001600160401b0381116101d3576110029036906004016101d8565b505060405163f23a6e6160e01b8152602090f35b346101d35760203660031901126101d357610021600435611036816101c2565b61103e61153f565b6111d7565b906110999161109360018060a01b036000805160206117f58339815191525416917f19457468657265756d205369676e6564204d6573736167653a0a333200000000600052601c52603c60002090565b90611279565b156110a957630b135d3f60e11b90565b6001600160e01b031990565b156110bc57565b60405162461bcd60e51b815260206004820152601360248201527277726f6e67206172726179206c656e6774687360681b6044820152606490fd5b634e487b7160e01b600052603260045260246000fd5b919081101561111d5760051b0190565b6110f7565b903590601e19813603018212156101d357018035906001600160401b0382116101d3576020019181360383136101d357565b9082101561111d5761116b9160051b810190611122565b9091565b6040513d6000823e3d90fd5b908160209103126101d3575190565b6111a6906111966116c5565b61119e6116c5565b61103e6116c5565b6111ae6116c5565b6111b66116c5565b600080516020611835833981519152805460ff191690556111d56116c5565b565b6001600160a01b03908116908115611232576000805160206117f583398151915280546001600160a01b031981168417909155167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0600080a3565b604051631e4fbdf760e01b815260006004820152602490fd5b6040513481527f6063d17f97b8837d6ec87876288b0dcba611bf6d68465a6e592be6f9d9ba4dc360203392a2565b61128383836115e2565b5060048195929510156113515715938461133b575b5083156112a6575b50505090565b60009293509082916040516112ed816112df6020820194630b135d3f60e11b998a87526024840152604060448401526064830190610bd8565b03601f1981018352826103ac565b51915afa906112fa61150f565b8261132d575b82611310575b50503880806112a0565b6113259192506020808251830101910161117b565b143880611306565b915060208251101591611300565b6001600160a01b03838116911614935038611298565b634e487b7160e01b600052602160045260246000fd5b60ff600080516020611835833981519152541661138057565b60405163d93c066560e01b8152600490fd5b60018060a01b03807f0000000000000000000000000000000000000000000000000000000000000000163314908115611412575b50156113ce57565b606460405162461bcd60e51b815260206004820152602060248201527f6163636f756e743a206e6f7420456e747279506f696e74206f72204f776e65726044820152fd5b90506000805160206117f583398151915254163314386113c6565b600091829182602083519301915af13d906040519060208383010160405282825260208201926000843e15611460575050565b5190fd5b916000928392602083519301915af13d906040519060208383010160405282825260208201926000843e15611460575050565b6114cd611500927f19457468657265756d205369676e6564204d6573736167653a0a333200000000600052601c52603c60002090565b6000805160206117f5833981519152546001600160a01b0316916114fa9061055990610100810190611122565b91611279565b1561150a57600090565b600190565b3d1561153a573d90611520826103cd565b9161152e60405193846103ac565b82523d6000602084013e565b606090565b6000805160206117f5833981519152546001600160a01b0316331480156115ad575b1561156857565b60405162461bcd60e51b815260206004820152601760248201527f43616c6c6572206973206e6f7420746865206f776e65720000000000000000006044820152606490fd5b50303314611561565b60ff6000805160206118358339815191525416156115d057565b604051638dfc202b60e01b8152600490fd5b81519190604183036116135761160c92506020820151906060604084015193015160001a906116f4565b9192909190565b505060009160029190565b90813b156116a45760008051602061181583398151915280546001600160a01b0319166001600160a01b0384169081179091557fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b600080a28051156116895761168691611778565b50565b50503461169257565b60405163b398979f60e01b8152600490fd5b604051634c9c8ce360e01b81526001600160a01b0383166004820152602490fd5b60ff6000805160206118558339815191525460401c16156116e257565b604051631afcd79f60e31b8152600490fd5b91907f7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0841161176c57926020929160ff608095604051948552168484015260408301526060820152600092839182805260015afa156108205780516001600160a01b0381161561176357918190565b50809160019190565b50505060009160039190565b60008061043a93602081519101845af461179061150f565b91906117b857508051156117a657805190602001fd5b604051630a12f52160e11b8152600490fd5b815115806117eb575b6117c9575090565b604051639996b31560e01b81526001600160a01b039091166004820152602490fd5b50803b156117c156fe9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbccd5ed15c6e187e77e9aee88184c21f4f2182ab5827cb3b7e07fbedcd63f03300f0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00a2646970667358221220448dc9503740dd7944f3b2174822176887490cfad277ab777610394c94adc0ff64736f6c63430008180033",
}

// ECDSAAccountABI is the input ABI used to generate the binding from.
// Deprecated: Use ECDSAAccountMetaData.ABI instead.
var ECDSAAccountABI = ECDSAAccountMetaData.ABI

// ECDSAAccountBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use ECDSAAccountMetaData.Bin instead.
var ECDSAAccountBin = ECDSAAccountMetaData.Bin

// DeployECDSAAccount deploys a new Ethereum contract, binding an instance of ECDSAAccount to it.
func DeployECDSAAccount(auth *bind.TransactOpts, backend bind.ContractBackend, _newEntryPoint common.Address) (common.Address, *types.Transaction, *ECDSAAccount, error) {
	parsed, err := ECDSAAccountMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(ECDSAAccountBin), backend, _newEntryPoint)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &ECDSAAccount{ECDSAAccountCaller: ECDSAAccountCaller{contract: contract}, ECDSAAccountTransactor: ECDSAAccountTransactor{contract: contract}, ECDSAAccountFilterer: ECDSAAccountFilterer{contract: contract}}, nil
}

// ECDSAAccount is an auto generated Go binding around an Ethereum contract.
type ECDSAAccount struct {
	ECDSAAccountCaller     // Read-only binding to the contract
	ECDSAAccountTransactor // Write-only binding to the contract
	ECDSAAccountFilterer   // Log filterer for contract events
}

// ECDSAAccountCaller is an auto generated read-only Go binding around an Ethereum contract.
type ECDSAAccountCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ECDSAAccountTransactor is an auto generated write-only Go binding around an Ethereum contract.
type ECDSAAccountTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ECDSAAccountFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type ECDSAAccountFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ECDSAAccountSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type ECDSAAccountSession struct {
	Contract     *ECDSAAccount     // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// ECDSAAccountCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type ECDSAAccountCallerSession struct {
	Contract *ECDSAAccountCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts       // Call options to use throughout this session
}

// ECDSAAccountTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type ECDSAAccountTransactorSession struct {
	Contract     *ECDSAAccountTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts       // Transaction auth options to use throughout this session
}

// ECDSAAccountRaw is an auto generated low-level Go binding around an Ethereum contract.
type ECDSAAccountRaw struct {
	Contract *ECDSAAccount // Generic contract binding to access the raw methods on
}

// ECDSAAccountCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type ECDSAAccountCallerRaw struct {
	Contract *ECDSAAccountCaller // Generic read-only contract binding to access the raw methods on
}

// ECDSAAccountTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type ECDSAAccountTransactorRaw struct {
	Contract *ECDSAAccountTransactor // Generic write-only contract binding to access the raw methods on
}

// NewECDSAAccount creates a new instance of ECDSAAccount, bound to a specific deployed contract.
func NewECDSAAccount(address common.Address, backend bind.ContractBackend) (*ECDSAAccount, error) {
	contract, err := bindECDSAAccount(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &ECDSAAccount{ECDSAAccountCaller: ECDSAAccountCaller{contract: contract}, ECDSAAccountTransactor: ECDSAAccountTransactor{contract: contract}, ECDSAAccountFilterer: ECDSAAccountFilterer{contract: contract}}, nil
}

// NewECDSAAccountCaller creates a new read-only instance of ECDSAAccount, bound to a specific deployed contract.
func NewECDSAAccountCaller(address common.Address, caller bind.ContractCaller) (*ECDSAAccountCaller, error) {
	contract, err := bindECDSAAccount(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &ECDSAAccountCaller{contract: contract}, nil
}

// NewECDSAAccountTransactor creates a new write-only instance of ECDSAAccount, bound to a specific deployed contract.
func NewECDSAAccountTransactor(address common.Address, transactor bind.ContractTransactor) (*ECDSAAccountTransactor, error) {
	contract, err := bindECDSAAccount(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &ECDSAAccountTransactor{contract: contract}, nil
}

// NewECDSAAccountFilterer creates a new log filterer instance of ECDSAAccount, bound to a specific deployed contract.
func NewECDSAAccountFilterer(address common.Address, filterer bind.ContractFilterer) (*ECDSAAccountFilterer, error) {
	contract, err := bindECDSAAccount(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &ECDSAAccountFilterer{contract: contract}, nil
}

// bindECDSAAccount binds a generic wrapper to an already deployed contract.
func bindECDSAAccount(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := ECDSAAccountMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ECDSAAccount *ECDSAAccountRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ECDSAAccount.Contract.ECDSAAccountCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ECDSAAccount *ECDSAAccountRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ECDSAAccount.Contract.ECDSAAccountTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ECDSAAccount *ECDSAAccountRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ECDSAAccount.Contract.ECDSAAccountTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ECDSAAccount *ECDSAAccountCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ECDSAAccount.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ECDSAAccount *ECDSAAccountTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ECDSAAccount.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ECDSAAccount *ECDSAAccountTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ECDSAAccount.Contract.contract.Transact(opts, method, params...)
}

// UPGRADEINTERFACEVERSION is a free data retrieval call binding the contract method 0xad3cb1cc.
//
// Solidity: function UPGRADE_INTERFACE_VERSION() view returns(string)
func (_ECDSAAccount *ECDSAAccountCaller) UPGRADEINTERFACEVERSION(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _ECDSAAccount.contract.Call(opts, &out, "UPGRADE_INTERFACE_VERSION")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// UPGRADEINTERFACEVERSION is a free data retrieval call binding the contract method 0xad3cb1cc.
//
// Solidity: function UPGRADE_INTERFACE_VERSION() view returns(string)
func (_ECDSAAccount *ECDSAAccountSession) UPGRADEINTERFACEVERSION() (string, error) {
	return _ECDSAAccount.Contract.UPGRADEINTERFACEVERSION(&_ECDSAAccount.CallOpts)
}

// UPGRADEINTERFACEVERSION is a free data retrieval call binding the contract method 0xad3cb1cc.
//
// Solidity: function UPGRADE_INTERFACE_VERSION() view returns(string)
func (_ECDSAAccount *ECDSAAccountCallerSession) UPGRADEINTERFACEVERSION() (string, error) {
	return _ECDSAAccount.Contract.UPGRADEINTERFACEVERSION(&_ECDSAAccount.CallOpts)
}

// EntryPoint is a free data retrieval call binding the contract method 0xb0d691fe.
//
// Solidity: function entryPoint() view returns(address)
func (_ECDSAAccount *ECDSAAccountCaller) EntryPoint(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _ECDSAAccount.contract.Call(opts, &out, "entryPoint")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// EntryPoint is a free data retrieval call binding the contract method 0xb0d691fe.
//
// Solidity: function entryPoint() view returns(address)
func (_ECDSAAccount *ECDSAAccountSession) EntryPoint() (common.Address, error) {
	return _ECDSAAccount.Contract.EntryPoint(&_ECDSAAccount.CallOpts)
}

// EntryPoint is a free data retrieval call binding the contract method 0xb0d691fe.
//
// Solidity: function entryPoint() view returns(address)
func (_ECDSAAccount *ECDSAAccountCallerSession) EntryPoint() (common.Address, error) {
	return _ECDSAAccount.Contract.EntryPoint(&_ECDSAAccount.CallOpts)
}

// EntryPointAddress is a free data retrieval call binding the contract method 0x06dc245c.
//
// Solidity: function entryPointAddress() view returns(address)
func (_ECDSAAccount *ECDSAAccountCaller) EntryPointAddress(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _ECDSAAccount.contract.Call(opts, &out, "entryPointAddress")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// EntryPointAddress is a free data retrieval call binding the contract method 0x06dc245c.
//
// Solidity: function entryPointAddress() view returns(address)
func (_ECDSAAccount *ECDSAAccountSession) EntryPointAddress() (common.Address, error) {
	return _ECDSAAccount.Contract.EntryPointAddress(&_ECDSAAccount.CallOpts)
}

// EntryPointAddress is a free data retrieval call binding the contract method 0x06dc245c.
//
// Solidity: function entryPointAddress() view returns(address)
func (_ECDSAAccount *ECDSAAccountCallerSession) EntryPointAddress() (common.Address, error) {
	return _ECDSAAccount.Contract.EntryPointAddress(&_ECDSAAccount.CallOpts)
}

// GetDeposit is a free data retrieval call binding the contract method 0xc399ec88.
//
// Solidity: function getDeposit() view returns(uint256)
func (_ECDSAAccount *ECDSAAccountCaller) GetDeposit(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _ECDSAAccount.contract.Call(opts, &out, "getDeposit")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetDeposit is a free data retrieval call binding the contract method 0xc399ec88.
//
// Solidity: function getDeposit() view returns(uint256)
func (_ECDSAAccount *ECDSAAccountSession) GetDeposit() (*big.Int, error) {
	return _ECDSAAccount.Contract.GetDeposit(&_ECDSAAccount.CallOpts)
}

// GetDeposit is a free data retrieval call binding the contract method 0xc399ec88.
//
// Solidity: function getDeposit() view returns(uint256)
func (_ECDSAAccount *ECDSAAccountCallerSession) GetDeposit() (*big.Int, error) {
	return _ECDSAAccount.Contract.GetDeposit(&_ECDSAAccount.CallOpts)
}

// GetNonce is a free data retrieval call binding the contract method 0xd087d288.
//
// Solidity: function getNonce() view returns(uint256)
func (_ECDSAAccount *ECDSAAccountCaller) GetNonce(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _ECDSAAccount.contract.Call(opts, &out, "getNonce")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetNonce is a free data retrieval call binding the contract method 0xd087d288.
//
// Solidity: function getNonce() view returns(uint256)
func (_ECDSAAccount *ECDSAAccountSession) GetNonce() (*big.Int, error) {
	return _ECDSAAccount.Contract.GetNonce(&_ECDSAAccount.CallOpts)
}

// GetNonce is a free data retrieval call binding the contract method 0xd087d288.
//
// Solidity: function getNonce() view returns(uint256)
func (_ECDSAAccount *ECDSAAccountCallerSession) GetNonce() (*big.Int, error) {
	return _ECDSAAccount.Contract.GetNonce(&_ECDSAAccount.CallOpts)
}

// IsValidSignature is a free data retrieval call binding the contract method 0x1626ba7e.
//
// Solidity: function isValidSignature(bytes32 hash, bytes signature) view returns(bytes4)
func (_ECDSAAccount *ECDSAAccountCaller) IsValidSignature(opts *bind.CallOpts, hash [32]byte, signature []byte) ([4]byte, error) {
	var out []interface{}
	err := _ECDSAAccount.contract.Call(opts, &out, "isValidSignature", hash, signature)

	if err != nil {
		return *new([4]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([4]byte)).(*[4]byte)

	return out0, err

}

// IsValidSignature is a free data retrieval call binding the contract method 0x1626ba7e.
//
// Solidity: function isValidSignature(bytes32 hash, bytes signature) view returns(bytes4)
func (_ECDSAAccount *ECDSAAccountSession) IsValidSignature(hash [32]byte, signature []byte) ([4]byte, error) {
	return _ECDSAAccount.Contract.IsValidSignature(&_ECDSAAccount.CallOpts, hash, signature)
}

// IsValidSignature is a free data retrieval call binding the contract method 0x1626ba7e.
//
// Solidity: function isValidSignature(bytes32 hash, bytes signature) view returns(bytes4)
func (_ECDSAAccount *ECDSAAccountCallerSession) IsValidSignature(hash [32]byte, signature []byte) ([4]byte, error) {
	return _ECDSAAccount.Contract.IsValidSignature(&_ECDSAAccount.CallOpts, hash, signature)
}

// OnERC1155BatchReceived is a free data retrieval call binding the contract method 0xbc197c81.
//
// Solidity: function onERC1155BatchReceived(address , address , uint256[] , uint256[] , bytes ) pure returns(bytes4)
func (_ECDSAAccount *ECDSAAccountCaller) OnERC1155BatchReceived(opts *bind.CallOpts, arg0 common.Address, arg1 common.Address, arg2 []*big.Int, arg3 []*big.Int, arg4 []byte) ([4]byte, error) {
	var out []interface{}
	err := _ECDSAAccount.contract.Call(opts, &out, "onERC1155BatchReceived", arg0, arg1, arg2, arg3, arg4)

	if err != nil {
		return *new([4]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([4]byte)).(*[4]byte)

	return out0, err

}

// OnERC1155BatchReceived is a free data retrieval call binding the contract method 0xbc197c81.
//
// Solidity: function onERC1155BatchReceived(address , address , uint256[] , uint256[] , bytes ) pure returns(bytes4)
func (_ECDSAAccount *ECDSAAccountSession) OnERC1155BatchReceived(arg0 common.Address, arg1 common.Address, arg2 []*big.Int, arg3 []*big.Int, arg4 []byte) ([4]byte, error) {
	return _ECDSAAccount.Contract.OnERC1155BatchReceived(&_ECDSAAccount.CallOpts, arg0, arg1, arg2, arg3, arg4)
}

// OnERC1155BatchReceived is a free data retrieval call binding the contract method 0xbc197c81.
//
// Solidity: function onERC1155BatchReceived(address , address , uint256[] , uint256[] , bytes ) pure returns(bytes4)
func (_ECDSAAccount *ECDSAAccountCallerSession) OnERC1155BatchReceived(arg0 common.Address, arg1 common.Address, arg2 []*big.Int, arg3 []*big.Int, arg4 []byte) ([4]byte, error) {
	return _ECDSAAccount.Contract.OnERC1155BatchReceived(&_ECDSAAccount.CallOpts, arg0, arg1, arg2, arg3, arg4)
}

// OnERC1155Received is a free data retrieval call binding the contract method 0xf23a6e61.
//
// Solidity: function onERC1155Received(address , address , uint256 , uint256 , bytes ) pure returns(bytes4)
func (_ECDSAAccount *ECDSAAccountCaller) OnERC1155Received(opts *bind.CallOpts, arg0 common.Address, arg1 common.Address, arg2 *big.Int, arg3 *big.Int, arg4 []byte) ([4]byte, error) {
	var out []interface{}
	err := _ECDSAAccount.contract.Call(opts, &out, "onERC1155Received", arg0, arg1, arg2, arg3, arg4)

	if err != nil {
		return *new([4]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([4]byte)).(*[4]byte)

	return out0, err

}

// OnERC1155Received is a free data retrieval call binding the contract method 0xf23a6e61.
//
// Solidity: function onERC1155Received(address , address , uint256 , uint256 , bytes ) pure returns(bytes4)
func (_ECDSAAccount *ECDSAAccountSession) OnERC1155Received(arg0 common.Address, arg1 common.Address, arg2 *big.Int, arg3 *big.Int, arg4 []byte) ([4]byte, error) {
	return _ECDSAAccount.Contract.OnERC1155Received(&_ECDSAAccount.CallOpts, arg0, arg1, arg2, arg3, arg4)
}

// OnERC1155Received is a free data retrieval call binding the contract method 0xf23a6e61.
//
// Solidity: function onERC1155Received(address , address , uint256 , uint256 , bytes ) pure returns(bytes4)
func (_ECDSAAccount *ECDSAAccountCallerSession) OnERC1155Received(arg0 common.Address, arg1 common.Address, arg2 *big.Int, arg3 *big.Int, arg4 []byte) ([4]byte, error) {
	return _ECDSAAccount.Contract.OnERC1155Received(&_ECDSAAccount.CallOpts, arg0, arg1, arg2, arg3, arg4)
}

// OnERC721Received is a free data retrieval call binding the contract method 0x150b7a02.
//
// Solidity: function onERC721Received(address , address , uint256 , bytes ) pure returns(bytes4)
func (_ECDSAAccount *ECDSAAccountCaller) OnERC721Received(opts *bind.CallOpts, arg0 common.Address, arg1 common.Address, arg2 *big.Int, arg3 []byte) ([4]byte, error) {
	var out []interface{}
	err := _ECDSAAccount.contract.Call(opts, &out, "onERC721Received", arg0, arg1, arg2, arg3)

	if err != nil {
		return *new([4]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([4]byte)).(*[4]byte)

	return out0, err

}

// OnERC721Received is a free data retrieval call binding the contract method 0x150b7a02.
//
// Solidity: function onERC721Received(address , address , uint256 , bytes ) pure returns(bytes4)
func (_ECDSAAccount *ECDSAAccountSession) OnERC721Received(arg0 common.Address, arg1 common.Address, arg2 *big.Int, arg3 []byte) ([4]byte, error) {
	return _ECDSAAccount.Contract.OnERC721Received(&_ECDSAAccount.CallOpts, arg0, arg1, arg2, arg3)
}

// OnERC721Received is a free data retrieval call binding the contract method 0x150b7a02.
//
// Solidity: function onERC721Received(address , address , uint256 , bytes ) pure returns(bytes4)
func (_ECDSAAccount *ECDSAAccountCallerSession) OnERC721Received(arg0 common.Address, arg1 common.Address, arg2 *big.Int, arg3 []byte) ([4]byte, error) {
	return _ECDSAAccount.Contract.OnERC721Received(&_ECDSAAccount.CallOpts, arg0, arg1, arg2, arg3)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_ECDSAAccount *ECDSAAccountCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _ECDSAAccount.contract.Call(opts, &out, "owner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_ECDSAAccount *ECDSAAccountSession) Owner() (common.Address, error) {
	return _ECDSAAccount.Contract.Owner(&_ECDSAAccount.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_ECDSAAccount *ECDSAAccountCallerSession) Owner() (common.Address, error) {
	return _ECDSAAccount.Contract.Owner(&_ECDSAAccount.CallOpts)
}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_ECDSAAccount *ECDSAAccountCaller) Paused(opts *bind.CallOpts) (bool, error) {
	var out []interface{}
	err := _ECDSAAccount.contract.Call(opts, &out, "paused")

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_ECDSAAccount *ECDSAAccountSession) Paused() (bool, error) {
	return _ECDSAAccount.Contract.Paused(&_ECDSAAccount.CallOpts)
}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_ECDSAAccount *ECDSAAccountCallerSession) Paused() (bool, error) {
	return _ECDSAAccount.Contract.Paused(&_ECDSAAccount.CallOpts)
}

// ProxiableUUID is a free data retrieval call binding the contract method 0x52d1902d.
//
// Solidity: function proxiableUUID() view returns(bytes32)
func (_ECDSAAccount *ECDSAAccountCaller) ProxiableUUID(opts *bind.CallOpts) ([32]byte, error) {
	var out []interface{}
	err := _ECDSAAccount.contract.Call(opts, &out, "proxiableUUID")

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// ProxiableUUID is a free data retrieval call binding the contract method 0x52d1902d.
//
// Solidity: function proxiableUUID() view returns(bytes32)
func (_ECDSAAccount *ECDSAAccountSession) ProxiableUUID() ([32]byte, error) {
	return _ECDSAAccount.Contract.ProxiableUUID(&_ECDSAAccount.CallOpts)
}

// ProxiableUUID is a free data retrieval call binding the contract method 0x52d1902d.
//
// Solidity: function proxiableUUID() view returns(bytes32)
func (_ECDSAAccount *ECDSAAccountCallerSession) ProxiableUUID() ([32]byte, error) {
	return _ECDSAAccount.Contract.ProxiableUUID(&_ECDSAAccount.CallOpts)
}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_ECDSAAccount *ECDSAAccountCaller) SupportsInterface(opts *bind.CallOpts, interfaceId [4]byte) (bool, error) {
	var out []interface{}
	err := _ECDSAAccount.contract.Call(opts, &out, "supportsInterface", interfaceId)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_ECDSAAccount *ECDSAAccountSession) SupportsInterface(interfaceId [4]byte) (bool, error) {
	return _ECDSAAccount.Contract.SupportsInterface(&_ECDSAAccount.CallOpts, interfaceId)
}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_ECDSAAccount *ECDSAAccountCallerSession) SupportsInterface(interfaceId [4]byte) (bool, error) {
	return _ECDSAAccount.Contract.SupportsInterface(&_ECDSAAccount.CallOpts, interfaceId)
}

// TokensReceived is a free data retrieval call binding the contract method 0x0023de29.
//
// Solidity: function tokensReceived(address operator, address from, address to, uint256 amount, bytes userData, bytes operatorData) pure returns()
func (_ECDSAAccount *ECDSAAccountCaller) TokensReceived(opts *bind.CallOpts, operator common.Address, from common.Address, to common.Address, amount *big.Int, userData []byte, operatorData []byte) error {
	var out []interface{}
	err := _ECDSAAccount.contract.Call(opts, &out, "tokensReceived", operator, from, to, amount, userData, operatorData)

	if err != nil {
		return err
	}

	return err

}

// TokensReceived is a free data retrieval call binding the contract method 0x0023de29.
//
// Solidity: function tokensReceived(address operator, address from, address to, uint256 amount, bytes userData, bytes operatorData) pure returns()
func (_ECDSAAccount *ECDSAAccountSession) TokensReceived(operator common.Address, from common.Address, to common.Address, amount *big.Int, userData []byte, operatorData []byte) error {
	return _ECDSAAccount.Contract.TokensReceived(&_ECDSAAccount.CallOpts, operator, from, to, amount, userData, operatorData)
}

// TokensReceived is a free data retrieval call binding the contract method 0x0023de29.
//
// Solidity: function tokensReceived(address operator, address from, address to, uint256 amount, bytes userData, bytes operatorData) pure returns()
func (_ECDSAAccount *ECDSAAccountCallerSession) TokensReceived(operator common.Address, from common.Address, to common.Address, amount *big.Int, userData []byte, operatorData []byte) error {
	return _ECDSAAccount.Contract.TokensReceived(&_ECDSAAccount.CallOpts, operator, from, to, amount, userData, operatorData)
}

// AddDeposit is a paid mutator transaction binding the contract method 0x4a58db19.
//
// Solidity: function addDeposit() payable returns()
func (_ECDSAAccount *ECDSAAccountTransactor) AddDeposit(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ECDSAAccount.contract.Transact(opts, "addDeposit")
}

// AddDeposit is a paid mutator transaction binding the contract method 0x4a58db19.
//
// Solidity: function addDeposit() payable returns()
func (_ECDSAAccount *ECDSAAccountSession) AddDeposit() (*types.Transaction, error) {
	return _ECDSAAccount.Contract.AddDeposit(&_ECDSAAccount.TransactOpts)
}

// AddDeposit is a paid mutator transaction binding the contract method 0x4a58db19.
//
// Solidity: function addDeposit() payable returns()
func (_ECDSAAccount *ECDSAAccountTransactorSession) AddDeposit() (*types.Transaction, error) {
	return _ECDSAAccount.Contract.AddDeposit(&_ECDSAAccount.TransactOpts)
}

// Execute is a paid mutator transaction binding the contract method 0xb61d27f6.
//
// Solidity: function execute(address dest, uint256 value, bytes func) returns()
func (_ECDSAAccount *ECDSAAccountTransactor) Execute(opts *bind.TransactOpts, dest common.Address, value *big.Int, arg2 []byte) (*types.Transaction, error) {
	return _ECDSAAccount.contract.Transact(opts, "execute", dest, value, arg2)
}

// Execute is a paid mutator transaction binding the contract method 0xb61d27f6.
//
// Solidity: function execute(address dest, uint256 value, bytes func) returns()
func (_ECDSAAccount *ECDSAAccountSession) Execute(dest common.Address, value *big.Int, arg2 []byte) (*types.Transaction, error) {
	return _ECDSAAccount.Contract.Execute(&_ECDSAAccount.TransactOpts, dest, value, arg2)
}

// Execute is a paid mutator transaction binding the contract method 0xb61d27f6.
//
// Solidity: function execute(address dest, uint256 value, bytes func) returns()
func (_ECDSAAccount *ECDSAAccountTransactorSession) Execute(dest common.Address, value *big.Int, arg2 []byte) (*types.Transaction, error) {
	return _ECDSAAccount.Contract.Execute(&_ECDSAAccount.TransactOpts, dest, value, arg2)
}

// ExecuteBatch is a paid mutator transaction binding the contract method 0x18dfb3c7.
//
// Solidity: function executeBatch(address[] dest, bytes[] func) returns()
func (_ECDSAAccount *ECDSAAccountTransactor) ExecuteBatch(opts *bind.TransactOpts, dest []common.Address, arg1 [][]byte) (*types.Transaction, error) {
	return _ECDSAAccount.contract.Transact(opts, "executeBatch", dest, arg1)
}

// ExecuteBatch is a paid mutator transaction binding the contract method 0x18dfb3c7.
//
// Solidity: function executeBatch(address[] dest, bytes[] func) returns()
func (_ECDSAAccount *ECDSAAccountSession) ExecuteBatch(dest []common.Address, arg1 [][]byte) (*types.Transaction, error) {
	return _ECDSAAccount.Contract.ExecuteBatch(&_ECDSAAccount.TransactOpts, dest, arg1)
}

// ExecuteBatch is a paid mutator transaction binding the contract method 0x18dfb3c7.
//
// Solidity: function executeBatch(address[] dest, bytes[] func) returns()
func (_ECDSAAccount *ECDSAAccountTransactorSession) ExecuteBatch(dest []common.Address, arg1 [][]byte) (*types.Transaction, error) {
	return _ECDSAAccount.Contract.ExecuteBatch(&_ECDSAAccount.TransactOpts, dest, arg1)
}

// ExecuteBatch0 is a paid mutator transaction binding the contract method 0x47e1da2a.
//
// Solidity: function executeBatch(address[] dest, uint256[] value, bytes[] func) returns()
func (_ECDSAAccount *ECDSAAccountTransactor) ExecuteBatch0(opts *bind.TransactOpts, dest []common.Address, value []*big.Int, arg2 [][]byte) (*types.Transaction, error) {
	return _ECDSAAccount.contract.Transact(opts, "executeBatch0", dest, value, arg2)
}

// ExecuteBatch0 is a paid mutator transaction binding the contract method 0x47e1da2a.
//
// Solidity: function executeBatch(address[] dest, uint256[] value, bytes[] func) returns()
func (_ECDSAAccount *ECDSAAccountSession) ExecuteBatch0(dest []common.Address, value []*big.Int, arg2 [][]byte) (*types.Transaction, error) {
	return _ECDSAAccount.Contract.ExecuteBatch0(&_ECDSAAccount.TransactOpts, dest, value, arg2)
}

// ExecuteBatch0 is a paid mutator transaction binding the contract method 0x47e1da2a.
//
// Solidity: function executeBatch(address[] dest, uint256[] value, bytes[] func) returns()
func (_ECDSAAccount *ECDSAAccountTransactorSession) ExecuteBatch0(dest []common.Address, value []*big.Int, arg2 [][]byte) (*types.Transaction, error) {
	return _ECDSAAccount.Contract.ExecuteBatch0(&_ECDSAAccount.TransactOpts, dest, value, arg2)
}

// Initialize is a paid mutator transaction binding the contract method 0xc4d66de8.
//
// Solidity: function initialize(address _newOwner) returns()
func (_ECDSAAccount *ECDSAAccountTransactor) Initialize(opts *bind.TransactOpts, _newOwner common.Address) (*types.Transaction, error) {
	return _ECDSAAccount.contract.Transact(opts, "initialize", _newOwner)
}

// Initialize is a paid mutator transaction binding the contract method 0xc4d66de8.
//
// Solidity: function initialize(address _newOwner) returns()
func (_ECDSAAccount *ECDSAAccountSession) Initialize(_newOwner common.Address) (*types.Transaction, error) {
	return _ECDSAAccount.Contract.Initialize(&_ECDSAAccount.TransactOpts, _newOwner)
}

// Initialize is a paid mutator transaction binding the contract method 0xc4d66de8.
//
// Solidity: function initialize(address _newOwner) returns()
func (_ECDSAAccount *ECDSAAccountTransactorSession) Initialize(_newOwner common.Address) (*types.Transaction, error) {
	return _ECDSAAccount.Contract.Initialize(&_ECDSAAccount.TransactOpts, _newOwner)
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns()
func (_ECDSAAccount *ECDSAAccountTransactor) Pause(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ECDSAAccount.contract.Transact(opts, "pause")
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns()
func (_ECDSAAccount *ECDSAAccountSession) Pause() (*types.Transaction, error) {
	return _ECDSAAccount.Contract.Pause(&_ECDSAAccount.TransactOpts)
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns()
func (_ECDSAAccount *ECDSAAccountTransactorSession) Pause() (*types.Transaction, error) {
	return _ECDSAAccount.Contract.Pause(&_ECDSAAccount.TransactOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_ECDSAAccount *ECDSAAccountTransactor) RenounceOwnership(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ECDSAAccount.contract.Transact(opts, "renounceOwnership")
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_ECDSAAccount *ECDSAAccountSession) RenounceOwnership() (*types.Transaction, error) {
	return _ECDSAAccount.Contract.RenounceOwnership(&_ECDSAAccount.TransactOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_ECDSAAccount *ECDSAAccountTransactorSession) RenounceOwnership() (*types.Transaction, error) {
	return _ECDSAAccount.Contract.RenounceOwnership(&_ECDSAAccount.TransactOpts)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_ECDSAAccount *ECDSAAccountTransactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _ECDSAAccount.contract.Transact(opts, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_ECDSAAccount *ECDSAAccountSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _ECDSAAccount.Contract.TransferOwnership(&_ECDSAAccount.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_ECDSAAccount *ECDSAAccountTransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _ECDSAAccount.Contract.TransferOwnership(&_ECDSAAccount.TransactOpts, newOwner)
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns()
func (_ECDSAAccount *ECDSAAccountTransactor) Unpause(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ECDSAAccount.contract.Transact(opts, "unpause")
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns()
func (_ECDSAAccount *ECDSAAccountSession) Unpause() (*types.Transaction, error) {
	return _ECDSAAccount.Contract.Unpause(&_ECDSAAccount.TransactOpts)
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns()
func (_ECDSAAccount *ECDSAAccountTransactorSession) Unpause() (*types.Transaction, error) {
	return _ECDSAAccount.Contract.Unpause(&_ECDSAAccount.TransactOpts)
}

// UpgradeToAndCall is a paid mutator transaction binding the contract method 0x4f1ef286.
//
// Solidity: function upgradeToAndCall(address newImplementation, bytes data) payable returns()
func (_ECDSAAccount *ECDSAAccountTransactor) UpgradeToAndCall(opts *bind.TransactOpts, newImplementation common.Address, data []byte) (*types.Transaction, error) {
	return _ECDSAAccount.contract.Transact(opts, "upgradeToAndCall", newImplementation, data)
}

// UpgradeToAndCall is a paid mutator transaction binding the contract method 0x4f1ef286.
//
// Solidity: function upgradeToAndCall(address newImplementation, bytes data) payable returns()
func (_ECDSAAccount *ECDSAAccountSession) UpgradeToAndCall(newImplementation common.Address, data []byte) (*types.Transaction, error) {
	return _ECDSAAccount.Contract.UpgradeToAndCall(&_ECDSAAccount.TransactOpts, newImplementation, data)
}

// UpgradeToAndCall is a paid mutator transaction binding the contract method 0x4f1ef286.
//
// Solidity: function upgradeToAndCall(address newImplementation, bytes data) payable returns()
func (_ECDSAAccount *ECDSAAccountTransactorSession) UpgradeToAndCall(newImplementation common.Address, data []byte) (*types.Transaction, error) {
	return _ECDSAAccount.Contract.UpgradeToAndCall(&_ECDSAAccount.TransactOpts, newImplementation, data)
}

// ValidateUserOp is a paid mutator transaction binding the contract method 0x19822f7c.
//
// Solidity: function validateUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes) userOp, bytes32 userOpHash, uint256 missingAccountFunds) returns(uint256 validationData)
func (_ECDSAAccount *ECDSAAccountTransactor) ValidateUserOp(opts *bind.TransactOpts, userOp PackedUserOperation, userOpHash [32]byte, missingAccountFunds *big.Int) (*types.Transaction, error) {
	return _ECDSAAccount.contract.Transact(opts, "validateUserOp", userOp, userOpHash, missingAccountFunds)
}

// ValidateUserOp is a paid mutator transaction binding the contract method 0x19822f7c.
//
// Solidity: function validateUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes) userOp, bytes32 userOpHash, uint256 missingAccountFunds) returns(uint256 validationData)
func (_ECDSAAccount *ECDSAAccountSession) ValidateUserOp(userOp PackedUserOperation, userOpHash [32]byte, missingAccountFunds *big.Int) (*types.Transaction, error) {
	return _ECDSAAccount.Contract.ValidateUserOp(&_ECDSAAccount.TransactOpts, userOp, userOpHash, missingAccountFunds)
}

// ValidateUserOp is a paid mutator transaction binding the contract method 0x19822f7c.
//
// Solidity: function validateUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes) userOp, bytes32 userOpHash, uint256 missingAccountFunds) returns(uint256 validationData)
func (_ECDSAAccount *ECDSAAccountTransactorSession) ValidateUserOp(userOp PackedUserOperation, userOpHash [32]byte, missingAccountFunds *big.Int) (*types.Transaction, error) {
	return _ECDSAAccount.Contract.ValidateUserOp(&_ECDSAAccount.TransactOpts, userOp, userOpHash, missingAccountFunds)
}

// WithdrawDepositTo is a paid mutator transaction binding the contract method 0x4d44560d.
//
// Solidity: function withdrawDepositTo(address withdrawAddress, uint256 amount) returns()
func (_ECDSAAccount *ECDSAAccountTransactor) WithdrawDepositTo(opts *bind.TransactOpts, withdrawAddress common.Address, amount *big.Int) (*types.Transaction, error) {
	return _ECDSAAccount.contract.Transact(opts, "withdrawDepositTo", withdrawAddress, amount)
}

// WithdrawDepositTo is a paid mutator transaction binding the contract method 0x4d44560d.
//
// Solidity: function withdrawDepositTo(address withdrawAddress, uint256 amount) returns()
func (_ECDSAAccount *ECDSAAccountSession) WithdrawDepositTo(withdrawAddress common.Address, amount *big.Int) (*types.Transaction, error) {
	return _ECDSAAccount.Contract.WithdrawDepositTo(&_ECDSAAccount.TransactOpts, withdrawAddress, amount)
}

// WithdrawDepositTo is a paid mutator transaction binding the contract method 0x4d44560d.
//
// Solidity: function withdrawDepositTo(address withdrawAddress, uint256 amount) returns()
func (_ECDSAAccount *ECDSAAccountTransactorSession) WithdrawDepositTo(withdrawAddress common.Address, amount *big.Int) (*types.Transaction, error) {
	return _ECDSAAccount.Contract.WithdrawDepositTo(&_ECDSAAccount.TransactOpts, withdrawAddress, amount)
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_ECDSAAccount *ECDSAAccountTransactor) Receive(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ECDSAAccount.contract.RawTransact(opts, nil) // calldata is disallowed for receive function
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_ECDSAAccount *ECDSAAccountSession) Receive() (*types.Transaction, error) {
	return _ECDSAAccount.Contract.Receive(&_ECDSAAccount.TransactOpts)
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_ECDSAAccount *ECDSAAccountTransactorSession) Receive() (*types.Transaction, error) {
	return _ECDSAAccount.Contract.Receive(&_ECDSAAccount.TransactOpts)
}

// ECDSAAccountAccountReceivedNativeTokenIterator is returned from FilterAccountReceivedNativeToken and is used to iterate over the raw logs and unpacked data for AccountReceivedNativeToken events raised by the ECDSAAccount contract.
type ECDSAAccountAccountReceivedNativeTokenIterator struct {
	Event *ECDSAAccountAccountReceivedNativeToken // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ECDSAAccountAccountReceivedNativeTokenIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ECDSAAccountAccountReceivedNativeToken)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ECDSAAccountAccountReceivedNativeToken)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ECDSAAccountAccountReceivedNativeTokenIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ECDSAAccountAccountReceivedNativeTokenIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ECDSAAccountAccountReceivedNativeToken represents a AccountReceivedNativeToken event raised by the ECDSAAccount contract.
type ECDSAAccountAccountReceivedNativeToken struct {
	Sender common.Address
	Value  *big.Int
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterAccountReceivedNativeToken is a free log retrieval operation binding the contract event 0x6063d17f97b8837d6ec87876288b0dcba611bf6d68465a6e592be6f9d9ba4dc3.
//
// Solidity: event AccountReceivedNativeToken(address indexed sender, uint256 value)
func (_ECDSAAccount *ECDSAAccountFilterer) FilterAccountReceivedNativeToken(opts *bind.FilterOpts, sender []common.Address) (*ECDSAAccountAccountReceivedNativeTokenIterator, error) {

	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}

	logs, sub, err := _ECDSAAccount.contract.FilterLogs(opts, "AccountReceivedNativeToken", senderRule)
	if err != nil {
		return nil, err
	}
	return &ECDSAAccountAccountReceivedNativeTokenIterator{contract: _ECDSAAccount.contract, event: "AccountReceivedNativeToken", logs: logs, sub: sub}, nil
}

// WatchAccountReceivedNativeToken is a free log subscription operation binding the contract event 0x6063d17f97b8837d6ec87876288b0dcba611bf6d68465a6e592be6f9d9ba4dc3.
//
// Solidity: event AccountReceivedNativeToken(address indexed sender, uint256 value)
func (_ECDSAAccount *ECDSAAccountFilterer) WatchAccountReceivedNativeToken(opts *bind.WatchOpts, sink chan<- *ECDSAAccountAccountReceivedNativeToken, sender []common.Address) (event.Subscription, error) {

	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}

	logs, sub, err := _ECDSAAccount.contract.WatchLogs(opts, "AccountReceivedNativeToken", senderRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ECDSAAccountAccountReceivedNativeToken)
				if err := _ECDSAAccount.contract.UnpackLog(event, "AccountReceivedNativeToken", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAccountReceivedNativeToken is a log parse operation binding the contract event 0x6063d17f97b8837d6ec87876288b0dcba611bf6d68465a6e592be6f9d9ba4dc3.
//
// Solidity: event AccountReceivedNativeToken(address indexed sender, uint256 value)
func (_ECDSAAccount *ECDSAAccountFilterer) ParseAccountReceivedNativeToken(log types.Log) (*ECDSAAccountAccountReceivedNativeToken, error) {
	event := new(ECDSAAccountAccountReceivedNativeToken)
	if err := _ECDSAAccount.contract.UnpackLog(event, "AccountReceivedNativeToken", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// ECDSAAccountInitializedIterator is returned from FilterInitialized and is used to iterate over the raw logs and unpacked data for Initialized events raised by the ECDSAAccount contract.
type ECDSAAccountInitializedIterator struct {
	Event *ECDSAAccountInitialized // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ECDSAAccountInitializedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ECDSAAccountInitialized)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ECDSAAccountInitialized)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ECDSAAccountInitializedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ECDSAAccountInitializedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ECDSAAccountInitialized represents a Initialized event raised by the ECDSAAccount contract.
type ECDSAAccountInitialized struct {
	Version uint64
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterInitialized is a free log retrieval operation binding the contract event 0xc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d2.
//
// Solidity: event Initialized(uint64 version)
func (_ECDSAAccount *ECDSAAccountFilterer) FilterInitialized(opts *bind.FilterOpts) (*ECDSAAccountInitializedIterator, error) {

	logs, sub, err := _ECDSAAccount.contract.FilterLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return &ECDSAAccountInitializedIterator{contract: _ECDSAAccount.contract, event: "Initialized", logs: logs, sub: sub}, nil
}

// WatchInitialized is a free log subscription operation binding the contract event 0xc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d2.
//
// Solidity: event Initialized(uint64 version)
func (_ECDSAAccount *ECDSAAccountFilterer) WatchInitialized(opts *bind.WatchOpts, sink chan<- *ECDSAAccountInitialized) (event.Subscription, error) {

	logs, sub, err := _ECDSAAccount.contract.WatchLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ECDSAAccountInitialized)
				if err := _ECDSAAccount.contract.UnpackLog(event, "Initialized", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseInitialized is a log parse operation binding the contract event 0xc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d2.
//
// Solidity: event Initialized(uint64 version)
func (_ECDSAAccount *ECDSAAccountFilterer) ParseInitialized(log types.Log) (*ECDSAAccountInitialized, error) {
	event := new(ECDSAAccountInitialized)
	if err := _ECDSAAccount.contract.UnpackLog(event, "Initialized", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// ECDSAAccountOwnershipTransferredIterator is returned from FilterOwnershipTransferred and is used to iterate over the raw logs and unpacked data for OwnershipTransferred events raised by the ECDSAAccount contract.
type ECDSAAccountOwnershipTransferredIterator struct {
	Event *ECDSAAccountOwnershipTransferred // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ECDSAAccountOwnershipTransferredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ECDSAAccountOwnershipTransferred)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ECDSAAccountOwnershipTransferred)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ECDSAAccountOwnershipTransferredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ECDSAAccountOwnershipTransferredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ECDSAAccountOwnershipTransferred represents a OwnershipTransferred event raised by the ECDSAAccount contract.
type ECDSAAccountOwnershipTransferred struct {
	PreviousOwner common.Address
	NewOwner      common.Address
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterOwnershipTransferred is a free log retrieval operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_ECDSAAccount *ECDSAAccountFilterer) FilterOwnershipTransferred(opts *bind.FilterOpts, previousOwner []common.Address, newOwner []common.Address) (*ECDSAAccountOwnershipTransferredIterator, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _ECDSAAccount.contract.FilterLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return &ECDSAAccountOwnershipTransferredIterator{contract: _ECDSAAccount.contract, event: "OwnershipTransferred", logs: logs, sub: sub}, nil
}

// WatchOwnershipTransferred is a free log subscription operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_ECDSAAccount *ECDSAAccountFilterer) WatchOwnershipTransferred(opts *bind.WatchOpts, sink chan<- *ECDSAAccountOwnershipTransferred, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _ECDSAAccount.contract.WatchLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ECDSAAccountOwnershipTransferred)
				if err := _ECDSAAccount.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseOwnershipTransferred is a log parse operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_ECDSAAccount *ECDSAAccountFilterer) ParseOwnershipTransferred(log types.Log) (*ECDSAAccountOwnershipTransferred, error) {
	event := new(ECDSAAccountOwnershipTransferred)
	if err := _ECDSAAccount.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// ECDSAAccountPausedIterator is returned from FilterPaused and is used to iterate over the raw logs and unpacked data for Paused events raised by the ECDSAAccount contract.
type ECDSAAccountPausedIterator struct {
	Event *ECDSAAccountPaused // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ECDSAAccountPausedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ECDSAAccountPaused)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ECDSAAccountPaused)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ECDSAAccountPausedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ECDSAAccountPausedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ECDSAAccountPaused represents a Paused event raised by the ECDSAAccount contract.
type ECDSAAccountPaused struct {
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterPaused is a free log retrieval operation binding the contract event 0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258.
//
// Solidity: event Paused(address account)
func (_ECDSAAccount *ECDSAAccountFilterer) FilterPaused(opts *bind.FilterOpts) (*ECDSAAccountPausedIterator, error) {

	logs, sub, err := _ECDSAAccount.contract.FilterLogs(opts, "Paused")
	if err != nil {
		return nil, err
	}
	return &ECDSAAccountPausedIterator{contract: _ECDSAAccount.contract, event: "Paused", logs: logs, sub: sub}, nil
}

// WatchPaused is a free log subscription operation binding the contract event 0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258.
//
// Solidity: event Paused(address account)
func (_ECDSAAccount *ECDSAAccountFilterer) WatchPaused(opts *bind.WatchOpts, sink chan<- *ECDSAAccountPaused) (event.Subscription, error) {

	logs, sub, err := _ECDSAAccount.contract.WatchLogs(opts, "Paused")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ECDSAAccountPaused)
				if err := _ECDSAAccount.contract.UnpackLog(event, "Paused", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParsePaused is a log parse operation binding the contract event 0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258.
//
// Solidity: event Paused(address account)
func (_ECDSAAccount *ECDSAAccountFilterer) ParsePaused(log types.Log) (*ECDSAAccountPaused, error) {
	event := new(ECDSAAccountPaused)
	if err := _ECDSAAccount.contract.UnpackLog(event, "Paused", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// ECDSAAccountUnpausedIterator is returned from FilterUnpaused and is used to iterate over the raw logs and unpacked data for Unpaused events raised by the ECDSAAccount contract.
type ECDSAAccountUnpausedIterator struct {
	Event *ECDSAAccountUnpaused // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ECDSAAccountUnpausedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ECDSAAccountUnpaused)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ECDSAAccountUnpaused)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ECDSAAccountUnpausedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ECDSAAccountUnpausedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ECDSAAccountUnpaused represents a Unpaused event raised by the ECDSAAccount contract.
type ECDSAAccountUnpaused struct {
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterUnpaused is a free log retrieval operation binding the contract event 0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa.
//
// Solidity: event Unpaused(address account)
func (_ECDSAAccount *ECDSAAccountFilterer) FilterUnpaused(opts *bind.FilterOpts) (*ECDSAAccountUnpausedIterator, error) {

	logs, sub, err := _ECDSAAccount.contract.FilterLogs(opts, "Unpaused")
	if err != nil {
		return nil, err
	}
	return &ECDSAAccountUnpausedIterator{contract: _ECDSAAccount.contract, event: "Unpaused", logs: logs, sub: sub}, nil
}

// WatchUnpaused is a free log subscription operation binding the contract event 0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa.
//
// Solidity: event Unpaused(address account)
func (_ECDSAAccount *ECDSAAccountFilterer) WatchUnpaused(opts *bind.WatchOpts, sink chan<- *ECDSAAccountUnpaused) (event.Subscription, error) {

	logs, sub, err := _ECDSAAccount.contract.WatchLogs(opts, "Unpaused")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ECDSAAccountUnpaused)
				if err := _ECDSAAccount.contract.UnpackLog(event, "Unpaused", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseUnpaused is a log parse operation binding the contract event 0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa.
//
// Solidity: event Unpaused(address account)
func (_ECDSAAccount *ECDSAAccountFilterer) ParseUnpaused(log types.Log) (*ECDSAAccountUnpaused, error) {
	event := new(ECDSAAccountUnpaused)
	if err := _ECDSAAccount.contract.UnpackLog(event, "Unpaused", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// ECDSAAccountUpgradedIterator is returned from FilterUpgraded and is used to iterate over the raw logs and unpacked data for Upgraded events raised by the ECDSAAccount contract.
type ECDSAAccountUpgradedIterator struct {
	Event *ECDSAAccountUpgraded // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ECDSAAccountUpgradedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ECDSAAccountUpgraded)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ECDSAAccountUpgraded)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ECDSAAccountUpgradedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ECDSAAccountUpgradedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ECDSAAccountUpgraded represents a Upgraded event raised by the ECDSAAccount contract.
type ECDSAAccountUpgraded struct {
	Implementation common.Address
	Raw            types.Log // Blockchain specific contextual infos
}

// FilterUpgraded is a free log retrieval operation binding the contract event 0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b.
//
// Solidity: event Upgraded(address indexed implementation)
func (_ECDSAAccount *ECDSAAccountFilterer) FilterUpgraded(opts *bind.FilterOpts, implementation []common.Address) (*ECDSAAccountUpgradedIterator, error) {

	var implementationRule []interface{}
	for _, implementationItem := range implementation {
		implementationRule = append(implementationRule, implementationItem)
	}

	logs, sub, err := _ECDSAAccount.contract.FilterLogs(opts, "Upgraded", implementationRule)
	if err != nil {
		return nil, err
	}
	return &ECDSAAccountUpgradedIterator{contract: _ECDSAAccount.contract, event: "Upgraded", logs: logs, sub: sub}, nil
}

// WatchUpgraded is a free log subscription operation binding the contract event 0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b.
//
// Solidity: event Upgraded(address indexed implementation)
func (_ECDSAAccount *ECDSAAccountFilterer) WatchUpgraded(opts *bind.WatchOpts, sink chan<- *ECDSAAccountUpgraded, implementation []common.Address) (event.Subscription, error) {

	var implementationRule []interface{}
	for _, implementationItem := range implementation {
		implementationRule = append(implementationRule, implementationItem)
	}

	logs, sub, err := _ECDSAAccount.contract.WatchLogs(opts, "Upgraded", implementationRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ECDSAAccountUpgraded)
				if err := _ECDSAAccount.contract.UnpackLog(event, "Upgraded", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseUpgraded is a log parse operation binding the contract event 0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b.
//
// Solidity: event Upgraded(address indexed implementation)
func (_ECDSAAccount *ECDSAAccountFilterer) ParseUpgraded(log types.Log) (*ECDSAAccountUpgraded, error) {
	event := new(ECDSAAccountUpgraded)
	if err := _ECDSAAccount.contract.UnpackLog(event, "Upgraded", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
