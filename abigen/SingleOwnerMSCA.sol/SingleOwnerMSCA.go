// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package SingleOwnerMSCA

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

// Call is an auto generated low-level Go binding around an user-defined struct.
type Call struct {
	Target common.Address
	Value  *big.Int
	Data   []byte
}

// ExecutionFunctionConfig is an auto generated low-level Go binding around an user-defined struct.
type ExecutionFunctionConfig struct {
	Plugin                    common.Address
	UserOpValidationFunction  FunctionReference
	RuntimeValidationFunction FunctionReference
}

// ExecutionHooks is an auto generated low-level Go binding around an user-defined struct.
type ExecutionHooks struct {
	PreExecHook  FunctionReference
	PostExecHook FunctionReference
}

// FunctionReference is an auto generated low-level Go binding around an user-defined struct.
type FunctionReference struct {
	Plugin     common.Address
	FunctionId uint8
}

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

// SingleOwnerMSCAMetaData contains all meta data concerning the SingleOwnerMSCA contract.
var SingleOwnerMSCAMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[{\"name\":\"_newEntryPoint\",\"type\":\"address\",\"internalType\":\"contractIEntryPoint\"},{\"name\":\"_newPluginManager\",\"type\":\"address\",\"internalType\":\"contractPluginManager\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"fallback\",\"stateMutability\":\"payable\"},{\"type\":\"receive\",\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"UPGRADE_INTERFACE_VERSION\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"addDeposit\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"author\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"entryPoint\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"contractIEntryPoint\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"execute\",\"inputs\":[{\"name\":\"target\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"returnData\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"executeBatch\",\"inputs\":[{\"name\":\"calls\",\"type\":\"tuple[]\",\"internalType\":\"structCall[]\",\"components\":[{\"name\":\"target\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]}],\"outputs\":[{\"name\":\"returnData\",\"type\":\"bytes[]\",\"internalType\":\"bytes[]\"}],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"executeFromPlugin\",\"inputs\":[{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"executeFromPluginExternal\",\"inputs\":[{\"name\":\"target\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"getDeposit\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getEntryPoint\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"contractIEntryPoint\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getExecutionFunctionConfig\",\"inputs\":[{\"name\":\"selector\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}],\"outputs\":[{\"name\":\"executionFunctionConfig\",\"type\":\"tuple\",\"internalType\":\"structExecutionFunctionConfig\",\"components\":[{\"name\":\"plugin\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"userOpValidationFunction\",\"type\":\"tuple\",\"internalType\":\"structFunctionReference\",\"components\":[{\"name\":\"plugin\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"}]},{\"name\":\"runtimeValidationFunction\",\"type\":\"tuple\",\"internalType\":\"structFunctionReference\",\"components\":[{\"name\":\"plugin\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"}]}]}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getExecutionHooks\",\"inputs\":[{\"name\":\"selector\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}],\"outputs\":[{\"name\":\"executionHooks\",\"type\":\"tuple[]\",\"internalType\":\"structExecutionHooks[]\",\"components\":[{\"name\":\"preExecHook\",\"type\":\"tuple\",\"internalType\":\"structFunctionReference\",\"components\":[{\"name\":\"plugin\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"}]},{\"name\":\"postExecHook\",\"type\":\"tuple\",\"internalType\":\"structFunctionReference\",\"components\":[{\"name\":\"plugin\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"}]}]}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getInstalledPlugins\",\"inputs\":[],\"outputs\":[{\"name\":\"pluginAddresses\",\"type\":\"address[]\",\"internalType\":\"address[]\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getNativeOwner\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getNonce\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getPreValidationHooks\",\"inputs\":[{\"name\":\"selector\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}],\"outputs\":[{\"name\":\"preUserOpValidationHooks\",\"type\":\"tuple[]\",\"internalType\":\"structFunctionReference[]\",\"components\":[{\"name\":\"plugin\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"}]},{\"name\":\"preRuntimeValidationHooks\",\"type\":\"tuple[]\",\"internalType\":\"structFunctionReference[]\",\"components\":[{\"name\":\"plugin\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"}]}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"initializeSingleOwnerMSCA\",\"inputs\":[{\"name\":\"owner\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"installPlugin\",\"inputs\":[{\"name\":\"plugin\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"manifestHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"pluginInstallData\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"dependencies\",\"type\":\"tuple[]\",\"internalType\":\"structFunctionReference[]\",\"components\":[{\"name\":\"plugin\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"}]}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"isValidSignature\",\"inputs\":[{\"name\":\"hash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"signature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"onERC1155BatchReceived\",\"inputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"\",\"type\":\"uint256[]\",\"internalType\":\"uint256[]\"},{\"name\":\"\",\"type\":\"uint256[]\",\"internalType\":\"uint256[]\"},{\"name\":\"\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"onERC1155Received\",\"inputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"onERC721Received\",\"inputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"pluginManager\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"contractPluginManager\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"proxiableUUID\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"renounceNativeOwnership\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"supportsInterface\",\"inputs\":[{\"name\":\"interfaceId\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"tokensReceived\",\"inputs\":[{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"from\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"to\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"userData\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"operatorData\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"transferNativeOwnership\",\"inputs\":[{\"name\":\"newOwner\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"uninstallPlugin\",\"inputs\":[{\"name\":\"plugin\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"config\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"pluginUninstallData\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"upgradeToAndCall\",\"inputs\":[{\"name\":\"newImplementation\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"validateUserOp\",\"inputs\":[{\"name\":\"userOp\",\"type\":\"tuple\",\"internalType\":\"structPackedUserOperation\",\"components\":[{\"name\":\"sender\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"nonce\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"initCode\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"callData\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"accountGasLimits\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"preVerificationGas\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"gasFees\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"paymasterAndData\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"signature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]},{\"name\":\"userOpHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"missingAccountFunds\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"validationData\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"version\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"withdrawDepositTo\",\"inputs\":[{\"name\":\"withdrawAddress\",\"type\":\"address\",\"internalType\":\"addresspayable\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"event\",\"name\":\"Initialized\",\"inputs\":[{\"name\":\"version\",\"type\":\"uint64\",\"indexed\":false,\"internalType\":\"uint64\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"OwnershipTransferred\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"previousOwner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"newOwner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"PluginInstalled\",\"inputs\":[{\"name\":\"plugin\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"manifestHash\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"},{\"name\":\"dependencies\",\"type\":\"tuple[]\",\"indexed\":false,\"internalType\":\"structFunctionReference[]\",\"components\":[{\"name\":\"plugin\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"}]}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"PluginUninstalled\",\"inputs\":[{\"name\":\"plugin\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"onUninstallSucceeded\",\"type\":\"bool\",\"indexed\":true,\"internalType\":\"bool\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"SingleOwnerMSCAInitialized\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"entryPointAddress\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"owner\",\"type\":\"address\",\"indexed\":false,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"Upgraded\",\"inputs\":[{\"name\":\"implementation\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"WalletStorageInitialized\",\"inputs\":[],\"anonymous\":false},{\"type\":\"error\",\"name\":\"AddressEmptyCode\",\"inputs\":[{\"name\":\"target\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"ERC1967InvalidImplementation\",\"inputs\":[{\"name\":\"implementation\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"ERC1967NonPayable\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"ExecFromPluginToSelectorNotPermitted\",\"inputs\":[{\"name\":\"plugin\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"selector\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}]},{\"type\":\"error\",\"name\":\"ExecuteFromPluginToExternalNotPermitted\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"FailedInnerCall\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"InvalidAuthorizer\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"InvalidExecutionFunction\",\"inputs\":[{\"name\":\"selector\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}]},{\"type\":\"error\",\"name\":\"InvalidHookFunctionId\",\"inputs\":[{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"}]},{\"type\":\"error\",\"name\":\"InvalidInitialization\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"InvalidLimit\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"InvalidOwnerForMSCA\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"owner\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"InvalidValidationFunctionId\",\"inputs\":[{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"}]},{\"type\":\"error\",\"name\":\"NativeTokenSpendingNotPermitted\",\"inputs\":[{\"name\":\"plugin\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"NotFoundSelector\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"NotInitializing\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"NotNativeFunctionSelector\",\"inputs\":[{\"name\":\"selector\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}]},{\"type\":\"error\",\"name\":\"PostExecHookFailed\",\"inputs\":[{\"name\":\"plugin\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"revertReason\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]},{\"type\":\"error\",\"name\":\"PreExecHookFailed\",\"inputs\":[{\"name\":\"plugin\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"revertReason\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]},{\"type\":\"error\",\"name\":\"PreRuntimeValidationHookFailed\",\"inputs\":[{\"name\":\"plugin\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"revertReason\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]},{\"type\":\"error\",\"name\":\"RuntimeValidationFailed\",\"inputs\":[{\"name\":\"plugin\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"revertReason\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]},{\"type\":\"error\",\"name\":\"TargetIsPlugin\",\"inputs\":[{\"name\":\"plugin\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"UUPSUnauthorizedCallContext\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"UUPSUnsupportedProxiableUUID\",\"inputs\":[{\"name\":\"slot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]},{\"type\":\"error\",\"name\":\"UnauthorizedCaller\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"WalletStorageIsInitialized\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"WalletStorageIsInitializing\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"WalletStorageIsNotInitializing\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"WrongTimeBounds\",\"inputs\":[]}]",
	Bin: "0x60e0346200010157601f6200454638819003918201601f19168301916001600160401b0383118484101762000106578084926040948552833981010312620001015780516001600160a01b039182821682036200010157602001519182168203620001015760805260a052620000746200011c565b3060c052620000826200011c565b6040516143a990816200019d82396080518181816105ae015281816110bf015281816110fd0152818161118f01528181611cc401528181611e150152818161220e015281816123b2015281816127e601528181612b2e015261304d015260a0518181816108aa0152611c48015260c0518181816113b20152612b980152f35b600080fd5b634e487b7160e01b600052604160045260246000fd5b7fc6a0cc20c824c4eecc4b0fbb7fb297d07492a7bd12c83d4fa4d27b4249f9bfd0805460ff8160081c166200018a5760ff808216036200015a575050565b60ff191660ff1790557f80bd505c666aa4feeb94643343d3e5acfd6d0b8c43c826331f5d543cbfa7e575600080a1565b604051630a87f6e360e31b8152600490fdfe60806040526004361015610026575b36156100245761001c6123a8565b602081519101f35b005b60003560e01c806223de291461023057806301ffc9a71461022b578063150b7a02146102265780631626ba7e1461022157806319822f7c1461021c5780632e0e0bae1461021757806334fcd5be1461021257806336cf06ff1461020d57806338997b11146102085780633a0cac561461020357806344ab613f146101c25780634a58db19146101fe5780634d44560d146101f95780634ee53c76146101f45780634f1ef286146101ef57806352d1902d146101ea57806354fd4d50146101e5578063642f9dd4146101e057806366b46a7a146101db5780638d112184146101d657806394ed11e7146101d1578063a6c3e6b9146101cc578063ad3cb1cc146101c7578063b0d691fe146101c2578063b61d27f6146101bd578063bc197c81146101b8578063c1a221f3146101b3578063c399ec88146101ae578063ceaf1309146101a9578063d087d288146101a4578063f23a6e611461019f578063f85730f41461019a5763f95d04b00361000e57611fdc565b611ef1565b611e80565b611de2565b611d7b565b611c98565b611b7f565b611af0565b611a83565b6110a9565b611a3d565b6119df565b61186b565b611771565b611737565b6114db565b61140a565b61139f565b61129b565b61121d565b611166565b6110ee565b610edc565b610c37565b610ad2565b6109b5565b610894565b610565565b610515565b61039d565b610303565b610285565b6001600160a01b0381160361024657565b600080fd5b359061025682610235565b565b9181601f84011215610246578235916001600160401b038311610246576020838186019501011161024657565b346102465760c0366003190112610246576102a1600435610235565b6102ac602435610235565b6102b7604435610235565b6001600160401b03608435818111610246576102d7903690600401610258565b505060a43590811161024657610024903690600401610258565b6001600160e01b031981160361024657565b34610246576020366003190112610246576020600435610322816102f1565b61032b81612476565b908115610382575b8115610367575b811561034c575b506040519015158152f35b6001600160e01b031916630b135d3f60e11b14905038610341565b6001600160e01b03198116630271189760e51b14915061033a565b6001600160e01b03198116630a85bd0160e11b149150610333565b34610246576080366003190112610246576103b9600435610235565b6103c4602435610235565b6064356001600160401b038111610246576103e3903690600401610258565b5050604051630a85bd0160e11b8152602090f35b634e487b7160e01b600052604160045260246000fd5b6001600160401b03811161042057604052565b6103f7565b606081019081106001600160401b0382111761042057604052565b604081019081106001600160401b0382111761042057604052565b61016081019081106001600160401b0382111761042057604052565b90601f801991011681019081106001600160401b0382111761042057604052565b6040519061025682610425565b6001600160401b03811161042057601f01601f191660200190565b9291926104cc826104a5565b916104da6040519384610477565b829481845281830111610246578281602093846000960137010152565b9080601f8301121561024657816020610512933591016104c0565b90565b34610246576040366003190112610246576024356001600160401b0381116102465761055261054a60209236906004016104f7565b6004356120df565b6040516001600160e01b03199091168152f35b34610246576003196060368201126102465760048035906001600160401b03821161024657610120828201938336030112610246576001600160a01b03926044359290602435907f0000000000000000000000000000000000000000000000000000000000000000861633036108785760648301846105e48284612616565b905010610867576106016105fb6106079284612616565b90612648565b90612656565b6001600160e01b0319811615610867576106209061204b565b61062b83838361369b565b6000805160206143348339815191525490949060101c6001600160a01b03169088821661082857505060010190610661826122a5565b6001600160581b031961067382613891565b16801590811561081a575b811561080c575b506107e157916106e194939160006106c56106ba6106ae6106ae6020985160018060a01b031690565b6001600160a01b031690565b935460a01c60ff1690565b60405163c4db8dd960e01b8152978895869485938c85016126d4565b03925af180156107dc576106fe926000916107ad575b50906138b8565b60408101519093166001600160a01b031680151590816107a1575b50610792575061075c6107749260018060a01b0360408201511665ffffffffffff60a01b602083015160a01b16179065ffffffffffff60d01b905160d01b161790565b9080610778575b506040519081529081906020820190565b0390f35b600080808093338219f15061078b61209a565b5038610763565b6040516310b1cc1760e31b8152fd5b60019150141538610719565b6107cf915060203d6020116107d5575b6107c78183610477565b8101906122cd565b386106f7565b503d6107bd565b612280565b6020908101516040516314d291c760e21b815260ff90911681880190815281900390910190fd5b0390fd5b600160591b14905038610685565b600160581b8114915061067e565b6106fe95949192506108456108529461010461084c930190612616565b36916104c0565b916124f5565b1561085f576000906138b8565b6001906138b8565b60405163aedb4d1360e01b81528590fd5b604051635c427cd960e01b81528490fd5b600091031261024657565b34610246576000366003190112610246576040517f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03168152602090f35b9181601f84011215610246578235916001600160401b038311610246576020808501948460051b01011161024657565b60005b83811061091c5750506000910152565b818101518382015260200161090c565b9060209161094581518092818552858086019101610909565b601f01601f1916010190565b6020808201906020835283518092526040830192602060408460051b8301019501936000915b8483106109875750505050505090565b90919293949584806109a5600193603f198682030187528a5161092c565b9801930193019194939290610977565b602080600319360112610246576004906004356001600160401b038111610246576109e49036906004016108d9565b9290916109ef6127be565b926109f9856129b9565b9460005b818110610a1d5761077487610a11886128b2565b60405191829182610951565b610a38610a33610a2e838587612a03565b612a25565b613a47565b610a9b5780610a7f610a50610a2e6001948688612a03565b86610a5c848789612a03565b0135610a79610845610a6f86898b612a03565b6040810190612616565b9161360e565b610a89828a612858565b52610a948189612858565b50016109fd565b90610aaa9350610a2e92612a03565b604051632738731760e21b81526001600160a01b039091169181019182529081906020010390fd5b3461024657602036600319011261024657600435610aef81610235565b600080516020614334833981519152549060ff808360081c161592168280610bdd575b15908115610bc0575b50610bae57600080516020614334833981519152805460ff19166001179055610b489082610b8d576121eb565b610b4e57005b600080516020614334833981519152805461ff00191690557f80bd505c666aa4feeb94643343d3e5acfd6d0b8c43c826331f5d543cbfa7e575600080a1005b600080516020614334833981519152805461ff0019166101001790556121eb565b60405163281f483d60e11b8152600490fd5b303b15915081610bd2575b5038610b1b565b600191501438610bcb565b5060018110610b12565b606060031982011261024657600435610bff81610235565b9160243591604435906001600160401b03821161024657610c2291600401610258565b9091565b90602061051292818152019061092c565b610c4036610be7565b91906001600160a01b03841630148015610e88575b610e765781151580610e6d575b80610e23575b610e0b573360009081527fc6a0cc20c824c4eecc4b0fbb7fb297d07492a7bd12c83d4fa4d27b4249f9bfcd602090815260408083206001600160a01b03881684529091529020610cb88483612656565b9081815460ff8116600014610dcc5760081c60ff16918215610d99575b50508015610d91575b15610d6757506338997b1160e01b6000527fc6a0cc20c824c4eecc4b0fbb7fb297d07492a7bd12c83d4fa4d27b4249f9bfcf60205261077493610d5b92610d5592610a7990610d4d367f07eda5375f0c0049cbc1df9c13c9a2a93f42195e5d3aa188c59b49f74f3e5e51613418565b9636916104c0565b916128b2565b60405191829182610c26565b60405163415b1b4960e01b81523360048201526001600160e01b0319919091166024820152604490fd5b508315610cde565b610dc59250906001610dbe92019063ffffffff60e01b16600052602052604060002090565b5460ff1690565b8138610cd5565b50503360009081527fc6a0cc20c824c4eecc4b0fbb7fb297d07492a7bd12c83d4fa4d27b4249f9bfcb60205260409020610e069150610dbe565b610cde565b60405163171b202760e11b8152336004820152602490fd5b503360009081527fc6a0cc20c824c4eecc4b0fbb7fb297d07492a7bd12c83d4fa4d27b4249f9bfcb60205260409020610e6890610e64905460081c60ff1690565b1590565b610c68565b50348211610c62565b6040516305d2fdc960e41b8152600490fd5b50610e9284613a47565b610c55565b602090602060408183019282815285518094520193019160005b828110610ebf575050505090565b83516001600160a01b031685529381019392810192600101610eb1565b34610246576000806003193601126110a6577fc6a0cc20c824c4eecc4b0fbb7fb297d07492a7bd12c83d4fa4d27b4249f9bfca5490610f1a82612ac8565b918180805b838310610f35575b604051806107748882610e97565b610f3d612a9b565b926001600160a01b03928381161561104f575b86905b600a821080611044575b15610fdb57610fcf610fc282610f89610fd594610f7a878c612858565b6001600160a01b039091169052565b6001600160a01b031660009081527fc6a0cc20c824c4eecc4b0fbb7fb297d07492a7bd12c83d4fa4d27b4249f9bfc86020526040902090565b546001600160a01b031690565b91612b10565b90610f53565b9295919396908552805b8551811015611027578061102161100e6110016001948a612858565b516001600160a01b031690565b610f7a61101a8b612b10565b9a8d612858565b01610fe5565b50959094935081161561103f57600190910191610f1f565b610f27565b508481161515610f5d565b50600080527fc6a0cc20c824c4eecc4b0fbb7fb297d07492a7bd12c83d4fa4d27b4249f9bfc86020526110a17fd594a02d3fda915a830c228e795b44eb4af5dfc9cc085b4c42f40bccd958a910610fc2565b610f50565b80fd5b34610246576000366003190112610246576040517f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03168152602090f35b6000806003193601126110a6577f00000000000000000000000000000000000000000000000000000000000000006001600160a01b031681813b156110a65760405163b760faf960e01b8152306004820152918290602490829034905af180156107dc5761115a575080f35b6111639061040d565b80f35b3461024657600060403660031901126110a65760043561118581610235565b6001600160a01b037f0000000000000000000000000000000000000000000000000000000000000000811691903383141580611213575b611201578391833b156111fd5760449083604051958694859363040b850f60e31b855216600484015260243560248401525af180156107dc5761115a575080f35b8280fd5b604051635c427cd960e01b8152600490fd5b50303314156111bc565b34610246576000806003193601126110a657611237612b24565b6111636112426127be565b600080516020614334833981519152805462010000600160b01b03198116909155839060101c6001600160a01b0316307fc8894f26f396ce8c004245c8b7cd1b92103a6e4302fcbab883987149ac01b7ec8380a46128b2565b6040366003190112610246576004356112b381610235565b6024356001600160401b038111610246576112d29036906004016104f7565b906112db612b8e565b6112e36127be565b6112eb612b8e565b6040516352d1902d60e01b81526020816004816001600160a01b0387165afa6000918161137e575b5061133957604051634c9c8ce360e01b81526001600160a01b0384166004820152602490fd5b600080516020614354833981519152819392930361136457506100249261135f916140a6565b6128b2565b604051632a87526960e21b81526004810191909152602490fd5b61139891925060203d6020116107d5576107c78183610477565b9038611313565b34610246576000366003190112610246577f00000000000000000000000000000000000000000000000000000000000000006001600160a01b031630036113f85760206040516000805160206143548339815191528152f35b60405163703e46dd60e11b8152600490fd5b346102465760003660031901126102465761077460405161142a81610440565b60058152640312e302e360dc1b602082015260405191829160208352602083019061092c565b602080820190602083528351809252602060408094019401926000905b83821061147c57505050505090565b90919293948360806001926114ce838a516114ad84825160ff6020809260018060a01b038151168552015116910152565b015180516001600160a01b031683880190815260209182015160ff16910152565b019601949392019061146d565b3461024657602080600319360112610246576115016004356114fc816102f1565b61204b565b600d810160108201546013830192601681015494611523601183015487612be8565b9561152f600097612bf5565b95611538613b22565b9088915b8383106116a6575b50505050611550613b22565b601260009301905b848410611571575b878752604051806107748982611450565b611582908692969897949598613b6f565b6000969196975b8751891015611665576115ca6115c56115ab6115a58c8c612858565b51613891565b85906001600160581b031916600052602052604060002090565b612ecd565b805190949015611638576000915b85518310156116245761161c6001916115f18d8d612858565b516115fc828c612858565b51526116088589612858565b5189611614838d612858565b510152612b10565b9201916115d8565b9a92945098600191505b0197929098611589565b986001919a92945061164a818a612858565b5161165e6116578d612b10565b9c89612858565b515261162e565b9650909793965093919361168861167b82613891565b6001600160581b03191690565b1561169e57600190920192939196909496611558565b859750611560565b6116b890829998999796939597613b6f565b9390996000905b8b5182101561170357816001918a6116f38f8e9c9b9a999897966116e291612858565b51926116ed81612b10565b9c612858565b51015201909192939495966116bf565b98999593969a50509261171861167b82613891565b1561172d57600190920191989593969861153c565b9895939698611544565b34610246576000366003190112610246576000805160206143348339815191525460405160109190911c6001600160a01b03168152602090f35b3461024657602036600319011261024657610774600435611791816102f1565b6040519061179e82610425565b600082526117f560076117e860208501936117b761228c565b855260408601946117c661228c565b86526117d182612c62565b1561184a573087525b6117ee60016117e88461204b565b016122a5565b905261204b565b90526040519182918281516001600160a01b039081168252602080840151805183168285015281015160ff90811660408086019190915290940151805190921660608401520151909116608082015260a00190565b611866611859610fc28461204b565b6001600160a01b03168852565b6117da565b602036600319011261024657600480356001600160401b038111610246576118969036908301610258565b91908183106119cf576118ac6106018483612648565b6001600160e01b03198116156119be573360009081527fc6a0cc20c824c4eecc4b0fbb7fb297d07492a7bd12c83d4fa4d27b4249f9bfcc602090815260408083206001600160e01b031985168452909152902061190c90610e6490610dbe565b611990576119198161204b565b80549093906001600160a01b0316156119685761077484610d5b610d55886119628861195a61194c8483600d8a016134f6565b96546001600160a01b031690565b9236916104c0565b906135d7565b604051632d71321b60e11b81526001600160e01b031990921690820190815281906020010390fd5b6040805163415b1b4960e01b8152338186019081526001600160e01b03199093166020840152918291010390fd5b60405163aedb4d1360e01b81528390fd5b5060405163aedb4d1360e01b8152fd5b34610246576000366003190112610246576107746040516119ff81610440565b601981527f436972636c6520496e7465726e65742046696e616e6369616c00000000000000602082015260405191829160208352602083019061092c565b3461024657600036600319011261024657610774604051611a5d81610440565b60058152640352e302e360dc1b602082015260405191829160208352602083019061092c565b611a8c36610be7565b9190611a966127be565b92611aa085613a47565b611acf5793611abb92610a79610d55936107749736916104c0565b60405191829160208352602083019061092c565b604051632738731760e21b81526001600160a01b0386166004820152602490fd5b346102465760a036600319011261024657611b0c600435610235565b611b17602435610235565b6001600160401b0360443581811161024657611b379036906004016108d9565b505060643581811161024657611b519036906004016108d9565b505060843590811161024657611b6b903690600401610258565b505060405163bc197c8160e01b8152602090f35b3461024657606036600319011261024657600435611b9c81610235565b6001600160401b039060243582811161024657611bbd9036906004016104f7565b916044359081116102465761002492611c6d611c38611be260019436906004016104f7565b94611c46611bee6127be565b9660405193849163b58bb5cb60e01b6020840152611c26898060a01b038096169889602486015260606044860152608485019061092c565b8381036023190160648501529061092c565b03601f198101845283610477565b7f000000000000000000000000000000000000000000000000000000000000000016612e56565b507feb7551bad8fd10038dee62a958c2b6f45624499dc800ff8936bb0a4904bdd2fe600080a36128b2565b34610246576000366003190112610246576040516370a0823160e01b81523060048201526020816024817f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03165afa80156107dc57602091600091611d08575b50604051908152f35b611d1f9150823d84116107d5576107c78183610477565b38611cff565b90815180825260208080930193019160005b828110611d45575050505090565b9091929382604082611d6f600194895160ff6020809260018060a01b038151168552015116910152565b01950193929101611d37565b3461024657602036600319011261024657611dd4600435611d9b816102f1565b610774611dc06008611db4611dba6002611db48761204b565b01612ecd565b9461204b565b604051938493604085526040850190611d25565b908382036020850152611d25565b3461024657600036600319011261024657604051631aab3f0d60e11b8152306004820152600060248201526020816044817f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03165afa80156107dc5761077491600091611e6157506040519081529081906020820190565b611e7a915060203d6020116107d5576107c78183610477565b38610763565b346102465760a036600319011261024657611e9c600435610235565b611ea7602435610235565b6084356001600160401b03811161024657611ec6903690600401610258565b505060405163f23a6e6160e01b8152602090f35b6001600160401b0381116104205760051b60200190565b3461024657608036600319011261024657600435611f0e81610235565b6001600160401b0360443581811161024657611f2e9036906004016104f7565b606435918211610246573660238301121561024657816004013592611f5284611eda565b92604094611f636040519586610477565b8085526020906024602087019160061b8401019236841161024657602401905b838210611f98576100248787602435886122dc565b878236031261024657875190611fad82610440565b8235611fb881610235565b8252838301359060ff8216820361024657828592838c950152815201910190611f83565b3461024657602036600319011261024657600435611ff981610235565b612001612b24565b6120096127be565b6001600160a01b038216156120245761135f61002492612a2f565b6040516317c34cad60e01b81523060048201526001600160a01b0383166024820152604490fd5b63ffffffff60e01b166000527fc6a0cc20c824c4eecc4b0fbb7fb297d07492a7bd12c83d4fa4d27b4249f9bfcf602052604060002090565b60409061051293928152816020820152019061092c565b3d156120c5573d906120ab826104a5565b916120b96040519384610477565b82523d6000602084013e565b606090565b908160209103126102465751610512816102f1565b6000805160206143348339815191525460101c6001600160a01b0316919082156121275761210c926124f5565b61211c576001600160e01b031990565b630b135d3f60e11b90565b630b135d3f60e11b60009081527fc6a0cc20c824c4eecc4b0fbb7fb297d07492a7bd12c83d4fa4d27b4249f9bfcf60205292508291906121ab6121b961218c7fdd9229e5df2d5a19f89aca56c9c5f0120c005d627694c233e51b66fa569ffd50610fc2565b936040519283916020830195630b135d3f60e11b875260248401612083565b03601f198101835282610477565b51915afa6121c561209a565b90156121de5780602080610512935183010191016120ca565b506001600160e01b031990565b6001600160a01b038181169182156122575761220690612a2f565b6040519182527f000000000000000000000000000000000000000000000000000000000000000016907fb9a2e77405e16894f62a69f7bd6a34b8ca7647b6f5d5408d7c577d275691fde360203092a3565b6040516317c34cad60e01b81523060048201526001600160a01b03919091166024820152604490fd5b6040513d6000823e3d90fd5b6040519061229982610440565b60006020838281520152565b906040516122b281610440565b91546001600160a01b038116835260a01c60ff166020830152565b90816020910312610246575190565b9190610256937fbd807faaec7a357be5390445b7efef4a0ca92fa66300ee4827dde3d9387ffb519161237961230f6127be565b956040519063c877ea6360e01b6020830152611c468261236561235360018060a01b038095169a8b602485015288604485015260a0606485015260c484019061092c565b82810360231901608484015288611d25565b3060a483015203601f198101845283610477565b5061238960405192839283612391565b0390a26128b2565b604090610512939281528160208201520190611d25565b6001600160a01b037f00000000000000000000000000000000000000000000000000000000000000008116330361245c575b6000356001600160e01b031916906123f18261204b565b908154169182156124445750610d5561241161051292600d369101613418565b9261241b366104a5565b906124296040519283610477565b3682523660006020840137600060203684010152349061360e565b60249060405190632d71321b60e11b82526004820152fd5b6124716000356001600160e01b031916613041565b6123da565b6001600160e01b03199081169081146124cf576301ffc9a760e01b81146124c9576000527fc6a0cc20c824c4eecc4b0fbb7fb297d07492a7bd12c83d4fa4d27b4249f9bfce602052604060002054151590565b50600190565b50600090565b600411156124df57565b634e487b7160e01b600052602160045260246000fd5b90917f19457468657265756d205369676e6564204d6573736167653a0a33320000000060005282601c5261252d81603c600020613640565b50612537816124d5565b159081612600575b506125e25761254e8184613640565b50612558816124d5565b1590816125ea575b506125e257600091829160405161258e816121ab6020820194630b135d3f60e11b998a875260248401612083565b51915afa9061259b61209a565b826125d4575b826125b7575b50506125b257600090565b600190565b6125cc919250602080825183010191016122cd565b1438806125a7565b9150602082511015916125a1565b505050600190565b6001600160a01b03848116911614905038612560565b6001600160a01b0384811691161490503861253f565b903590601e198136030182121561024657018035906001600160401b0382116102465760200191813603831361024657565b906004116102465790600490565b6001600160e01b0319903581811693926004811061267357505050565b60040360031b82901b16169150565b9035601e19823603018112156102465701602081359101916001600160401b03821161024657813603831361024657565b908060209392818452848401376000828201840152601f01601f1916010190565b93929161273a6127b99160ff6040941687526060602088015261270a606088016126fd8361024b565b6001600160a01b03169052565b602081013560808801526127a961272385830183612682565b9390610120948560a08c01526101808b01916126b3565b916127a061276261274e6060840184612682565b605f198d8803810160c08f015296916126b3565b608083013560e08c01526101009560a0840135878d015260c0840135908c015261278f60e0840184612682565b8c830387016101408e0152906126b3565b93810190612682565b91888403016101608901526126b3565b930152565b6000356001600160e01b0319166127d481612c62565b1561282a5761051290600d90612819907f00000000000000000000000000000000000000000000000000000000000000006001600160a01b031633036128215761204b565b013690613418565b6114fc81613041565b602490604051906350f2762560e11b82526004820152fd5b634e487b7160e01b600052603260045260246000fd5b805182101561286c5760209160051b010190565b612842565b60409060ff6105129493168152816020820152019061092c565b60ff610512949360609360018060a01b03168352166020820152816040820152019061092c565b80516000905b8082106128c457505050565b909192602090816128d58587612858565b51015180519093906128f1906106ae906001600160a01b031681565b92840195612900875160ff1690565b9561290b8183612858565b515196853b15610246576040958651808093631128186d60e01b825260049b8c83019161293792612871565b03815a6000948591f190816129a0575b5061298d578787610808888861297761296f61296161209a565b93516001600160a01b031690565b955160ff1690565b9051638342a64960e01b8152948594850161288b565b92965093509350600191500190916128b8565b806129ad6129b39261040d565b80610889565b38612947565b906129c382611eda565b6129d06040519182610477565b82815280926129e1601f1991611eda565b019060005b8281106129f257505050565b8060606020809385010152016129e6565b919081101561286c5760051b81013590605e1981360301821215610246570190565b3561051281610235565b600080516020614334833981519152805462010000600160b01b03198116601084811b62010000600160b01b0316919091179092556001600160a01b0392831692911c16307fc8894f26f396ce8c004245c8b7cd1b92103a6e4302fcbab883987149ac01b7ec600080a4565b6040519061016082018281106001600160401b0382111761042057604052600a8252610140366020840137565b90612ad282611eda565b612adf6040519182610477565b8281528092612af0601f1991611eda565b0190602036910137565b634e487b7160e01b600052601160045260246000fd5b6000198114612b1f5760010190565b612afa565b60018060a01b03807f0000000000000000000000000000000000000000000000000000000000000000163314159081612b6f575b5080612b65575b61120157565b5030331415612b5f565b90506000805160206143348339815191525460101c1633141538612b58565b6001600160a01b037f00000000000000000000000000000000000000000000000000000000000000008116308114918215612bcc575b50506113f857565b6000805160206143548339815191525416141590503880612bc4565b91908201809211612b1f57565b90612bff82611eda565b604090612c0f6040519182610477565b8381528093612c20601f1991611eda565b019160005b838110612c325750505050565b6020908251612c4081610440565b612c4861228c565b815282612c5361228c565b81830152828601015201612c25565b63ffffffff60e01b16635b0e93fb60e11b8114908115612e45575b8115612e34575b8115612e23575b8115612e12575b8115612e01575b8115612df0575b8115612ddf575b8115612dce575b8115612dbd575b8115612dac575b8115612d9b575b8115612d8a575b8115612d79575b8115612d68575b8115612d57575b8115612d46575b8115612d35575b8115612d24575b8115612d13575b8115612d05575090565b63335a353d60e11b14919050565b6327729e3b60e11b81149150612cfb565b630f95d04b60e41b81149150612cf4565b6336cf06ff60e01b81149150612ced565b6370c321eb60e01b81149150612ce6565b631a10fa5160e31b81149150612cdf565b6344ab613f60e01b81149150612cd8565b637437e28f60e11b81149150612cd1565b631d06562b60e11b81149150612cca565b63ceaf130960e01b81149150612cc3565b63190be77560e21b81149150612cbc565b632344486160e21b81149150612cb5565b6338997b1160e01b81149150612cae565b6394ed11e760e01b81149150612ca7565b6301ffc9a760e01b81149150612ca0565b6352d1902d60e01b81149150612c99565b63278f794360e11b81149150612c92565b63c1a221f360e01b81149150612c8b565b633e15cc3d60e21b81149150612c84565b631a7e6adf60e11b81149150612c7d565b6000918291602082519201905af4612e6c61209a565b9015612e755790565b602081519101fd5b90612e8782611eda565b612e946040519182610477565b8281528092612ea5601f1991611eda565b019060005b828110612eb657505050565b602090612ec161228c565b82828501015201612eaa565b600381015490612edc82612e7d565b916000612ee7613b22565b6000905b838210612efb575b505050505090565b612f0b9085979395969496613b6f565b95909660005b8851811015612f4e5780612f47612f2a6001938c612858565b5198612f3581612b10565b99612f40828b612858565b5288612858565b5001612f11565b509650929391946001600160581b0319612f6782613891565b1615612f7c5760019091019095939495612eeb565b84959650612ef3565b92909160ff60a09593168452600180861b03166020840152604083015260806060830152806080830152806000848401376000828201840152601f01601f1916010190565b919260809360ff6020969316845260018060a01b0316858401526040830152826060830152808383015280600060a084013760008282018401850152601f01601f191601010190565b909260809260ff610512979516835260018060a01b03166020830152604082015281606082015201916126b3565b6001600160a01b0390337f00000000000000000000000000000000000000000000000000000000000000008316146133935761307c9061204b565b90613089600783016122a5565b600b830154909260080161309b613b22565b6130a361228c565b506000905b8382106131e1575b50506000805160206143348339815191525460101c6001600160a01b031691506130d79050565b16806131c65750600160581b6001600160581b03196130f583613891565b16036130fe5750565b8051909190613117906106ae906001600160a01b031681565b906020830191613128835160ff1690565b90803b156102465760405163bfd151c160e01b815291600091839182908490829061315c9036903490339060048601612f85565b03925af190816131b3575b506131ae575061080861319461318c61317e61209a565b94516001600160a01b031690565b925160ff1690565b92604051938493636d4fdb0960e01b85526004850161288b565b915050565b806129ad6131c09261040d565b38613167565b9050331480156131d8575b1561120157565b503033146131d1565b6131f19083979495969297613b6f565b9290966000965b88518810156133695761321161167b6115a58a8c612858565b801590811561335b575b811561334d575b5061331a579087959493929161324f6106ae6106ae6132418a8e612858565b51516001600160a01b031690565b9561326a8b61326160209c8d92612858565b51015160ff1690565b98873b156102465760409788519063031fb36160e21b8252818060049d8e36903490339085019361329a94612f85565b03815a6000948591f19081613307575b506132f057508a896108088a8a6132da8f6132616132c661209a565b946132d4613241828b612858565b98612858565b90516340b788e360e01b8152948594850161288b565b6001909801995096975093945091929091906131f8565b806129ad6133149261040d565b386132aa565b61080861332c60206132618b8d612858565b6040516314d291c760e21b815260ff90911660048201529081906024820190565b600160591b14905038613222565b600160581b8114915061321b565b95949750929091955061337e61167b82613891565b1561338e579091600101906130a8565b6130b0565b5050565b906133a182611eda565b6040906133b16040519182610477565b83815280936133c2601f1991611eda565b019160005b8381106133d45750505050565b60209082516133e281610440565b60608152826133ef61228c565b818301528286010152016133c7565b6040519061340b82610440565b6060602083600081520152565b9190916006810192600982015491613434600482015484612be8565b92613440600094613397565b90613449613b22565b906000915b81831061347a575b5050506134749495506134676133fe565b9384526020840152613c69565b91908252565b61348d9089989598979692939497613b6f565b92909860005b8a518110156134c857806134a96001928d612858565b5160206134bf6134b88c612b10565b9b8d612858565b51015201613493565b5098509196939695929094956134e061167b82613891565b156134f1576001909101919061344e565b613456565b9092916006820193600983015492613512600482015485612be8565b9361351e600095613397565b90613527613b22565b906000915b818310613552575b5050506134749596506135456133fe565b9485526020850152613dea565b613565908a99969294979395989a613b6f565b93909860005b8a518110156135aa57808b9c602061359c61358b8d9e9f95600196612858565b519261359681612b10565b9d612858565b510152019a9998979a61356b565b50999794919598509195926135c161167b82613891565b156135d2576001909101919061352c565b613534565b600091829182602083519301915af13d6040519160208284010160405281835260208301916000833e15613609575090565b905190fd5b916000928392602083519301915af13d6040519160208284010160405281835260208301916000833e15613609575090565b81519190604183036136715761366a92506020820151906060604084015193015160001a90613f73565b9192909190565b505060009160029190565b6040519061368982610425565b60006040838281528260208201520152565b916136a461367c565b506136ad610498565b906000908183526020906136c882850165ffffffffffff9052565b60409383604082015295600560028201910154906136e4613b22565b906136ed61228c565b5085915b838310613705575b50505050505050505090565b61371890829b949a95969798999b613b6f565b99909488905b86518210156138655761373761167b6115a5848a612858565b8015908115613857575b8115613849575b5061381757906137988b93928a8f8a8c918f61377b856132618a6137756106ae6106ae613241848b612858565b96612858565b995180978195829463056ddae160e21b845260049d8e85016126d4565b03925af19081156107dc576137b4928d926137f8575b506138b8565b808c01519093906001600160a01b031680151590816137ec575b506137de5750600101909161371e565b8b516310b1cc1760e31b8152fd5b600191501415386137ce565b6138109192508c8d3d106107d5576107c78183610477565b90386137ae565b6108088b6138298b613261868c612858565b905163520c50ef60e01b815260ff90911660048201529081906024820190565b600160591b14905038613748565b600160581b81149150613741565b9a91949b9998979695505061387c61167b82613891565b1561388c576001909201916136f1565b6136f9565b6bffffffffffffffffffffffff19815160601b1690602060ff60581b91015160581b161790565b6138c96138c361367c565b92613ff7565b906138da815165ffffffffffff1690565b9160208201916138fe6138f3845165ffffffffffff1690565b65ffffffffffff1690565b65ffffffffffff80951611613a3557815165ffffffffffff16916020810192856139316138f3865165ffffffffffff1690565b911611613a355760408201516001600160a01b031680613a2257506040818101516001600160a01b0316908701525b613980613973835165ffffffffffff1690565b915165ffffffffffff1690565b908582169086161115613a1257505165ffffffffffff1684525b6139ad613973835165ffffffffffff1690565b9083821690841610156139ff57505165ffffffffffff1660208301525b815165ffffffffffff16906139eb6138f3602085015165ffffffffffff1690565b9116116139f55790565b6001604082015290565b65ffffffffffff166020840152506139ca565b65ffffffffffff1685525061399a565b6001600160a01b03166040870152613960565b60405163a45d8f5360e01b8152600490fd5b6040519060208083018160006301ffc9a760e01b9586845286602482015260248152613a7281610425565b51617530938685fa933d6000519086613b17575b5085613b0d575b5084613aaa575b50505081613aa0575090565b6105129150614049565b83945090600091839460405185810192835263ffffffff60e01b602482015260248152613ad681610425565b5192fa60005190913d83613b02575b505081613af8575b501590388080613a94565b9050151538613aed565b101591503880613ae5565b1515945038613a8d565b841115955038613a86565b613b2a61228c565b50604051613b3781610440565b600081526000602082015290565b613b4d61228c565b5060ff60405191613b5d83610440565b8060601c835260581c16602082015290565b9190613b8390613b7d61228c565b50613891565b60405192613b908461045b565b600a92600a855260005b6101408110613c5257506001600160581b031980841615613c39575b6000935b85851080613c2e575b15613c1e57613c12613c0b82613bdb613c1894613b45565b613be5898c612858565b52613bf0888b612858565b5086906001600160581b031916600052602052604060002090565b5460581b90565b94612b10565b93613bba565b9250509250610512918452613b45565b508181161515613bc3565b9250600080528160205260406000205460581b92613bb6565b602090613c5d61228c565b82828901015201613b9a565b929192613c74613b22565b916003820154926000905b848210613c96575b50505050506020825192015190565b613ca39084979597613b6f565b909660005b8851811015613dc557613cbe6115a5828b612858565b6001600160581b031981168015908115613db7575b8115613da9575b50613d9757613d176115c5613cf988613cf3868f612858565b516141ab565b9260058a01906001600160581b031916600052602052604060002090565b8051613d28575b5050600101613ca8565b95919893999490969260005b8751811015613d83578089613d6f8c613d4f6001958d612858565b516020613d63818401938451905190612858565b510152518d5190612858565b5152613d7b8b51612b10565b8b5201613d34565b509296509398929760019195509038613d1e565b61080861332c6020613261858e612858565b600160591b14905038613cda565b600160581b81149150613cd3565b50949650613dd561167b82613891565b15613de557600190910190613c7f565b613c87565b90939293613df6613b22565b926003830154936000905b858210613e19575b5050505050506020825192015190565b613e269085989698613b6f565b909760005b8951811015613f4e57613e416115a5828c612858565b6001600160581b031981168015908115613f40575b8115613f32575b50613f2057613e9c6115c5613e7e888a8f87613e7891612858565b51614265565b9260058b01906001600160581b031916600052602052604060002090565b8051613ead575b5050600101613e2b565b969260009b96929a959198949b5b8851811015613f0b57808a613ef78d613ed66001958e612858565b5160209081830191613eeb8351855190612858565b51015251905190612858565b5152613f038c51612b10565b8c5201613ebb565b509296509398600191959a9397509038613ea3565b61080861332c6020613261858f612858565b600160591b14905038613e5d565b600160581b81149150613e56565b50959750613f5e61167b82613891565b15613f6e57600190910190613e01565b613e09565b91907f7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a08411613feb57926020929160ff608095604051948552168484015260408301526060820152600092839182805260015afa156107dc5780516001600160a01b03811615613fe257918190565b50809160019190565b50505060009160039190565b613fff61367c565b5065ffffffffffff90818160a01c16918215614041575b6040519261402384610425565b60d083901c84521660208301526001600160a01b0316604082015290565b915081614016565b6000602091604051838101906301ffc9a760e01b825263043140ed60e01b60248201526024815261407981610425565b5191617530fa6000513d8261409a575b5081614093575090565b9050151590565b60201115915038614089565b90813b1561412c5760008051602061435483398151915280546001600160a01b0319166001600160a01b0384169081179091557fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b600080a28051156141115761410e916142b7565b50565b50503461411a57565b60405163b398979f60e01b8152600490fd5b604051634c9c8ce360e01b81526001600160a01b0383166004820152602490fd5b602081830312610246578051906001600160401b038211610246570181601f8201121561024657805161417f816104a5565b9261418d6040519485610477565b81845260208284010111610246576105129160208085019101610909565b80519092906141fb906000906141c9906001600160a01b03166106ae565b9360208601946141da865160ff1690565b8360405180968195829463236b075960e11b84523490339060048601612fca565b03925af160009181614240575b5061423a57505061080861422061318c61317e61209a565b92604051938493636d1fbba160e11b85526004850161288b565b92509050565b61425e9192503d806000833e6142568183610477565b81019061414d565b9038614208565b8051909391926141fb9160009190614285906001600160a01b03166106ae565b602087019583614296885160ff1690565b60405163236b075960e11b8152968795869485933490339060048701613013565b60008061051293602081519101845af46142cf61209a565b91906142f757508051156142e557805190602001fd5b604051630a12f52160e11b8152600490fd5b8151158061432a575b614308575090565b604051639996b31560e01b81526001600160a01b039091166004820152602490fd5b50803b1561430056fec6a0cc20c824c4eecc4b0fbb7fb297d07492a7bd12c83d4fa4d27b4249f9bfd0360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbca26469706673582212205a9a85242aa970e489811f6060c279665f03704115dd4a5d1381a7a7aa57eed364736f6c63430008180033",
}

// SingleOwnerMSCAABI is the input ABI used to generate the binding from.
// Deprecated: Use SingleOwnerMSCAMetaData.ABI instead.
var SingleOwnerMSCAABI = SingleOwnerMSCAMetaData.ABI

// SingleOwnerMSCABin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use SingleOwnerMSCAMetaData.Bin instead.
var SingleOwnerMSCABin = SingleOwnerMSCAMetaData.Bin

// DeploySingleOwnerMSCA deploys a new Ethereum contract, binding an instance of SingleOwnerMSCA to it.
func DeploySingleOwnerMSCA(auth *bind.TransactOpts, backend bind.ContractBackend, _newEntryPoint common.Address, _newPluginManager common.Address) (common.Address, *types.Transaction, *SingleOwnerMSCA, error) {
	parsed, err := SingleOwnerMSCAMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(SingleOwnerMSCABin), backend, _newEntryPoint, _newPluginManager)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &SingleOwnerMSCA{SingleOwnerMSCACaller: SingleOwnerMSCACaller{contract: contract}, SingleOwnerMSCATransactor: SingleOwnerMSCATransactor{contract: contract}, SingleOwnerMSCAFilterer: SingleOwnerMSCAFilterer{contract: contract}}, nil
}

// SingleOwnerMSCA is an auto generated Go binding around an Ethereum contract.
type SingleOwnerMSCA struct {
	SingleOwnerMSCACaller     // Read-only binding to the contract
	SingleOwnerMSCATransactor // Write-only binding to the contract
	SingleOwnerMSCAFilterer   // Log filterer for contract events
}

// SingleOwnerMSCACaller is an auto generated read-only Go binding around an Ethereum contract.
type SingleOwnerMSCACaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SingleOwnerMSCATransactor is an auto generated write-only Go binding around an Ethereum contract.
type SingleOwnerMSCATransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SingleOwnerMSCAFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type SingleOwnerMSCAFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SingleOwnerMSCASession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type SingleOwnerMSCASession struct {
	Contract     *SingleOwnerMSCA  // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// SingleOwnerMSCACallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type SingleOwnerMSCACallerSession struct {
	Contract *SingleOwnerMSCACaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts          // Call options to use throughout this session
}

// SingleOwnerMSCATransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type SingleOwnerMSCATransactorSession struct {
	Contract     *SingleOwnerMSCATransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts          // Transaction auth options to use throughout this session
}

// SingleOwnerMSCARaw is an auto generated low-level Go binding around an Ethereum contract.
type SingleOwnerMSCARaw struct {
	Contract *SingleOwnerMSCA // Generic contract binding to access the raw methods on
}

// SingleOwnerMSCACallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type SingleOwnerMSCACallerRaw struct {
	Contract *SingleOwnerMSCACaller // Generic read-only contract binding to access the raw methods on
}

// SingleOwnerMSCATransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type SingleOwnerMSCATransactorRaw struct {
	Contract *SingleOwnerMSCATransactor // Generic write-only contract binding to access the raw methods on
}

// NewSingleOwnerMSCA creates a new instance of SingleOwnerMSCA, bound to a specific deployed contract.
func NewSingleOwnerMSCA(address common.Address, backend bind.ContractBackend) (*SingleOwnerMSCA, error) {
	contract, err := bindSingleOwnerMSCA(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &SingleOwnerMSCA{SingleOwnerMSCACaller: SingleOwnerMSCACaller{contract: contract}, SingleOwnerMSCATransactor: SingleOwnerMSCATransactor{contract: contract}, SingleOwnerMSCAFilterer: SingleOwnerMSCAFilterer{contract: contract}}, nil
}

// NewSingleOwnerMSCACaller creates a new read-only instance of SingleOwnerMSCA, bound to a specific deployed contract.
func NewSingleOwnerMSCACaller(address common.Address, caller bind.ContractCaller) (*SingleOwnerMSCACaller, error) {
	contract, err := bindSingleOwnerMSCA(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &SingleOwnerMSCACaller{contract: contract}, nil
}

// NewSingleOwnerMSCATransactor creates a new write-only instance of SingleOwnerMSCA, bound to a specific deployed contract.
func NewSingleOwnerMSCATransactor(address common.Address, transactor bind.ContractTransactor) (*SingleOwnerMSCATransactor, error) {
	contract, err := bindSingleOwnerMSCA(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &SingleOwnerMSCATransactor{contract: contract}, nil
}

// NewSingleOwnerMSCAFilterer creates a new log filterer instance of SingleOwnerMSCA, bound to a specific deployed contract.
func NewSingleOwnerMSCAFilterer(address common.Address, filterer bind.ContractFilterer) (*SingleOwnerMSCAFilterer, error) {
	contract, err := bindSingleOwnerMSCA(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &SingleOwnerMSCAFilterer{contract: contract}, nil
}

// bindSingleOwnerMSCA binds a generic wrapper to an already deployed contract.
func bindSingleOwnerMSCA(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := SingleOwnerMSCAMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_SingleOwnerMSCA *SingleOwnerMSCARaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _SingleOwnerMSCA.Contract.SingleOwnerMSCACaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_SingleOwnerMSCA *SingleOwnerMSCARaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.SingleOwnerMSCATransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_SingleOwnerMSCA *SingleOwnerMSCARaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.SingleOwnerMSCATransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_SingleOwnerMSCA *SingleOwnerMSCACallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _SingleOwnerMSCA.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_SingleOwnerMSCA *SingleOwnerMSCATransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_SingleOwnerMSCA *SingleOwnerMSCATransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.contract.Transact(opts, method, params...)
}

// UPGRADEINTERFACEVERSION is a free data retrieval call binding the contract method 0xad3cb1cc.
//
// Solidity: function UPGRADE_INTERFACE_VERSION() view returns(string)
func (_SingleOwnerMSCA *SingleOwnerMSCACaller) UPGRADEINTERFACEVERSION(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _SingleOwnerMSCA.contract.Call(opts, &out, "UPGRADE_INTERFACE_VERSION")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// UPGRADEINTERFACEVERSION is a free data retrieval call binding the contract method 0xad3cb1cc.
//
// Solidity: function UPGRADE_INTERFACE_VERSION() view returns(string)
func (_SingleOwnerMSCA *SingleOwnerMSCASession) UPGRADEINTERFACEVERSION() (string, error) {
	return _SingleOwnerMSCA.Contract.UPGRADEINTERFACEVERSION(&_SingleOwnerMSCA.CallOpts)
}

// UPGRADEINTERFACEVERSION is a free data retrieval call binding the contract method 0xad3cb1cc.
//
// Solidity: function UPGRADE_INTERFACE_VERSION() view returns(string)
func (_SingleOwnerMSCA *SingleOwnerMSCACallerSession) UPGRADEINTERFACEVERSION() (string, error) {
	return _SingleOwnerMSCA.Contract.UPGRADEINTERFACEVERSION(&_SingleOwnerMSCA.CallOpts)
}

// Author is a free data retrieval call binding the contract method 0xa6c3e6b9.
//
// Solidity: function author() view returns(string)
func (_SingleOwnerMSCA *SingleOwnerMSCACaller) Author(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _SingleOwnerMSCA.contract.Call(opts, &out, "author")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// Author is a free data retrieval call binding the contract method 0xa6c3e6b9.
//
// Solidity: function author() view returns(string)
func (_SingleOwnerMSCA *SingleOwnerMSCASession) Author() (string, error) {
	return _SingleOwnerMSCA.Contract.Author(&_SingleOwnerMSCA.CallOpts)
}

// Author is a free data retrieval call binding the contract method 0xa6c3e6b9.
//
// Solidity: function author() view returns(string)
func (_SingleOwnerMSCA *SingleOwnerMSCACallerSession) Author() (string, error) {
	return _SingleOwnerMSCA.Contract.Author(&_SingleOwnerMSCA.CallOpts)
}

// EntryPoint is a free data retrieval call binding the contract method 0xb0d691fe.
//
// Solidity: function entryPoint() view returns(address)
func (_SingleOwnerMSCA *SingleOwnerMSCACaller) EntryPoint(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _SingleOwnerMSCA.contract.Call(opts, &out, "entryPoint")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// EntryPoint is a free data retrieval call binding the contract method 0xb0d691fe.
//
// Solidity: function entryPoint() view returns(address)
func (_SingleOwnerMSCA *SingleOwnerMSCASession) EntryPoint() (common.Address, error) {
	return _SingleOwnerMSCA.Contract.EntryPoint(&_SingleOwnerMSCA.CallOpts)
}

// EntryPoint is a free data retrieval call binding the contract method 0xb0d691fe.
//
// Solidity: function entryPoint() view returns(address)
func (_SingleOwnerMSCA *SingleOwnerMSCACallerSession) EntryPoint() (common.Address, error) {
	return _SingleOwnerMSCA.Contract.EntryPoint(&_SingleOwnerMSCA.CallOpts)
}

// GetDeposit is a free data retrieval call binding the contract method 0xc399ec88.
//
// Solidity: function getDeposit() view returns(uint256)
func (_SingleOwnerMSCA *SingleOwnerMSCACaller) GetDeposit(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _SingleOwnerMSCA.contract.Call(opts, &out, "getDeposit")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetDeposit is a free data retrieval call binding the contract method 0xc399ec88.
//
// Solidity: function getDeposit() view returns(uint256)
func (_SingleOwnerMSCA *SingleOwnerMSCASession) GetDeposit() (*big.Int, error) {
	return _SingleOwnerMSCA.Contract.GetDeposit(&_SingleOwnerMSCA.CallOpts)
}

// GetDeposit is a free data retrieval call binding the contract method 0xc399ec88.
//
// Solidity: function getDeposit() view returns(uint256)
func (_SingleOwnerMSCA *SingleOwnerMSCACallerSession) GetDeposit() (*big.Int, error) {
	return _SingleOwnerMSCA.Contract.GetDeposit(&_SingleOwnerMSCA.CallOpts)
}

// GetEntryPoint is a free data retrieval call binding the contract method 0x44ab613f.
//
// Solidity: function getEntryPoint() view returns(address)
func (_SingleOwnerMSCA *SingleOwnerMSCACaller) GetEntryPoint(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _SingleOwnerMSCA.contract.Call(opts, &out, "getEntryPoint")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetEntryPoint is a free data retrieval call binding the contract method 0x44ab613f.
//
// Solidity: function getEntryPoint() view returns(address)
func (_SingleOwnerMSCA *SingleOwnerMSCASession) GetEntryPoint() (common.Address, error) {
	return _SingleOwnerMSCA.Contract.GetEntryPoint(&_SingleOwnerMSCA.CallOpts)
}

// GetEntryPoint is a free data retrieval call binding the contract method 0x44ab613f.
//
// Solidity: function getEntryPoint() view returns(address)
func (_SingleOwnerMSCA *SingleOwnerMSCACallerSession) GetEntryPoint() (common.Address, error) {
	return _SingleOwnerMSCA.Contract.GetEntryPoint(&_SingleOwnerMSCA.CallOpts)
}

// GetExecutionFunctionConfig is a free data retrieval call binding the contract method 0x8d112184.
//
// Solidity: function getExecutionFunctionConfig(bytes4 selector) view returns((address,(address,uint8),(address,uint8)) executionFunctionConfig)
func (_SingleOwnerMSCA *SingleOwnerMSCACaller) GetExecutionFunctionConfig(opts *bind.CallOpts, selector [4]byte) (ExecutionFunctionConfig, error) {
	var out []interface{}
	err := _SingleOwnerMSCA.contract.Call(opts, &out, "getExecutionFunctionConfig", selector)

	if err != nil {
		return *new(ExecutionFunctionConfig), err
	}

	out0 := *abi.ConvertType(out[0], new(ExecutionFunctionConfig)).(*ExecutionFunctionConfig)

	return out0, err

}

// GetExecutionFunctionConfig is a free data retrieval call binding the contract method 0x8d112184.
//
// Solidity: function getExecutionFunctionConfig(bytes4 selector) view returns((address,(address,uint8),(address,uint8)) executionFunctionConfig)
func (_SingleOwnerMSCA *SingleOwnerMSCASession) GetExecutionFunctionConfig(selector [4]byte) (ExecutionFunctionConfig, error) {
	return _SingleOwnerMSCA.Contract.GetExecutionFunctionConfig(&_SingleOwnerMSCA.CallOpts, selector)
}

// GetExecutionFunctionConfig is a free data retrieval call binding the contract method 0x8d112184.
//
// Solidity: function getExecutionFunctionConfig(bytes4 selector) view returns((address,(address,uint8),(address,uint8)) executionFunctionConfig)
func (_SingleOwnerMSCA *SingleOwnerMSCACallerSession) GetExecutionFunctionConfig(selector [4]byte) (ExecutionFunctionConfig, error) {
	return _SingleOwnerMSCA.Contract.GetExecutionFunctionConfig(&_SingleOwnerMSCA.CallOpts, selector)
}

// GetExecutionHooks is a free data retrieval call binding the contract method 0x642f9dd4.
//
// Solidity: function getExecutionHooks(bytes4 selector) view returns(((address,uint8),(address,uint8))[] executionHooks)
func (_SingleOwnerMSCA *SingleOwnerMSCACaller) GetExecutionHooks(opts *bind.CallOpts, selector [4]byte) ([]ExecutionHooks, error) {
	var out []interface{}
	err := _SingleOwnerMSCA.contract.Call(opts, &out, "getExecutionHooks", selector)

	if err != nil {
		return *new([]ExecutionHooks), err
	}

	out0 := *abi.ConvertType(out[0], new([]ExecutionHooks)).(*[]ExecutionHooks)

	return out0, err

}

// GetExecutionHooks is a free data retrieval call binding the contract method 0x642f9dd4.
//
// Solidity: function getExecutionHooks(bytes4 selector) view returns(((address,uint8),(address,uint8))[] executionHooks)
func (_SingleOwnerMSCA *SingleOwnerMSCASession) GetExecutionHooks(selector [4]byte) ([]ExecutionHooks, error) {
	return _SingleOwnerMSCA.Contract.GetExecutionHooks(&_SingleOwnerMSCA.CallOpts, selector)
}

// GetExecutionHooks is a free data retrieval call binding the contract method 0x642f9dd4.
//
// Solidity: function getExecutionHooks(bytes4 selector) view returns(((address,uint8),(address,uint8))[] executionHooks)
func (_SingleOwnerMSCA *SingleOwnerMSCACallerSession) GetExecutionHooks(selector [4]byte) ([]ExecutionHooks, error) {
	return _SingleOwnerMSCA.Contract.GetExecutionHooks(&_SingleOwnerMSCA.CallOpts, selector)
}

// GetInstalledPlugins is a free data retrieval call binding the contract method 0x3a0cac56.
//
// Solidity: function getInstalledPlugins() view returns(address[] pluginAddresses)
func (_SingleOwnerMSCA *SingleOwnerMSCACaller) GetInstalledPlugins(opts *bind.CallOpts) ([]common.Address, error) {
	var out []interface{}
	err := _SingleOwnerMSCA.contract.Call(opts, &out, "getInstalledPlugins")

	if err != nil {
		return *new([]common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new([]common.Address)).(*[]common.Address)

	return out0, err

}

// GetInstalledPlugins is a free data retrieval call binding the contract method 0x3a0cac56.
//
// Solidity: function getInstalledPlugins() view returns(address[] pluginAddresses)
func (_SingleOwnerMSCA *SingleOwnerMSCASession) GetInstalledPlugins() ([]common.Address, error) {
	return _SingleOwnerMSCA.Contract.GetInstalledPlugins(&_SingleOwnerMSCA.CallOpts)
}

// GetInstalledPlugins is a free data retrieval call binding the contract method 0x3a0cac56.
//
// Solidity: function getInstalledPlugins() view returns(address[] pluginAddresses)
func (_SingleOwnerMSCA *SingleOwnerMSCACallerSession) GetInstalledPlugins() ([]common.Address, error) {
	return _SingleOwnerMSCA.Contract.GetInstalledPlugins(&_SingleOwnerMSCA.CallOpts)
}

// GetNativeOwner is a free data retrieval call binding the contract method 0x66b46a7a.
//
// Solidity: function getNativeOwner() view returns(address)
func (_SingleOwnerMSCA *SingleOwnerMSCACaller) GetNativeOwner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _SingleOwnerMSCA.contract.Call(opts, &out, "getNativeOwner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetNativeOwner is a free data retrieval call binding the contract method 0x66b46a7a.
//
// Solidity: function getNativeOwner() view returns(address)
func (_SingleOwnerMSCA *SingleOwnerMSCASession) GetNativeOwner() (common.Address, error) {
	return _SingleOwnerMSCA.Contract.GetNativeOwner(&_SingleOwnerMSCA.CallOpts)
}

// GetNativeOwner is a free data retrieval call binding the contract method 0x66b46a7a.
//
// Solidity: function getNativeOwner() view returns(address)
func (_SingleOwnerMSCA *SingleOwnerMSCACallerSession) GetNativeOwner() (common.Address, error) {
	return _SingleOwnerMSCA.Contract.GetNativeOwner(&_SingleOwnerMSCA.CallOpts)
}

// GetNonce is a free data retrieval call binding the contract method 0xd087d288.
//
// Solidity: function getNonce() view returns(uint256)
func (_SingleOwnerMSCA *SingleOwnerMSCACaller) GetNonce(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _SingleOwnerMSCA.contract.Call(opts, &out, "getNonce")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetNonce is a free data retrieval call binding the contract method 0xd087d288.
//
// Solidity: function getNonce() view returns(uint256)
func (_SingleOwnerMSCA *SingleOwnerMSCASession) GetNonce() (*big.Int, error) {
	return _SingleOwnerMSCA.Contract.GetNonce(&_SingleOwnerMSCA.CallOpts)
}

// GetNonce is a free data retrieval call binding the contract method 0xd087d288.
//
// Solidity: function getNonce() view returns(uint256)
func (_SingleOwnerMSCA *SingleOwnerMSCACallerSession) GetNonce() (*big.Int, error) {
	return _SingleOwnerMSCA.Contract.GetNonce(&_SingleOwnerMSCA.CallOpts)
}

// GetPreValidationHooks is a free data retrieval call binding the contract method 0xceaf1309.
//
// Solidity: function getPreValidationHooks(bytes4 selector) view returns((address,uint8)[] preUserOpValidationHooks, (address,uint8)[] preRuntimeValidationHooks)
func (_SingleOwnerMSCA *SingleOwnerMSCACaller) GetPreValidationHooks(opts *bind.CallOpts, selector [4]byte) (struct {
	PreUserOpValidationHooks  []FunctionReference
	PreRuntimeValidationHooks []FunctionReference
}, error) {
	var out []interface{}
	err := _SingleOwnerMSCA.contract.Call(opts, &out, "getPreValidationHooks", selector)

	outstruct := new(struct {
		PreUserOpValidationHooks  []FunctionReference
		PreRuntimeValidationHooks []FunctionReference
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.PreUserOpValidationHooks = *abi.ConvertType(out[0], new([]FunctionReference)).(*[]FunctionReference)
	outstruct.PreRuntimeValidationHooks = *abi.ConvertType(out[1], new([]FunctionReference)).(*[]FunctionReference)

	return *outstruct, err

}

// GetPreValidationHooks is a free data retrieval call binding the contract method 0xceaf1309.
//
// Solidity: function getPreValidationHooks(bytes4 selector) view returns((address,uint8)[] preUserOpValidationHooks, (address,uint8)[] preRuntimeValidationHooks)
func (_SingleOwnerMSCA *SingleOwnerMSCASession) GetPreValidationHooks(selector [4]byte) (struct {
	PreUserOpValidationHooks  []FunctionReference
	PreRuntimeValidationHooks []FunctionReference
}, error) {
	return _SingleOwnerMSCA.Contract.GetPreValidationHooks(&_SingleOwnerMSCA.CallOpts, selector)
}

// GetPreValidationHooks is a free data retrieval call binding the contract method 0xceaf1309.
//
// Solidity: function getPreValidationHooks(bytes4 selector) view returns((address,uint8)[] preUserOpValidationHooks, (address,uint8)[] preRuntimeValidationHooks)
func (_SingleOwnerMSCA *SingleOwnerMSCACallerSession) GetPreValidationHooks(selector [4]byte) (struct {
	PreUserOpValidationHooks  []FunctionReference
	PreRuntimeValidationHooks []FunctionReference
}, error) {
	return _SingleOwnerMSCA.Contract.GetPreValidationHooks(&_SingleOwnerMSCA.CallOpts, selector)
}

// IsValidSignature is a free data retrieval call binding the contract method 0x1626ba7e.
//
// Solidity: function isValidSignature(bytes32 hash, bytes signature) view returns(bytes4)
func (_SingleOwnerMSCA *SingleOwnerMSCACaller) IsValidSignature(opts *bind.CallOpts, hash [32]byte, signature []byte) ([4]byte, error) {
	var out []interface{}
	err := _SingleOwnerMSCA.contract.Call(opts, &out, "isValidSignature", hash, signature)

	if err != nil {
		return *new([4]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([4]byte)).(*[4]byte)

	return out0, err

}

// IsValidSignature is a free data retrieval call binding the contract method 0x1626ba7e.
//
// Solidity: function isValidSignature(bytes32 hash, bytes signature) view returns(bytes4)
func (_SingleOwnerMSCA *SingleOwnerMSCASession) IsValidSignature(hash [32]byte, signature []byte) ([4]byte, error) {
	return _SingleOwnerMSCA.Contract.IsValidSignature(&_SingleOwnerMSCA.CallOpts, hash, signature)
}

// IsValidSignature is a free data retrieval call binding the contract method 0x1626ba7e.
//
// Solidity: function isValidSignature(bytes32 hash, bytes signature) view returns(bytes4)
func (_SingleOwnerMSCA *SingleOwnerMSCACallerSession) IsValidSignature(hash [32]byte, signature []byte) ([4]byte, error) {
	return _SingleOwnerMSCA.Contract.IsValidSignature(&_SingleOwnerMSCA.CallOpts, hash, signature)
}

// OnERC1155BatchReceived is a free data retrieval call binding the contract method 0xbc197c81.
//
// Solidity: function onERC1155BatchReceived(address , address , uint256[] , uint256[] , bytes ) pure returns(bytes4)
func (_SingleOwnerMSCA *SingleOwnerMSCACaller) OnERC1155BatchReceived(opts *bind.CallOpts, arg0 common.Address, arg1 common.Address, arg2 []*big.Int, arg3 []*big.Int, arg4 []byte) ([4]byte, error) {
	var out []interface{}
	err := _SingleOwnerMSCA.contract.Call(opts, &out, "onERC1155BatchReceived", arg0, arg1, arg2, arg3, arg4)

	if err != nil {
		return *new([4]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([4]byte)).(*[4]byte)

	return out0, err

}

// OnERC1155BatchReceived is a free data retrieval call binding the contract method 0xbc197c81.
//
// Solidity: function onERC1155BatchReceived(address , address , uint256[] , uint256[] , bytes ) pure returns(bytes4)
func (_SingleOwnerMSCA *SingleOwnerMSCASession) OnERC1155BatchReceived(arg0 common.Address, arg1 common.Address, arg2 []*big.Int, arg3 []*big.Int, arg4 []byte) ([4]byte, error) {
	return _SingleOwnerMSCA.Contract.OnERC1155BatchReceived(&_SingleOwnerMSCA.CallOpts, arg0, arg1, arg2, arg3, arg4)
}

// OnERC1155BatchReceived is a free data retrieval call binding the contract method 0xbc197c81.
//
// Solidity: function onERC1155BatchReceived(address , address , uint256[] , uint256[] , bytes ) pure returns(bytes4)
func (_SingleOwnerMSCA *SingleOwnerMSCACallerSession) OnERC1155BatchReceived(arg0 common.Address, arg1 common.Address, arg2 []*big.Int, arg3 []*big.Int, arg4 []byte) ([4]byte, error) {
	return _SingleOwnerMSCA.Contract.OnERC1155BatchReceived(&_SingleOwnerMSCA.CallOpts, arg0, arg1, arg2, arg3, arg4)
}

// OnERC1155Received is a free data retrieval call binding the contract method 0xf23a6e61.
//
// Solidity: function onERC1155Received(address , address , uint256 , uint256 , bytes ) pure returns(bytes4)
func (_SingleOwnerMSCA *SingleOwnerMSCACaller) OnERC1155Received(opts *bind.CallOpts, arg0 common.Address, arg1 common.Address, arg2 *big.Int, arg3 *big.Int, arg4 []byte) ([4]byte, error) {
	var out []interface{}
	err := _SingleOwnerMSCA.contract.Call(opts, &out, "onERC1155Received", arg0, arg1, arg2, arg3, arg4)

	if err != nil {
		return *new([4]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([4]byte)).(*[4]byte)

	return out0, err

}

// OnERC1155Received is a free data retrieval call binding the contract method 0xf23a6e61.
//
// Solidity: function onERC1155Received(address , address , uint256 , uint256 , bytes ) pure returns(bytes4)
func (_SingleOwnerMSCA *SingleOwnerMSCASession) OnERC1155Received(arg0 common.Address, arg1 common.Address, arg2 *big.Int, arg3 *big.Int, arg4 []byte) ([4]byte, error) {
	return _SingleOwnerMSCA.Contract.OnERC1155Received(&_SingleOwnerMSCA.CallOpts, arg0, arg1, arg2, arg3, arg4)
}

// OnERC1155Received is a free data retrieval call binding the contract method 0xf23a6e61.
//
// Solidity: function onERC1155Received(address , address , uint256 , uint256 , bytes ) pure returns(bytes4)
func (_SingleOwnerMSCA *SingleOwnerMSCACallerSession) OnERC1155Received(arg0 common.Address, arg1 common.Address, arg2 *big.Int, arg3 *big.Int, arg4 []byte) ([4]byte, error) {
	return _SingleOwnerMSCA.Contract.OnERC1155Received(&_SingleOwnerMSCA.CallOpts, arg0, arg1, arg2, arg3, arg4)
}

// OnERC721Received is a free data retrieval call binding the contract method 0x150b7a02.
//
// Solidity: function onERC721Received(address , address , uint256 , bytes ) pure returns(bytes4)
func (_SingleOwnerMSCA *SingleOwnerMSCACaller) OnERC721Received(opts *bind.CallOpts, arg0 common.Address, arg1 common.Address, arg2 *big.Int, arg3 []byte) ([4]byte, error) {
	var out []interface{}
	err := _SingleOwnerMSCA.contract.Call(opts, &out, "onERC721Received", arg0, arg1, arg2, arg3)

	if err != nil {
		return *new([4]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([4]byte)).(*[4]byte)

	return out0, err

}

// OnERC721Received is a free data retrieval call binding the contract method 0x150b7a02.
//
// Solidity: function onERC721Received(address , address , uint256 , bytes ) pure returns(bytes4)
func (_SingleOwnerMSCA *SingleOwnerMSCASession) OnERC721Received(arg0 common.Address, arg1 common.Address, arg2 *big.Int, arg3 []byte) ([4]byte, error) {
	return _SingleOwnerMSCA.Contract.OnERC721Received(&_SingleOwnerMSCA.CallOpts, arg0, arg1, arg2, arg3)
}

// OnERC721Received is a free data retrieval call binding the contract method 0x150b7a02.
//
// Solidity: function onERC721Received(address , address , uint256 , bytes ) pure returns(bytes4)
func (_SingleOwnerMSCA *SingleOwnerMSCACallerSession) OnERC721Received(arg0 common.Address, arg1 common.Address, arg2 *big.Int, arg3 []byte) ([4]byte, error) {
	return _SingleOwnerMSCA.Contract.OnERC721Received(&_SingleOwnerMSCA.CallOpts, arg0, arg1, arg2, arg3)
}

// PluginManager is a free data retrieval call binding the contract method 0x2e0e0bae.
//
// Solidity: function pluginManager() view returns(address)
func (_SingleOwnerMSCA *SingleOwnerMSCACaller) PluginManager(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _SingleOwnerMSCA.contract.Call(opts, &out, "pluginManager")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// PluginManager is a free data retrieval call binding the contract method 0x2e0e0bae.
//
// Solidity: function pluginManager() view returns(address)
func (_SingleOwnerMSCA *SingleOwnerMSCASession) PluginManager() (common.Address, error) {
	return _SingleOwnerMSCA.Contract.PluginManager(&_SingleOwnerMSCA.CallOpts)
}

// PluginManager is a free data retrieval call binding the contract method 0x2e0e0bae.
//
// Solidity: function pluginManager() view returns(address)
func (_SingleOwnerMSCA *SingleOwnerMSCACallerSession) PluginManager() (common.Address, error) {
	return _SingleOwnerMSCA.Contract.PluginManager(&_SingleOwnerMSCA.CallOpts)
}

// ProxiableUUID is a free data retrieval call binding the contract method 0x52d1902d.
//
// Solidity: function proxiableUUID() view returns(bytes32)
func (_SingleOwnerMSCA *SingleOwnerMSCACaller) ProxiableUUID(opts *bind.CallOpts) ([32]byte, error) {
	var out []interface{}
	err := _SingleOwnerMSCA.contract.Call(opts, &out, "proxiableUUID")

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// ProxiableUUID is a free data retrieval call binding the contract method 0x52d1902d.
//
// Solidity: function proxiableUUID() view returns(bytes32)
func (_SingleOwnerMSCA *SingleOwnerMSCASession) ProxiableUUID() ([32]byte, error) {
	return _SingleOwnerMSCA.Contract.ProxiableUUID(&_SingleOwnerMSCA.CallOpts)
}

// ProxiableUUID is a free data retrieval call binding the contract method 0x52d1902d.
//
// Solidity: function proxiableUUID() view returns(bytes32)
func (_SingleOwnerMSCA *SingleOwnerMSCACallerSession) ProxiableUUID() ([32]byte, error) {
	return _SingleOwnerMSCA.Contract.ProxiableUUID(&_SingleOwnerMSCA.CallOpts)
}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_SingleOwnerMSCA *SingleOwnerMSCACaller) SupportsInterface(opts *bind.CallOpts, interfaceId [4]byte) (bool, error) {
	var out []interface{}
	err := _SingleOwnerMSCA.contract.Call(opts, &out, "supportsInterface", interfaceId)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_SingleOwnerMSCA *SingleOwnerMSCASession) SupportsInterface(interfaceId [4]byte) (bool, error) {
	return _SingleOwnerMSCA.Contract.SupportsInterface(&_SingleOwnerMSCA.CallOpts, interfaceId)
}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_SingleOwnerMSCA *SingleOwnerMSCACallerSession) SupportsInterface(interfaceId [4]byte) (bool, error) {
	return _SingleOwnerMSCA.Contract.SupportsInterface(&_SingleOwnerMSCA.CallOpts, interfaceId)
}

// TokensReceived is a free data retrieval call binding the contract method 0x0023de29.
//
// Solidity: function tokensReceived(address operator, address from, address to, uint256 amount, bytes userData, bytes operatorData) pure returns()
func (_SingleOwnerMSCA *SingleOwnerMSCACaller) TokensReceived(opts *bind.CallOpts, operator common.Address, from common.Address, to common.Address, amount *big.Int, userData []byte, operatorData []byte) error {
	var out []interface{}
	err := _SingleOwnerMSCA.contract.Call(opts, &out, "tokensReceived", operator, from, to, amount, userData, operatorData)

	if err != nil {
		return err
	}

	return err

}

// TokensReceived is a free data retrieval call binding the contract method 0x0023de29.
//
// Solidity: function tokensReceived(address operator, address from, address to, uint256 amount, bytes userData, bytes operatorData) pure returns()
func (_SingleOwnerMSCA *SingleOwnerMSCASession) TokensReceived(operator common.Address, from common.Address, to common.Address, amount *big.Int, userData []byte, operatorData []byte) error {
	return _SingleOwnerMSCA.Contract.TokensReceived(&_SingleOwnerMSCA.CallOpts, operator, from, to, amount, userData, operatorData)
}

// TokensReceived is a free data retrieval call binding the contract method 0x0023de29.
//
// Solidity: function tokensReceived(address operator, address from, address to, uint256 amount, bytes userData, bytes operatorData) pure returns()
func (_SingleOwnerMSCA *SingleOwnerMSCACallerSession) TokensReceived(operator common.Address, from common.Address, to common.Address, amount *big.Int, userData []byte, operatorData []byte) error {
	return _SingleOwnerMSCA.Contract.TokensReceived(&_SingleOwnerMSCA.CallOpts, operator, from, to, amount, userData, operatorData)
}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(string)
func (_SingleOwnerMSCA *SingleOwnerMSCACaller) Version(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _SingleOwnerMSCA.contract.Call(opts, &out, "version")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(string)
func (_SingleOwnerMSCA *SingleOwnerMSCASession) Version() (string, error) {
	return _SingleOwnerMSCA.Contract.Version(&_SingleOwnerMSCA.CallOpts)
}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(string)
func (_SingleOwnerMSCA *SingleOwnerMSCACallerSession) Version() (string, error) {
	return _SingleOwnerMSCA.Contract.Version(&_SingleOwnerMSCA.CallOpts)
}

// AddDeposit is a paid mutator transaction binding the contract method 0x4a58db19.
//
// Solidity: function addDeposit() payable returns()
func (_SingleOwnerMSCA *SingleOwnerMSCATransactor) AddDeposit(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SingleOwnerMSCA.contract.Transact(opts, "addDeposit")
}

// AddDeposit is a paid mutator transaction binding the contract method 0x4a58db19.
//
// Solidity: function addDeposit() payable returns()
func (_SingleOwnerMSCA *SingleOwnerMSCASession) AddDeposit() (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.AddDeposit(&_SingleOwnerMSCA.TransactOpts)
}

// AddDeposit is a paid mutator transaction binding the contract method 0x4a58db19.
//
// Solidity: function addDeposit() payable returns()
func (_SingleOwnerMSCA *SingleOwnerMSCATransactorSession) AddDeposit() (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.AddDeposit(&_SingleOwnerMSCA.TransactOpts)
}

// Execute is a paid mutator transaction binding the contract method 0xb61d27f6.
//
// Solidity: function execute(address target, uint256 value, bytes data) payable returns(bytes returnData)
func (_SingleOwnerMSCA *SingleOwnerMSCATransactor) Execute(opts *bind.TransactOpts, target common.Address, value *big.Int, data []byte) (*types.Transaction, error) {
	return _SingleOwnerMSCA.contract.Transact(opts, "execute", target, value, data)
}

// Execute is a paid mutator transaction binding the contract method 0xb61d27f6.
//
// Solidity: function execute(address target, uint256 value, bytes data) payable returns(bytes returnData)
func (_SingleOwnerMSCA *SingleOwnerMSCASession) Execute(target common.Address, value *big.Int, data []byte) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.Execute(&_SingleOwnerMSCA.TransactOpts, target, value, data)
}

// Execute is a paid mutator transaction binding the contract method 0xb61d27f6.
//
// Solidity: function execute(address target, uint256 value, bytes data) payable returns(bytes returnData)
func (_SingleOwnerMSCA *SingleOwnerMSCATransactorSession) Execute(target common.Address, value *big.Int, data []byte) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.Execute(&_SingleOwnerMSCA.TransactOpts, target, value, data)
}

// ExecuteBatch is a paid mutator transaction binding the contract method 0x34fcd5be.
//
// Solidity: function executeBatch((address,uint256,bytes)[] calls) payable returns(bytes[] returnData)
func (_SingleOwnerMSCA *SingleOwnerMSCATransactor) ExecuteBatch(opts *bind.TransactOpts, calls []Call) (*types.Transaction, error) {
	return _SingleOwnerMSCA.contract.Transact(opts, "executeBatch", calls)
}

// ExecuteBatch is a paid mutator transaction binding the contract method 0x34fcd5be.
//
// Solidity: function executeBatch((address,uint256,bytes)[] calls) payable returns(bytes[] returnData)
func (_SingleOwnerMSCA *SingleOwnerMSCASession) ExecuteBatch(calls []Call) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.ExecuteBatch(&_SingleOwnerMSCA.TransactOpts, calls)
}

// ExecuteBatch is a paid mutator transaction binding the contract method 0x34fcd5be.
//
// Solidity: function executeBatch((address,uint256,bytes)[] calls) payable returns(bytes[] returnData)
func (_SingleOwnerMSCA *SingleOwnerMSCATransactorSession) ExecuteBatch(calls []Call) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.ExecuteBatch(&_SingleOwnerMSCA.TransactOpts, calls)
}

// ExecuteFromPlugin is a paid mutator transaction binding the contract method 0x94ed11e7.
//
// Solidity: function executeFromPlugin(bytes data) payable returns(bytes)
func (_SingleOwnerMSCA *SingleOwnerMSCATransactor) ExecuteFromPlugin(opts *bind.TransactOpts, data []byte) (*types.Transaction, error) {
	return _SingleOwnerMSCA.contract.Transact(opts, "executeFromPlugin", data)
}

// ExecuteFromPlugin is a paid mutator transaction binding the contract method 0x94ed11e7.
//
// Solidity: function executeFromPlugin(bytes data) payable returns(bytes)
func (_SingleOwnerMSCA *SingleOwnerMSCASession) ExecuteFromPlugin(data []byte) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.ExecuteFromPlugin(&_SingleOwnerMSCA.TransactOpts, data)
}

// ExecuteFromPlugin is a paid mutator transaction binding the contract method 0x94ed11e7.
//
// Solidity: function executeFromPlugin(bytes data) payable returns(bytes)
func (_SingleOwnerMSCA *SingleOwnerMSCATransactorSession) ExecuteFromPlugin(data []byte) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.ExecuteFromPlugin(&_SingleOwnerMSCA.TransactOpts, data)
}

// ExecuteFromPluginExternal is a paid mutator transaction binding the contract method 0x38997b11.
//
// Solidity: function executeFromPluginExternal(address target, uint256 value, bytes data) payable returns(bytes)
func (_SingleOwnerMSCA *SingleOwnerMSCATransactor) ExecuteFromPluginExternal(opts *bind.TransactOpts, target common.Address, value *big.Int, data []byte) (*types.Transaction, error) {
	return _SingleOwnerMSCA.contract.Transact(opts, "executeFromPluginExternal", target, value, data)
}

// ExecuteFromPluginExternal is a paid mutator transaction binding the contract method 0x38997b11.
//
// Solidity: function executeFromPluginExternal(address target, uint256 value, bytes data) payable returns(bytes)
func (_SingleOwnerMSCA *SingleOwnerMSCASession) ExecuteFromPluginExternal(target common.Address, value *big.Int, data []byte) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.ExecuteFromPluginExternal(&_SingleOwnerMSCA.TransactOpts, target, value, data)
}

// ExecuteFromPluginExternal is a paid mutator transaction binding the contract method 0x38997b11.
//
// Solidity: function executeFromPluginExternal(address target, uint256 value, bytes data) payable returns(bytes)
func (_SingleOwnerMSCA *SingleOwnerMSCATransactorSession) ExecuteFromPluginExternal(target common.Address, value *big.Int, data []byte) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.ExecuteFromPluginExternal(&_SingleOwnerMSCA.TransactOpts, target, value, data)
}

// InitializeSingleOwnerMSCA is a paid mutator transaction binding the contract method 0x36cf06ff.
//
// Solidity: function initializeSingleOwnerMSCA(address owner) returns()
func (_SingleOwnerMSCA *SingleOwnerMSCATransactor) InitializeSingleOwnerMSCA(opts *bind.TransactOpts, owner common.Address) (*types.Transaction, error) {
	return _SingleOwnerMSCA.contract.Transact(opts, "initializeSingleOwnerMSCA", owner)
}

// InitializeSingleOwnerMSCA is a paid mutator transaction binding the contract method 0x36cf06ff.
//
// Solidity: function initializeSingleOwnerMSCA(address owner) returns()
func (_SingleOwnerMSCA *SingleOwnerMSCASession) InitializeSingleOwnerMSCA(owner common.Address) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.InitializeSingleOwnerMSCA(&_SingleOwnerMSCA.TransactOpts, owner)
}

// InitializeSingleOwnerMSCA is a paid mutator transaction binding the contract method 0x36cf06ff.
//
// Solidity: function initializeSingleOwnerMSCA(address owner) returns()
func (_SingleOwnerMSCA *SingleOwnerMSCATransactorSession) InitializeSingleOwnerMSCA(owner common.Address) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.InitializeSingleOwnerMSCA(&_SingleOwnerMSCA.TransactOpts, owner)
}

// InstallPlugin is a paid mutator transaction binding the contract method 0xf85730f4.
//
// Solidity: function installPlugin(address plugin, bytes32 manifestHash, bytes pluginInstallData, (address,uint8)[] dependencies) returns()
func (_SingleOwnerMSCA *SingleOwnerMSCATransactor) InstallPlugin(opts *bind.TransactOpts, plugin common.Address, manifestHash [32]byte, pluginInstallData []byte, dependencies []FunctionReference) (*types.Transaction, error) {
	return _SingleOwnerMSCA.contract.Transact(opts, "installPlugin", plugin, manifestHash, pluginInstallData, dependencies)
}

// InstallPlugin is a paid mutator transaction binding the contract method 0xf85730f4.
//
// Solidity: function installPlugin(address plugin, bytes32 manifestHash, bytes pluginInstallData, (address,uint8)[] dependencies) returns()
func (_SingleOwnerMSCA *SingleOwnerMSCASession) InstallPlugin(plugin common.Address, manifestHash [32]byte, pluginInstallData []byte, dependencies []FunctionReference) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.InstallPlugin(&_SingleOwnerMSCA.TransactOpts, plugin, manifestHash, pluginInstallData, dependencies)
}

// InstallPlugin is a paid mutator transaction binding the contract method 0xf85730f4.
//
// Solidity: function installPlugin(address plugin, bytes32 manifestHash, bytes pluginInstallData, (address,uint8)[] dependencies) returns()
func (_SingleOwnerMSCA *SingleOwnerMSCATransactorSession) InstallPlugin(plugin common.Address, manifestHash [32]byte, pluginInstallData []byte, dependencies []FunctionReference) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.InstallPlugin(&_SingleOwnerMSCA.TransactOpts, plugin, manifestHash, pluginInstallData, dependencies)
}

// RenounceNativeOwnership is a paid mutator transaction binding the contract method 0x4ee53c76.
//
// Solidity: function renounceNativeOwnership() returns()
func (_SingleOwnerMSCA *SingleOwnerMSCATransactor) RenounceNativeOwnership(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SingleOwnerMSCA.contract.Transact(opts, "renounceNativeOwnership")
}

// RenounceNativeOwnership is a paid mutator transaction binding the contract method 0x4ee53c76.
//
// Solidity: function renounceNativeOwnership() returns()
func (_SingleOwnerMSCA *SingleOwnerMSCASession) RenounceNativeOwnership() (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.RenounceNativeOwnership(&_SingleOwnerMSCA.TransactOpts)
}

// RenounceNativeOwnership is a paid mutator transaction binding the contract method 0x4ee53c76.
//
// Solidity: function renounceNativeOwnership() returns()
func (_SingleOwnerMSCA *SingleOwnerMSCATransactorSession) RenounceNativeOwnership() (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.RenounceNativeOwnership(&_SingleOwnerMSCA.TransactOpts)
}

// TransferNativeOwnership is a paid mutator transaction binding the contract method 0xf95d04b0.
//
// Solidity: function transferNativeOwnership(address newOwner) returns()
func (_SingleOwnerMSCA *SingleOwnerMSCATransactor) TransferNativeOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _SingleOwnerMSCA.contract.Transact(opts, "transferNativeOwnership", newOwner)
}

// TransferNativeOwnership is a paid mutator transaction binding the contract method 0xf95d04b0.
//
// Solidity: function transferNativeOwnership(address newOwner) returns()
func (_SingleOwnerMSCA *SingleOwnerMSCASession) TransferNativeOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.TransferNativeOwnership(&_SingleOwnerMSCA.TransactOpts, newOwner)
}

// TransferNativeOwnership is a paid mutator transaction binding the contract method 0xf95d04b0.
//
// Solidity: function transferNativeOwnership(address newOwner) returns()
func (_SingleOwnerMSCA *SingleOwnerMSCATransactorSession) TransferNativeOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.TransferNativeOwnership(&_SingleOwnerMSCA.TransactOpts, newOwner)
}

// UninstallPlugin is a paid mutator transaction binding the contract method 0xc1a221f3.
//
// Solidity: function uninstallPlugin(address plugin, bytes config, bytes pluginUninstallData) returns()
func (_SingleOwnerMSCA *SingleOwnerMSCATransactor) UninstallPlugin(opts *bind.TransactOpts, plugin common.Address, config []byte, pluginUninstallData []byte) (*types.Transaction, error) {
	return _SingleOwnerMSCA.contract.Transact(opts, "uninstallPlugin", plugin, config, pluginUninstallData)
}

// UninstallPlugin is a paid mutator transaction binding the contract method 0xc1a221f3.
//
// Solidity: function uninstallPlugin(address plugin, bytes config, bytes pluginUninstallData) returns()
func (_SingleOwnerMSCA *SingleOwnerMSCASession) UninstallPlugin(plugin common.Address, config []byte, pluginUninstallData []byte) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.UninstallPlugin(&_SingleOwnerMSCA.TransactOpts, plugin, config, pluginUninstallData)
}

// UninstallPlugin is a paid mutator transaction binding the contract method 0xc1a221f3.
//
// Solidity: function uninstallPlugin(address plugin, bytes config, bytes pluginUninstallData) returns()
func (_SingleOwnerMSCA *SingleOwnerMSCATransactorSession) UninstallPlugin(plugin common.Address, config []byte, pluginUninstallData []byte) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.UninstallPlugin(&_SingleOwnerMSCA.TransactOpts, plugin, config, pluginUninstallData)
}

// UpgradeToAndCall is a paid mutator transaction binding the contract method 0x4f1ef286.
//
// Solidity: function upgradeToAndCall(address newImplementation, bytes data) payable returns()
func (_SingleOwnerMSCA *SingleOwnerMSCATransactor) UpgradeToAndCall(opts *bind.TransactOpts, newImplementation common.Address, data []byte) (*types.Transaction, error) {
	return _SingleOwnerMSCA.contract.Transact(opts, "upgradeToAndCall", newImplementation, data)
}

// UpgradeToAndCall is a paid mutator transaction binding the contract method 0x4f1ef286.
//
// Solidity: function upgradeToAndCall(address newImplementation, bytes data) payable returns()
func (_SingleOwnerMSCA *SingleOwnerMSCASession) UpgradeToAndCall(newImplementation common.Address, data []byte) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.UpgradeToAndCall(&_SingleOwnerMSCA.TransactOpts, newImplementation, data)
}

// UpgradeToAndCall is a paid mutator transaction binding the contract method 0x4f1ef286.
//
// Solidity: function upgradeToAndCall(address newImplementation, bytes data) payable returns()
func (_SingleOwnerMSCA *SingleOwnerMSCATransactorSession) UpgradeToAndCall(newImplementation common.Address, data []byte) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.UpgradeToAndCall(&_SingleOwnerMSCA.TransactOpts, newImplementation, data)
}

// ValidateUserOp is a paid mutator transaction binding the contract method 0x19822f7c.
//
// Solidity: function validateUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes) userOp, bytes32 userOpHash, uint256 missingAccountFunds) returns(uint256 validationData)
func (_SingleOwnerMSCA *SingleOwnerMSCATransactor) ValidateUserOp(opts *bind.TransactOpts, userOp PackedUserOperation, userOpHash [32]byte, missingAccountFunds *big.Int) (*types.Transaction, error) {
	return _SingleOwnerMSCA.contract.Transact(opts, "validateUserOp", userOp, userOpHash, missingAccountFunds)
}

// ValidateUserOp is a paid mutator transaction binding the contract method 0x19822f7c.
//
// Solidity: function validateUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes) userOp, bytes32 userOpHash, uint256 missingAccountFunds) returns(uint256 validationData)
func (_SingleOwnerMSCA *SingleOwnerMSCASession) ValidateUserOp(userOp PackedUserOperation, userOpHash [32]byte, missingAccountFunds *big.Int) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.ValidateUserOp(&_SingleOwnerMSCA.TransactOpts, userOp, userOpHash, missingAccountFunds)
}

// ValidateUserOp is a paid mutator transaction binding the contract method 0x19822f7c.
//
// Solidity: function validateUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes) userOp, bytes32 userOpHash, uint256 missingAccountFunds) returns(uint256 validationData)
func (_SingleOwnerMSCA *SingleOwnerMSCATransactorSession) ValidateUserOp(userOp PackedUserOperation, userOpHash [32]byte, missingAccountFunds *big.Int) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.ValidateUserOp(&_SingleOwnerMSCA.TransactOpts, userOp, userOpHash, missingAccountFunds)
}

// WithdrawDepositTo is a paid mutator transaction binding the contract method 0x4d44560d.
//
// Solidity: function withdrawDepositTo(address withdrawAddress, uint256 amount) returns()
func (_SingleOwnerMSCA *SingleOwnerMSCATransactor) WithdrawDepositTo(opts *bind.TransactOpts, withdrawAddress common.Address, amount *big.Int) (*types.Transaction, error) {
	return _SingleOwnerMSCA.contract.Transact(opts, "withdrawDepositTo", withdrawAddress, amount)
}

// WithdrawDepositTo is a paid mutator transaction binding the contract method 0x4d44560d.
//
// Solidity: function withdrawDepositTo(address withdrawAddress, uint256 amount) returns()
func (_SingleOwnerMSCA *SingleOwnerMSCASession) WithdrawDepositTo(withdrawAddress common.Address, amount *big.Int) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.WithdrawDepositTo(&_SingleOwnerMSCA.TransactOpts, withdrawAddress, amount)
}

// WithdrawDepositTo is a paid mutator transaction binding the contract method 0x4d44560d.
//
// Solidity: function withdrawDepositTo(address withdrawAddress, uint256 amount) returns()
func (_SingleOwnerMSCA *SingleOwnerMSCATransactorSession) WithdrawDepositTo(withdrawAddress common.Address, amount *big.Int) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.WithdrawDepositTo(&_SingleOwnerMSCA.TransactOpts, withdrawAddress, amount)
}

// Fallback is a paid mutator transaction binding the contract fallback function.
//
// Solidity: fallback() payable returns()
func (_SingleOwnerMSCA *SingleOwnerMSCATransactor) Fallback(opts *bind.TransactOpts, calldata []byte) (*types.Transaction, error) {
	return _SingleOwnerMSCA.contract.RawTransact(opts, calldata)
}

// Fallback is a paid mutator transaction binding the contract fallback function.
//
// Solidity: fallback() payable returns()
func (_SingleOwnerMSCA *SingleOwnerMSCASession) Fallback(calldata []byte) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.Fallback(&_SingleOwnerMSCA.TransactOpts, calldata)
}

// Fallback is a paid mutator transaction binding the contract fallback function.
//
// Solidity: fallback() payable returns()
func (_SingleOwnerMSCA *SingleOwnerMSCATransactorSession) Fallback(calldata []byte) (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.Fallback(&_SingleOwnerMSCA.TransactOpts, calldata)
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_SingleOwnerMSCA *SingleOwnerMSCATransactor) Receive(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SingleOwnerMSCA.contract.RawTransact(opts, nil) // calldata is disallowed for receive function
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_SingleOwnerMSCA *SingleOwnerMSCASession) Receive() (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.Receive(&_SingleOwnerMSCA.TransactOpts)
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_SingleOwnerMSCA *SingleOwnerMSCATransactorSession) Receive() (*types.Transaction, error) {
	return _SingleOwnerMSCA.Contract.Receive(&_SingleOwnerMSCA.TransactOpts)
}

// SingleOwnerMSCAInitializedIterator is returned from FilterInitialized and is used to iterate over the raw logs and unpacked data for Initialized events raised by the SingleOwnerMSCA contract.
type SingleOwnerMSCAInitializedIterator struct {
	Event *SingleOwnerMSCAInitialized // Event containing the contract specifics and raw log

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
func (it *SingleOwnerMSCAInitializedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SingleOwnerMSCAInitialized)
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
		it.Event = new(SingleOwnerMSCAInitialized)
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
func (it *SingleOwnerMSCAInitializedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SingleOwnerMSCAInitializedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SingleOwnerMSCAInitialized represents a Initialized event raised by the SingleOwnerMSCA contract.
type SingleOwnerMSCAInitialized struct {
	Version uint64
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterInitialized is a free log retrieval operation binding the contract event 0xc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d2.
//
// Solidity: event Initialized(uint64 version)
func (_SingleOwnerMSCA *SingleOwnerMSCAFilterer) FilterInitialized(opts *bind.FilterOpts) (*SingleOwnerMSCAInitializedIterator, error) {

	logs, sub, err := _SingleOwnerMSCA.contract.FilterLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return &SingleOwnerMSCAInitializedIterator{contract: _SingleOwnerMSCA.contract, event: "Initialized", logs: logs, sub: sub}, nil
}

// WatchInitialized is a free log subscription operation binding the contract event 0xc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d2.
//
// Solidity: event Initialized(uint64 version)
func (_SingleOwnerMSCA *SingleOwnerMSCAFilterer) WatchInitialized(opts *bind.WatchOpts, sink chan<- *SingleOwnerMSCAInitialized) (event.Subscription, error) {

	logs, sub, err := _SingleOwnerMSCA.contract.WatchLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SingleOwnerMSCAInitialized)
				if err := _SingleOwnerMSCA.contract.UnpackLog(event, "Initialized", log); err != nil {
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
func (_SingleOwnerMSCA *SingleOwnerMSCAFilterer) ParseInitialized(log types.Log) (*SingleOwnerMSCAInitialized, error) {
	event := new(SingleOwnerMSCAInitialized)
	if err := _SingleOwnerMSCA.contract.UnpackLog(event, "Initialized", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SingleOwnerMSCAOwnershipTransferredIterator is returned from FilterOwnershipTransferred and is used to iterate over the raw logs and unpacked data for OwnershipTransferred events raised by the SingleOwnerMSCA contract.
type SingleOwnerMSCAOwnershipTransferredIterator struct {
	Event *SingleOwnerMSCAOwnershipTransferred // Event containing the contract specifics and raw log

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
func (it *SingleOwnerMSCAOwnershipTransferredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SingleOwnerMSCAOwnershipTransferred)
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
		it.Event = new(SingleOwnerMSCAOwnershipTransferred)
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
func (it *SingleOwnerMSCAOwnershipTransferredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SingleOwnerMSCAOwnershipTransferredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SingleOwnerMSCAOwnershipTransferred represents a OwnershipTransferred event raised by the SingleOwnerMSCA contract.
type SingleOwnerMSCAOwnershipTransferred struct {
	Account       common.Address
	PreviousOwner common.Address
	NewOwner      common.Address
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterOwnershipTransferred is a free log retrieval operation binding the contract event 0xc8894f26f396ce8c004245c8b7cd1b92103a6e4302fcbab883987149ac01b7ec.
//
// Solidity: event OwnershipTransferred(address indexed account, address indexed previousOwner, address indexed newOwner)
func (_SingleOwnerMSCA *SingleOwnerMSCAFilterer) FilterOwnershipTransferred(opts *bind.FilterOpts, account []common.Address, previousOwner []common.Address, newOwner []common.Address) (*SingleOwnerMSCAOwnershipTransferredIterator, error) {

	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}
	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _SingleOwnerMSCA.contract.FilterLogs(opts, "OwnershipTransferred", accountRule, previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return &SingleOwnerMSCAOwnershipTransferredIterator{contract: _SingleOwnerMSCA.contract, event: "OwnershipTransferred", logs: logs, sub: sub}, nil
}

// WatchOwnershipTransferred is a free log subscription operation binding the contract event 0xc8894f26f396ce8c004245c8b7cd1b92103a6e4302fcbab883987149ac01b7ec.
//
// Solidity: event OwnershipTransferred(address indexed account, address indexed previousOwner, address indexed newOwner)
func (_SingleOwnerMSCA *SingleOwnerMSCAFilterer) WatchOwnershipTransferred(opts *bind.WatchOpts, sink chan<- *SingleOwnerMSCAOwnershipTransferred, account []common.Address, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error) {

	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}
	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _SingleOwnerMSCA.contract.WatchLogs(opts, "OwnershipTransferred", accountRule, previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SingleOwnerMSCAOwnershipTransferred)
				if err := _SingleOwnerMSCA.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
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

// ParseOwnershipTransferred is a log parse operation binding the contract event 0xc8894f26f396ce8c004245c8b7cd1b92103a6e4302fcbab883987149ac01b7ec.
//
// Solidity: event OwnershipTransferred(address indexed account, address indexed previousOwner, address indexed newOwner)
func (_SingleOwnerMSCA *SingleOwnerMSCAFilterer) ParseOwnershipTransferred(log types.Log) (*SingleOwnerMSCAOwnershipTransferred, error) {
	event := new(SingleOwnerMSCAOwnershipTransferred)
	if err := _SingleOwnerMSCA.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SingleOwnerMSCAPluginInstalledIterator is returned from FilterPluginInstalled and is used to iterate over the raw logs and unpacked data for PluginInstalled events raised by the SingleOwnerMSCA contract.
type SingleOwnerMSCAPluginInstalledIterator struct {
	Event *SingleOwnerMSCAPluginInstalled // Event containing the contract specifics and raw log

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
func (it *SingleOwnerMSCAPluginInstalledIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SingleOwnerMSCAPluginInstalled)
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
		it.Event = new(SingleOwnerMSCAPluginInstalled)
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
func (it *SingleOwnerMSCAPluginInstalledIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SingleOwnerMSCAPluginInstalledIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SingleOwnerMSCAPluginInstalled represents a PluginInstalled event raised by the SingleOwnerMSCA contract.
type SingleOwnerMSCAPluginInstalled struct {
	Plugin       common.Address
	ManifestHash [32]byte
	Dependencies []FunctionReference
	Raw          types.Log // Blockchain specific contextual infos
}

// FilterPluginInstalled is a free log retrieval operation binding the contract event 0xbd807faaec7a357be5390445b7efef4a0ca92fa66300ee4827dde3d9387ffb51.
//
// Solidity: event PluginInstalled(address indexed plugin, bytes32 manifestHash, (address,uint8)[] dependencies)
func (_SingleOwnerMSCA *SingleOwnerMSCAFilterer) FilterPluginInstalled(opts *bind.FilterOpts, plugin []common.Address) (*SingleOwnerMSCAPluginInstalledIterator, error) {

	var pluginRule []interface{}
	for _, pluginItem := range plugin {
		pluginRule = append(pluginRule, pluginItem)
	}

	logs, sub, err := _SingleOwnerMSCA.contract.FilterLogs(opts, "PluginInstalled", pluginRule)
	if err != nil {
		return nil, err
	}
	return &SingleOwnerMSCAPluginInstalledIterator{contract: _SingleOwnerMSCA.contract, event: "PluginInstalled", logs: logs, sub: sub}, nil
}

// WatchPluginInstalled is a free log subscription operation binding the contract event 0xbd807faaec7a357be5390445b7efef4a0ca92fa66300ee4827dde3d9387ffb51.
//
// Solidity: event PluginInstalled(address indexed plugin, bytes32 manifestHash, (address,uint8)[] dependencies)
func (_SingleOwnerMSCA *SingleOwnerMSCAFilterer) WatchPluginInstalled(opts *bind.WatchOpts, sink chan<- *SingleOwnerMSCAPluginInstalled, plugin []common.Address) (event.Subscription, error) {

	var pluginRule []interface{}
	for _, pluginItem := range plugin {
		pluginRule = append(pluginRule, pluginItem)
	}

	logs, sub, err := _SingleOwnerMSCA.contract.WatchLogs(opts, "PluginInstalled", pluginRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SingleOwnerMSCAPluginInstalled)
				if err := _SingleOwnerMSCA.contract.UnpackLog(event, "PluginInstalled", log); err != nil {
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

// ParsePluginInstalled is a log parse operation binding the contract event 0xbd807faaec7a357be5390445b7efef4a0ca92fa66300ee4827dde3d9387ffb51.
//
// Solidity: event PluginInstalled(address indexed plugin, bytes32 manifestHash, (address,uint8)[] dependencies)
func (_SingleOwnerMSCA *SingleOwnerMSCAFilterer) ParsePluginInstalled(log types.Log) (*SingleOwnerMSCAPluginInstalled, error) {
	event := new(SingleOwnerMSCAPluginInstalled)
	if err := _SingleOwnerMSCA.contract.UnpackLog(event, "PluginInstalled", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SingleOwnerMSCAPluginUninstalledIterator is returned from FilterPluginUninstalled and is used to iterate over the raw logs and unpacked data for PluginUninstalled events raised by the SingleOwnerMSCA contract.
type SingleOwnerMSCAPluginUninstalledIterator struct {
	Event *SingleOwnerMSCAPluginUninstalled // Event containing the contract specifics and raw log

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
func (it *SingleOwnerMSCAPluginUninstalledIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SingleOwnerMSCAPluginUninstalled)
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
		it.Event = new(SingleOwnerMSCAPluginUninstalled)
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
func (it *SingleOwnerMSCAPluginUninstalledIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SingleOwnerMSCAPluginUninstalledIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SingleOwnerMSCAPluginUninstalled represents a PluginUninstalled event raised by the SingleOwnerMSCA contract.
type SingleOwnerMSCAPluginUninstalled struct {
	Plugin               common.Address
	OnUninstallSucceeded bool
	Raw                  types.Log // Blockchain specific contextual infos
}

// FilterPluginUninstalled is a free log retrieval operation binding the contract event 0xeb7551bad8fd10038dee62a958c2b6f45624499dc800ff8936bb0a4904bdd2fe.
//
// Solidity: event PluginUninstalled(address indexed plugin, bool indexed onUninstallSucceeded)
func (_SingleOwnerMSCA *SingleOwnerMSCAFilterer) FilterPluginUninstalled(opts *bind.FilterOpts, plugin []common.Address, onUninstallSucceeded []bool) (*SingleOwnerMSCAPluginUninstalledIterator, error) {

	var pluginRule []interface{}
	for _, pluginItem := range plugin {
		pluginRule = append(pluginRule, pluginItem)
	}
	var onUninstallSucceededRule []interface{}
	for _, onUninstallSucceededItem := range onUninstallSucceeded {
		onUninstallSucceededRule = append(onUninstallSucceededRule, onUninstallSucceededItem)
	}

	logs, sub, err := _SingleOwnerMSCA.contract.FilterLogs(opts, "PluginUninstalled", pluginRule, onUninstallSucceededRule)
	if err != nil {
		return nil, err
	}
	return &SingleOwnerMSCAPluginUninstalledIterator{contract: _SingleOwnerMSCA.contract, event: "PluginUninstalled", logs: logs, sub: sub}, nil
}

// WatchPluginUninstalled is a free log subscription operation binding the contract event 0xeb7551bad8fd10038dee62a958c2b6f45624499dc800ff8936bb0a4904bdd2fe.
//
// Solidity: event PluginUninstalled(address indexed plugin, bool indexed onUninstallSucceeded)
func (_SingleOwnerMSCA *SingleOwnerMSCAFilterer) WatchPluginUninstalled(opts *bind.WatchOpts, sink chan<- *SingleOwnerMSCAPluginUninstalled, plugin []common.Address, onUninstallSucceeded []bool) (event.Subscription, error) {

	var pluginRule []interface{}
	for _, pluginItem := range plugin {
		pluginRule = append(pluginRule, pluginItem)
	}
	var onUninstallSucceededRule []interface{}
	for _, onUninstallSucceededItem := range onUninstallSucceeded {
		onUninstallSucceededRule = append(onUninstallSucceededRule, onUninstallSucceededItem)
	}

	logs, sub, err := _SingleOwnerMSCA.contract.WatchLogs(opts, "PluginUninstalled", pluginRule, onUninstallSucceededRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SingleOwnerMSCAPluginUninstalled)
				if err := _SingleOwnerMSCA.contract.UnpackLog(event, "PluginUninstalled", log); err != nil {
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

// ParsePluginUninstalled is a log parse operation binding the contract event 0xeb7551bad8fd10038dee62a958c2b6f45624499dc800ff8936bb0a4904bdd2fe.
//
// Solidity: event PluginUninstalled(address indexed plugin, bool indexed onUninstallSucceeded)
func (_SingleOwnerMSCA *SingleOwnerMSCAFilterer) ParsePluginUninstalled(log types.Log) (*SingleOwnerMSCAPluginUninstalled, error) {
	event := new(SingleOwnerMSCAPluginUninstalled)
	if err := _SingleOwnerMSCA.contract.UnpackLog(event, "PluginUninstalled", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SingleOwnerMSCASingleOwnerMSCAInitializedIterator is returned from FilterSingleOwnerMSCAInitialized and is used to iterate over the raw logs and unpacked data for SingleOwnerMSCAInitialized events raised by the SingleOwnerMSCA contract.
type SingleOwnerMSCASingleOwnerMSCAInitializedIterator struct {
	Event *SingleOwnerMSCASingleOwnerMSCAInitialized // Event containing the contract specifics and raw log

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
func (it *SingleOwnerMSCASingleOwnerMSCAInitializedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SingleOwnerMSCASingleOwnerMSCAInitialized)
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
		it.Event = new(SingleOwnerMSCASingleOwnerMSCAInitialized)
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
func (it *SingleOwnerMSCASingleOwnerMSCAInitializedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SingleOwnerMSCASingleOwnerMSCAInitializedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SingleOwnerMSCASingleOwnerMSCAInitialized represents a SingleOwnerMSCAInitialized event raised by the SingleOwnerMSCA contract.
type SingleOwnerMSCASingleOwnerMSCAInitialized struct {
	Account           common.Address
	EntryPointAddress common.Address
	Owner             common.Address
	Raw               types.Log // Blockchain specific contextual infos
}

// FilterSingleOwnerMSCAInitialized is a free log retrieval operation binding the contract event 0xb9a2e77405e16894f62a69f7bd6a34b8ca7647b6f5d5408d7c577d275691fde3.
//
// Solidity: event SingleOwnerMSCAInitialized(address indexed account, address indexed entryPointAddress, address owner)
func (_SingleOwnerMSCA *SingleOwnerMSCAFilterer) FilterSingleOwnerMSCAInitialized(opts *bind.FilterOpts, account []common.Address, entryPointAddress []common.Address) (*SingleOwnerMSCASingleOwnerMSCAInitializedIterator, error) {

	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}
	var entryPointAddressRule []interface{}
	for _, entryPointAddressItem := range entryPointAddress {
		entryPointAddressRule = append(entryPointAddressRule, entryPointAddressItem)
	}

	logs, sub, err := _SingleOwnerMSCA.contract.FilterLogs(opts, "SingleOwnerMSCAInitialized", accountRule, entryPointAddressRule)
	if err != nil {
		return nil, err
	}
	return &SingleOwnerMSCASingleOwnerMSCAInitializedIterator{contract: _SingleOwnerMSCA.contract, event: "SingleOwnerMSCAInitialized", logs: logs, sub: sub}, nil
}

// WatchSingleOwnerMSCAInitialized is a free log subscription operation binding the contract event 0xb9a2e77405e16894f62a69f7bd6a34b8ca7647b6f5d5408d7c577d275691fde3.
//
// Solidity: event SingleOwnerMSCAInitialized(address indexed account, address indexed entryPointAddress, address owner)
func (_SingleOwnerMSCA *SingleOwnerMSCAFilterer) WatchSingleOwnerMSCAInitialized(opts *bind.WatchOpts, sink chan<- *SingleOwnerMSCASingleOwnerMSCAInitialized, account []common.Address, entryPointAddress []common.Address) (event.Subscription, error) {

	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}
	var entryPointAddressRule []interface{}
	for _, entryPointAddressItem := range entryPointAddress {
		entryPointAddressRule = append(entryPointAddressRule, entryPointAddressItem)
	}

	logs, sub, err := _SingleOwnerMSCA.contract.WatchLogs(opts, "SingleOwnerMSCAInitialized", accountRule, entryPointAddressRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SingleOwnerMSCASingleOwnerMSCAInitialized)
				if err := _SingleOwnerMSCA.contract.UnpackLog(event, "SingleOwnerMSCAInitialized", log); err != nil {
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

// ParseSingleOwnerMSCAInitialized is a log parse operation binding the contract event 0xb9a2e77405e16894f62a69f7bd6a34b8ca7647b6f5d5408d7c577d275691fde3.
//
// Solidity: event SingleOwnerMSCAInitialized(address indexed account, address indexed entryPointAddress, address owner)
func (_SingleOwnerMSCA *SingleOwnerMSCAFilterer) ParseSingleOwnerMSCAInitialized(log types.Log) (*SingleOwnerMSCASingleOwnerMSCAInitialized, error) {
	event := new(SingleOwnerMSCASingleOwnerMSCAInitialized)
	if err := _SingleOwnerMSCA.contract.UnpackLog(event, "SingleOwnerMSCAInitialized", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SingleOwnerMSCAUpgradedIterator is returned from FilterUpgraded and is used to iterate over the raw logs and unpacked data for Upgraded events raised by the SingleOwnerMSCA contract.
type SingleOwnerMSCAUpgradedIterator struct {
	Event *SingleOwnerMSCAUpgraded // Event containing the contract specifics and raw log

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
func (it *SingleOwnerMSCAUpgradedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SingleOwnerMSCAUpgraded)
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
		it.Event = new(SingleOwnerMSCAUpgraded)
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
func (it *SingleOwnerMSCAUpgradedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SingleOwnerMSCAUpgradedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SingleOwnerMSCAUpgraded represents a Upgraded event raised by the SingleOwnerMSCA contract.
type SingleOwnerMSCAUpgraded struct {
	Implementation common.Address
	Raw            types.Log // Blockchain specific contextual infos
}

// FilterUpgraded is a free log retrieval operation binding the contract event 0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b.
//
// Solidity: event Upgraded(address indexed implementation)
func (_SingleOwnerMSCA *SingleOwnerMSCAFilterer) FilterUpgraded(opts *bind.FilterOpts, implementation []common.Address) (*SingleOwnerMSCAUpgradedIterator, error) {

	var implementationRule []interface{}
	for _, implementationItem := range implementation {
		implementationRule = append(implementationRule, implementationItem)
	}

	logs, sub, err := _SingleOwnerMSCA.contract.FilterLogs(opts, "Upgraded", implementationRule)
	if err != nil {
		return nil, err
	}
	return &SingleOwnerMSCAUpgradedIterator{contract: _SingleOwnerMSCA.contract, event: "Upgraded", logs: logs, sub: sub}, nil
}

// WatchUpgraded is a free log subscription operation binding the contract event 0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b.
//
// Solidity: event Upgraded(address indexed implementation)
func (_SingleOwnerMSCA *SingleOwnerMSCAFilterer) WatchUpgraded(opts *bind.WatchOpts, sink chan<- *SingleOwnerMSCAUpgraded, implementation []common.Address) (event.Subscription, error) {

	var implementationRule []interface{}
	for _, implementationItem := range implementation {
		implementationRule = append(implementationRule, implementationItem)
	}

	logs, sub, err := _SingleOwnerMSCA.contract.WatchLogs(opts, "Upgraded", implementationRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SingleOwnerMSCAUpgraded)
				if err := _SingleOwnerMSCA.contract.UnpackLog(event, "Upgraded", log); err != nil {
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
func (_SingleOwnerMSCA *SingleOwnerMSCAFilterer) ParseUpgraded(log types.Log) (*SingleOwnerMSCAUpgraded, error) {
	event := new(SingleOwnerMSCAUpgraded)
	if err := _SingleOwnerMSCA.contract.UnpackLog(event, "Upgraded", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SingleOwnerMSCAWalletStorageInitializedIterator is returned from FilterWalletStorageInitialized and is used to iterate over the raw logs and unpacked data for WalletStorageInitialized events raised by the SingleOwnerMSCA contract.
type SingleOwnerMSCAWalletStorageInitializedIterator struct {
	Event *SingleOwnerMSCAWalletStorageInitialized // Event containing the contract specifics and raw log

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
func (it *SingleOwnerMSCAWalletStorageInitializedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SingleOwnerMSCAWalletStorageInitialized)
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
		it.Event = new(SingleOwnerMSCAWalletStorageInitialized)
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
func (it *SingleOwnerMSCAWalletStorageInitializedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SingleOwnerMSCAWalletStorageInitializedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SingleOwnerMSCAWalletStorageInitialized represents a WalletStorageInitialized event raised by the SingleOwnerMSCA contract.
type SingleOwnerMSCAWalletStorageInitialized struct {
	Raw types.Log // Blockchain specific contextual infos
}

// FilterWalletStorageInitialized is a free log retrieval operation binding the contract event 0x80bd505c666aa4feeb94643343d3e5acfd6d0b8c43c826331f5d543cbfa7e575.
//
// Solidity: event WalletStorageInitialized()
func (_SingleOwnerMSCA *SingleOwnerMSCAFilterer) FilterWalletStorageInitialized(opts *bind.FilterOpts) (*SingleOwnerMSCAWalletStorageInitializedIterator, error) {

	logs, sub, err := _SingleOwnerMSCA.contract.FilterLogs(opts, "WalletStorageInitialized")
	if err != nil {
		return nil, err
	}
	return &SingleOwnerMSCAWalletStorageInitializedIterator{contract: _SingleOwnerMSCA.contract, event: "WalletStorageInitialized", logs: logs, sub: sub}, nil
}

// WatchWalletStorageInitialized is a free log subscription operation binding the contract event 0x80bd505c666aa4feeb94643343d3e5acfd6d0b8c43c826331f5d543cbfa7e575.
//
// Solidity: event WalletStorageInitialized()
func (_SingleOwnerMSCA *SingleOwnerMSCAFilterer) WatchWalletStorageInitialized(opts *bind.WatchOpts, sink chan<- *SingleOwnerMSCAWalletStorageInitialized) (event.Subscription, error) {

	logs, sub, err := _SingleOwnerMSCA.contract.WatchLogs(opts, "WalletStorageInitialized")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SingleOwnerMSCAWalletStorageInitialized)
				if err := _SingleOwnerMSCA.contract.UnpackLog(event, "WalletStorageInitialized", log); err != nil {
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

// ParseWalletStorageInitialized is a log parse operation binding the contract event 0x80bd505c666aa4feeb94643343d3e5acfd6d0b8c43c826331f5d543cbfa7e575.
//
// Solidity: event WalletStorageInitialized()
func (_SingleOwnerMSCA *SingleOwnerMSCAFilterer) ParseWalletStorageInitialized(log types.Log) (*SingleOwnerMSCAWalletStorageInitialized, error) {
	event := new(SingleOwnerMSCAWalletStorageInitialized)
	if err := _SingleOwnerMSCA.contract.UnpackLog(event, "WalletStorageInitialized", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
