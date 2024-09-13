// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package AddressBookPlugin

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

// ManifestAssociatedFunction is an auto generated low-level Go binding around an user-defined struct.
type ManifestAssociatedFunction struct {
	ExecutionSelector  [4]byte
	AssociatedFunction ManifestFunction
}

// ManifestExecutionHook is an auto generated low-level Go binding around an user-defined struct.
type ManifestExecutionHook struct {
	Selector     [4]byte
	PreExecHook  ManifestFunction
	PostExecHook ManifestFunction
}

// ManifestExternalCallPermission is an auto generated low-level Go binding around an user-defined struct.
type ManifestExternalCallPermission struct {
	ExternalAddress   common.Address
	PermitAnySelector bool
	Selectors         [][4]byte
}

// ManifestFunction is an auto generated low-level Go binding around an user-defined struct.
type ManifestFunction struct {
	FunctionType    uint8
	FunctionId      uint8
	DependencyIndex *big.Int
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

// PluginManifest is an auto generated low-level Go binding around an user-defined struct.
type PluginManifest struct {
	InterfaceIds                [][4]byte
	DependencyInterfaceIds      [][4]byte
	ExecutionFunctions          [][4]byte
	PermittedExecutionSelectors [][4]byte
	PermitAnyExternalAddress    bool
	CanSpendNativeToken         bool
	PermittedExternalCalls      []ManifestExternalCallPermission
	UserOpValidationFunctions   []ManifestAssociatedFunction
	RuntimeValidationFunctions  []ManifestAssociatedFunction
	PreUserOpValidationHooks    []ManifestAssociatedFunction
	PreRuntimeValidationHooks   []ManifestAssociatedFunction
	ExecutionHooks              []ManifestExecutionHook
}

// PluginMetadata is an auto generated low-level Go binding around an user-defined struct.
type PluginMetadata struct {
	Name                  string
	Version               string
	Author                string
	PermissionDescriptors []SelectorPermission
}

// SelectorPermission is an auto generated low-level Go binding around an user-defined struct.
type SelectorPermission struct {
	FunctionSelector      [4]byte
	PermissionDescription string
}

// AddressBookPluginMetaData contains all meta data concerning the AddressBookPlugin contract.
var AddressBookPluginMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"function\",\"name\":\"NAME\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"addAllowedRecipients\",\"inputs\":[{\"name\":\"recipients\",\"type\":\"address[]\",\"internalType\":\"address[]\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"executeBatchWithAddressBook\",\"inputs\":[{\"name\":\"target\",\"type\":\"address[]\",\"internalType\":\"address[]\"},{\"name\":\"value\",\"type\":\"uint256[]\",\"internalType\":\"uint256[]\"},{\"name\":\"data\",\"type\":\"bytes[]\",\"internalType\":\"bytes[]\"},{\"name\":\"recipients\",\"type\":\"address[]\",\"internalType\":\"address[]\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes[]\",\"internalType\":\"bytes[]\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"executeWithAddressBook\",\"inputs\":[{\"name\":\"target\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"recipient\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"getAllowedRecipients\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"address[]\",\"internalType\":\"address[]\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"onInstall\",\"inputs\":[{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"onUninstall\",\"inputs\":[{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"pluginManifest\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"tuple\",\"internalType\":\"structPluginManifest\",\"components\":[{\"name\":\"interfaceIds\",\"type\":\"bytes4[]\",\"internalType\":\"bytes4[]\"},{\"name\":\"dependencyInterfaceIds\",\"type\":\"bytes4[]\",\"internalType\":\"bytes4[]\"},{\"name\":\"executionFunctions\",\"type\":\"bytes4[]\",\"internalType\":\"bytes4[]\"},{\"name\":\"permittedExecutionSelectors\",\"type\":\"bytes4[]\",\"internalType\":\"bytes4[]\"},{\"name\":\"permitAnyExternalAddress\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"canSpendNativeToken\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"permittedExternalCalls\",\"type\":\"tuple[]\",\"internalType\":\"structManifestExternalCallPermission[]\",\"components\":[{\"name\":\"externalAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"permitAnySelector\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"selectors\",\"type\":\"bytes4[]\",\"internalType\":\"bytes4[]\"}]},{\"name\":\"userOpValidationFunctions\",\"type\":\"tuple[]\",\"internalType\":\"structManifestAssociatedFunction[]\",\"components\":[{\"name\":\"executionSelector\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"},{\"name\":\"associatedFunction\",\"type\":\"tuple\",\"internalType\":\"structManifestFunction\",\"components\":[{\"name\":\"functionType\",\"type\":\"uint8\",\"internalType\":\"enumManifestAssociatedFunctionType\"},{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"dependencyIndex\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]}]},{\"name\":\"runtimeValidationFunctions\",\"type\":\"tuple[]\",\"internalType\":\"structManifestAssociatedFunction[]\",\"components\":[{\"name\":\"executionSelector\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"},{\"name\":\"associatedFunction\",\"type\":\"tuple\",\"internalType\":\"structManifestFunction\",\"components\":[{\"name\":\"functionType\",\"type\":\"uint8\",\"internalType\":\"enumManifestAssociatedFunctionType\"},{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"dependencyIndex\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]}]},{\"name\":\"preUserOpValidationHooks\",\"type\":\"tuple[]\",\"internalType\":\"structManifestAssociatedFunction[]\",\"components\":[{\"name\":\"executionSelector\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"},{\"name\":\"associatedFunction\",\"type\":\"tuple\",\"internalType\":\"structManifestFunction\",\"components\":[{\"name\":\"functionType\",\"type\":\"uint8\",\"internalType\":\"enumManifestAssociatedFunctionType\"},{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"dependencyIndex\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]}]},{\"name\":\"preRuntimeValidationHooks\",\"type\":\"tuple[]\",\"internalType\":\"structManifestAssociatedFunction[]\",\"components\":[{\"name\":\"executionSelector\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"},{\"name\":\"associatedFunction\",\"type\":\"tuple\",\"internalType\":\"structManifestFunction\",\"components\":[{\"name\":\"functionType\",\"type\":\"uint8\",\"internalType\":\"enumManifestAssociatedFunctionType\"},{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"dependencyIndex\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]}]},{\"name\":\"executionHooks\",\"type\":\"tuple[]\",\"internalType\":\"structManifestExecutionHook[]\",\"components\":[{\"name\":\"selector\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"},{\"name\":\"preExecHook\",\"type\":\"tuple\",\"internalType\":\"structManifestFunction\",\"components\":[{\"name\":\"functionType\",\"type\":\"uint8\",\"internalType\":\"enumManifestAssociatedFunctionType\"},{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"dependencyIndex\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]},{\"name\":\"postExecHook\",\"type\":\"tuple\",\"internalType\":\"structManifestFunction\",\"components\":[{\"name\":\"functionType\",\"type\":\"uint8\",\"internalType\":\"enumManifestAssociatedFunctionType\"},{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"dependencyIndex\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]}]}]}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"pluginMetadata\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"tuple\",\"internalType\":\"structPluginMetadata\",\"components\":[{\"name\":\"name\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"version\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"author\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"permissionDescriptors\",\"type\":\"tuple[]\",\"internalType\":\"structSelectorPermission[]\",\"components\":[{\"name\":\"functionSelector\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"},{\"name\":\"permissionDescription\",\"type\":\"string\",\"internalType\":\"string\"}]}]}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"postExecutionHook\",\"inputs\":[{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"preExecHookData\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"preExecutionHook\",\"inputs\":[{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"sender\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"context\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"preRuntimeValidationHook\",\"inputs\":[{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"sender\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"preUserOpValidationHook\",\"inputs\":[{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"userOp\",\"type\":\"tuple\",\"internalType\":\"structPackedUserOperation\",\"components\":[{\"name\":\"sender\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"nonce\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"initCode\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"callData\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"accountGasLimits\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"preVerificationGas\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"gasFees\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"paymasterAndData\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"signature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]},{\"name\":\"userOpHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"validationData\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"removeAllowedRecipients\",\"inputs\":[{\"name\":\"recipients\",\"type\":\"address[]\",\"internalType\":\"address[]\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"runtimeValidationFunction\",\"inputs\":[{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"sender\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"supportsInterface\",\"inputs\":[{\"name\":\"interfaceId\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"userOpValidationFunction\",\"inputs\":[{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"userOp\",\"type\":\"tuple\",\"internalType\":\"structPackedUserOperation\",\"components\":[{\"name\":\"sender\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"nonce\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"initCode\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"callData\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"accountGasLimits\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"preVerificationGas\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"gasFees\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"paymasterAndData\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"signature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]},{\"name\":\"userOpHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"validationData\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"event\",\"name\":\"AllowedAddressesAdded\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"recipients\",\"type\":\"address[]\",\"indexed\":false,\"internalType\":\"address[]\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"AllowedAddressesNotRemoved\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"AllowedAddressesRemoved\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"recipients\",\"type\":\"address[]\",\"indexed\":false,\"internalType\":\"address[]\"}],\"anonymous\":false},{\"type\":\"error\",\"name\":\"AlreadyInitialized\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"CallDataIsNotEmpty\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"target\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]},{\"type\":\"error\",\"name\":\"FailToAddRecipient\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"recipient\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"FailToRemoveRecipient\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"recipient\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"InvalidLength\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"InvalidTargetCodeLength\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"target\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]},{\"type\":\"error\",\"name\":\"NotImplemented\",\"inputs\":[{\"name\":\"selector\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"},{\"name\":\"functionId\",\"type\":\"uint8\",\"internalType\":\"uint8\"}]},{\"type\":\"error\",\"name\":\"NotInitialized\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"ReentrancyGuardReentrantCall\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"UnauthorizedRecipient\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"recipient\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"Unsupported\",\"inputs\":[]}]",
	Bin: "0x6080806040523461001b5760016000556121db90816100218239f35b600080fdfe6080604052600436101561001257600080fd5b60003560e01c806301fcb2fc146111d757806301ffc9a7146111675780630ae779e1146110815780630c7ecd84146110645780631128186d14611027578063118a538914610d8857806315b76b8414610d6657806346d60eb21461092a57806347b19eee14610cee5780636d61fe7014610c5a5780638a91b0e314610b8b578063a3f4df7e14610b5b578063b1c46f4a14610941578063bfd151c11461092a578063c4db8dd914610915578063c7763130146101185763cf01c349146100d757600080fd5b346101135760203660031901126101135761010f6101036100fe6100f9611258565b6120b6565b612172565b60405191829182611560565b0390f35b600080fd5b3461011357600036600319011261011357610131611bc4565b5061013a611bc4565b600160a0820152600160808201526040516101548161140c565b6005815260a0366020830137806040830152610176627f2cbf60e21b9161182a565b526358e237a560e11b61018c6040830151611837565b526323d8cf7760e11b6101a26040830151611847565b52630ae779e160e01b6101b86040830151611857565b5263cf01c34960e01b6101ce6040830151611867565b526101d7611c30565b61012082015261022f6040516101ec816113f1565b6001815260006020820152600060408201526040519061020b826113c0565b627f2cbf60e21b82526020820152610120830151906102298261182a565b5261182a565b5061028360405161023f816113f1565b6001815260026020820152600060408201526040519061025e826113c0565b6358e237a560e11b825260208201526101208301519061027d82611837565b52611837565b506102d7604051610293816113f1565b600481526000602082015260006040820152604051906102b2826113c0565b635b0e93fb60e11b82526020820152610120830151906102d182611847565b52611847565b5061032b6040516102e7816113f1565b60048152600060208201526000604082015260405190610306826113c0565b631a7e6adf60e11b825260208201526101208301519061032582611857565b52611857565b50610334611c30565b610140820152610386604051610349816113f1565b60018152600160208201526000604082015260405190610368826113c0565b627f2cbf60e21b82526020820152610140830151906102298261182a565b506103d4604051610396816113f1565b600181526003602082015260006040820152604051906103b5826113c0565b6358e237a560e11b825260208201526101408301519061027d82611837565b506104226040516103e4816113f1565b60048152600060208201526000604082015260405190610403826113c0565b635b0e93fb60e11b82526020820152610140830151906102d182611847565b50610470604051610432816113f1565b60048152600060208201526000604082015260405190610451826113c0565b631a7e6adf60e11b825260208201526101408301519061032582611857565b506104a3604051610480816113f1565b6002815260403660208301376020830181905263043140ed60e01b91829161182a565b526104b16020830151611837565b526105d06040516104c1816113f1565b6002815260006020820152600160408201526104db611ca2565b60e084015261050e6040516104ef816113c0565b627f2cbf60e21b81526020810183905260e0850151906102298261182a565b5061053e60405161051e816113c0565b6358e237a560e11b81526020810183905260e08501519061027d82611837565b5061056e60405161054e816113c0565b6323d8cf7760e11b81526020810183905260e0850151906102d182611847565b5061059e60405161057e816113c0565b630ae779e160e01b81526020810183905260e08501519061032582611857565b50604051906105ac826113c0565b63cf01c34960e01b8252602082015260e0830151906105ca82611867565b52611867565b506106ef6040516105e0816113f1565b6002815260006020820152600060408201526105fa611ca2565b61010084015261062f60405161060f816113c0565b627f2cbf60e21b815260208101839052610100850151906102298261182a565b5061066060405161063f816113c0565b6358e237a560e11b8152602081018390526101008501519061027d82611837565b50610691604051610670816113c0565b6323d8cf7760e11b815260208101839052610100850151906102d182611847565b506106c26040516106a1816113c0565b630ae779e160e01b8152602081018390526101008501519061032582611857565b50604051906106d0826113c0565b63cf01c34960e01b82526020820152610100830151906105ca82611867565b506040516106fc816113c0565b600181526020368183013780825263412b922360e11b9061071c9061182a565b5260405180916020825261078961077361075d610747845161018060208801526101a0870190611492565b6020850151868203601f19016040880152611492565b6040840151858203601f19016060870152611492565b6060830151848203601f19016080860152611492565b6080820151151560a084015260a0820151151560c084015260c082015190601f198482030160e0850152815180825260208201916020808360051b8301019401926000915b8383106108be578780886108296108116107f98b60e0850151601f198783030161010088015261150c565b610100840151858203601f190161012087015261150c565b610120830151848203601f190161014086015261150c565b6108476101408301519161016092601f19868303018487015261150c565b91015190601f19838203016101808401526020808351928381520192019060005b818110610876575050500390f35b91935091602060e06001926108b06040885163ffffffff851b81511684526108a486820151878601906114d0565b015160808301906114d0565b019401910191849392610868565b91939596509193602080610902600193601f19868203018752606060408b51878060a01b038151168452858101511515868501520151918160408201520190611492565b97019301930190928796959492936107ce565b34610113576109233661137c565b5050611a03565b346101135761093836611327565b50505050611a03565b34610113576080366003190112610113576001600160401b03600435818111610113576109729036906004016112f7565b90602480358481116101135761098c9036906004016112f7565b949091604435828111610113576109a79036906004016112f7565b9092606435908111610113576109c19036906004016112f7565b9390926109cc611d04565b87158015610b51575b8015610b47575b8015610b3d575b610b2b576109f08861162b565b986109fe6040519a8b611427565b888a52610a0a8961162b565b60209990601f19018a60005b8d838210610b1b575050505060005b818110610a93578b8b60018060005560405191808301818452845180915260408401918060408360051b8701019601926000905b838210610a665786880387f35b90919293948380610a82839a603f198b820301865289516112d2565b999701959493919091019101610a59565b610aa6610aa182848d6115a5565b6115cb565b610ab182858c6115a5565b3587831015610b0657828e610aef82948d8d610aff96610ae9610aa18f9b610ae160019d8260051b810190611abc565b9690956115a5565b93611d27565b610af98383611877565b52611877565b5001610a25565b85634e487b7160e01b60005260326004526000fd5b8282606092010152018b90610a16565b60405163251f56a160e21b8152600490fd5b50848814156109e3565b50828814156109dc565b50888814156109d5565b346101135760003660031901126101135761010f610b77611463565b6040519182916020835260208301906112d2565b34610113576020366003190112610113576004356001600160401b03811161011357610bbb903690600401611282565b5050610bc96100fe336120b6565b60408051338152637c9c64bb60e11b602082015260019181018290529060608201815b15610c0c575b600091815260808320600061fffe19825416915591610bec565b600182161580610c51575b610bf257837f8342bc442963161fe55b209fbfc4dafccac754f61a43438af2615c68dac75ed360405180610c4c339482611560565b0390a2005b50811515610c17565b34610113576020366003190112610113576001600160401b0360043581811161011357610c8b903690600401611282565b80929192610c9557005b82019060208383031261011357823590811161011357610cb59201611698565b610cbe81611f9e565b7f2762cf05265ec47ebbfe12ce03afa1f82fa948b789548da6e83f3a083ffb10e460405180610c4c339482611560565b34610113576020366003190112610113576004356001600160401b038111610113577f2762cf05265ec47ebbfe12ce03afa1f82fa948b789548da6e83f3a083ffb10e4610d42610c4c9236906004016112f7565b610d58610d53949294368387611642565b611f9e565b6040519182913395836115df565b34610113576020610d80610d793661137c565b5090611aee565b604051908152f35b3461011357600036600319011261011357610da1611a31565b50610daa611a31565b610db2611463565b815260405190610dc1826113c0565b600582526020640312e302e360dc1b8184015280820192835260405192610de7846113c0565b601984527f436972636c6520496e7465726e65742046696e616e6369616c00000000000000828501526040830193845260405193610e248561140c565b6005855260005b60a08110610ffd5750610f829060608501958652610e70610e4a611a65565b60405190610e57826113c0565b627f2cbf60e21b8252868201528751906102298261182a565b50610ea3610e7c611a65565b60405190610e89826113c0565b6358e237a560e11b82528682015287519061027d82611837565b50610ed6610eaf611a90565b60405190610ebc826113c0565b6323d8cf7760e11b8252868201528751906102d182611847565b50610f09610ee2611a90565b60405190610eef826113c0565b630ae779e160e01b82528682015287519061032582611857565b50610f3c610f15611a65565b60405190610f22826113c0565b63cf01c34960e01b8252868201528751906105ca82611867565b50610f71610f5b604051968688525160808789015260a08801906112d2565b935193601f1994858883030160408901526112d2565b9051838683030160608701526112d2565b9351918184860301608085015282519081865280860181808460051b8901019501936000975b848910610fb55787870388f35b9091929394958480610feb838686600196030188526040838c5163ffffffff60e01b8151168452015191818582015201906112d2565b98019401980197919094939294610fa8565b839060409693965161100e816113c0565b6000815260608382015282828601015201949194610e2b565b346101135760403660031901126101135760043560ff81168103610113576024356001600160401b03811161011357610923903690600401611282565b346101135761107f61107536611327565b93909291506118d1565b005b34610113576020366003190112610113576004356001600160401b038111610113576110b19036906004016112f7565b60005b8181106110ef5750610c4c7f8342bc442963161fe55b209fbfc4dafccac754f61a43438af2615c68dac75ed3916040519182913395836115df565b6111186bffffffffffffffffffffffff1961110e610aa18486886115a5565b60601b1633611e57565b15611125576001016110b4565b610aa19061113692611163946115a5565b60405163e3bee48360e01b81523360048201526001600160a01b0390911660248201529081906044820190565b0390fd5b346101135760203660031901126101135760043563ffffffff60e01b81168091036101135760209063412b922360e11b81149081156111ac575b506040519015158152f35b63043140ed60e01b8114915081156111c6575b50826111a1565b6301ffc9a760e01b149050826111bf565b34610113576080366003190112610113576111f0611258565b6044356001600160401b0381116101135761120f903690600401611282565b909190606435906001600160a01b03821682036101135761010f9361123f93611236611d04565b60243590611d27565b60016000556040519182916020835260208301906112d2565b600435906001600160a01b038216820361011357565b35906001600160a01b038216820361011357565b9181601f84011215610113578235916001600160401b038311610113576020838186019501011161011357565b60005b8381106112c25750506000910152565b81810151838201526020016112b2565b906020916112eb815180928185528580860191016112af565b601f01601f1916010190565b9181601f84011215610113578235916001600160401b038311610113576020808501948460051b01011161011357565b9060806003198301126101135760043560ff8116810361011357916024356001600160a01b0381168103610113579160443591606435906001600160401b0382116101135761137891600401611282565b9091565b906003196060818401126101135760043560ff811681036101135792602435916001600160401b038311610113578261012092030112610113576004019060443590565b604081019081106001600160401b038211176113db57604052565b634e487b7160e01b600052604160045260246000fd5b606081019081106001600160401b038211176113db57604052565b60c081019081106001600160401b038211176113db57604052565b90601f801991011681019081106001600160401b038211176113db57604052565b6001600160401b0381116113db57601f01601f191660200190565b60405190611470826113c0565b601382527220b2323932b9b9902137b7b59028363ab3b4b760691b6020830152565b90815180825260208080930193019160005b8281106114b2575050505090565b83516001600160e01b031916855293810193928101926001016114a4565b805160058110156114f6576040918291845260ff60208201511660208501520151910152565b634e487b7160e01b600052602160045260246000fd5b90815180825260208080930193019160005b82811061152c575050505090565b9091929382608060019261155483895163ffffffff60e01b81511684520151848301906114d0565b0195019392910161151e565b602090602060408183019282815285518094520193019160005b828110611588575050505090565b83516001600160a01b03168552938101939281019260010161157a565b91908110156115b55760051b0190565b634e487b7160e01b600052603260045260246000fd5b356001600160a01b03811681036101135790565b909160406020928260208201602083525201929160005b828110611604575050505090565b909192938280600192838060a01b0361161c8961126e565b168152019501939291016115f6565b6001600160401b0381116113db5760051b60200190565b929161164d8261162b565b9161165b6040519384611427565b829481845260208094019160051b810192831161011357905b8282106116815750505050565b83809161168d8461126e565b815201910190611674565b9080601f83011215610113578160206116b393359101611642565b90565b81601f82011215610113578035906116cd82611448565b926116db6040519485611427565b8284526020838301011161011357816000926020809301838601378301015290565b91608083830312610113576001600160401b039083358281116101135783611726918601611698565b936020938482013584811161011357820181601f820112156101135780359061174e8261162b565b9161175c6040519384611427565b808352878084019160051b830101918483116101135788809101915b83831061181a57505050509460408301358581116101135783019082601f830112156101135781356117a98161162b565b926117b76040519485611427565b818452828085019260051b8201019185831161011357838201905b8382106117f5575050505050936060830135908111610113576116b39201611698565b81358a811161011357859161180f898480948801016116b6565b8152019101906117d2565b8235815291810191899101611778565b8051156115b55760200190565b8051600110156115b55760400190565b8051600210156115b55760600190565b8051600310156115b55760800190565b8051600410156115b55760a00190565b80518210156115b55760209160051b010190565b6080818303126101135761189e8161126e565b926020820135926040830135906001600160401b038211610113576118ca6060916116b39386016116b6565b930161126e565b9092919060019060ff16818103611946575050816004116101135760046118fb928201910161188b565b6001600160a01b03169392506119149150839050611f47565b1561191d575050565b6040516375f4229560e11b81526001600160a01b03918216600482015291166024820152604490fd5b909391929060031461196457604051634851657960e11b8152600490fd5b6004928160041161011357600461197e92820191016116fd565b949250505082519260005b84811061199857505050505050565b6001600160a01b036119b5816119ae8486611877565b5116611f47565b156119c257508501611989565b906119d09061116393611877565b51604080516375f4229560e11b81526001600160a01b039687169581019586529290911690941660208401529283920190565b6040516384b9b37960e01b81526000356001600160e01b031916600482015260ff9091166024820152604490fd5b60405190608082018281106001600160401b038211176113db57604052606080838181528160208201528160408201520152565b60405190611a72826113c0565b600f82526e1059191c995cdcd09bdbdad4995859608a1b6020830152565b60405190611a9d826113c0565b601082526f41646472657373426f6f6b577269746560801b6020830152565b903590601e198136030182121561011357018035906001600160401b0382116101135760200191813603831361011357565b60ff1680611b425750806060611b05920190611abc565b8060041161011357816004611b2092611b339401910161188b565b6001600160a01b03169250611f47915050565b15611b3d57600090565b600190565b600214611b5b57604051634851657960e11b8152600490fd5b806060611b69920190611abc565b9081600411610113576004611b8192820191016116fd565b9250505080519060005b828110611b9a57505050600090565b611baf6001600160a01b036119ae8385611877565b15611bbc57600101611b8b565b505050600190565b6040519061018082018281106001600160401b038211176113db5760405281610160606091828152826020820152826040820152828082015260006080820152600060a08201528260c08201528260e08201528261010082015282610120820152826101408201520152565b6040906040519160a083018381106001600160401b038211176113db57604052600483528260005b60808110611c6557505050565b6020908351611c73816113c0565b60008152828551611c83816113f1565b6000815260008282015260008782015281830152828501015201611c58565b60409060405191611cb28361140c565b600583528260005b60a08110611cc757505050565b6020908351611cd5816113c0565b60008152828551611ce5816113f1565b6000815260008282015260008782015281830152828501015201611cba565b600260005414611d15576002600055565b604051633ee5aeb560e01b8152600490fd5b92919093611d3481611f47565b15611e2e575081906040519485946338997b1160e01b865260018060a01b031660048601526024850152606060448501528160648501526084840137816084600094838683819684010152601f8019910116810103018183335af1918215611e22578092611da157505090565b9091503d8082843e611db38184611427565b820191602081840312611e1a578051906001600160401b038211611e1e570182601f82011215611e1a57805191611de983611448565b93611df76040519586611427565b83855260208484010111611e175750906116b391602080850191016112af565b80fd5b5080fd5b8280fd5b604051903d90823e3d90fd5b6040516375f4229560e11b81523360048201526001600160a01b03919091166024820152604490fd5b919061ffff1916916040519060018060a01b03168152637c9c64bb60e11b60208201526001908160408201526060810190848252608090608081209182549187158015611f3f575b611f335785600087805b611ebd575b50600099505050505050505050565b15611f0b575b50855281812080549060009061fffe1980841691908c8314611eeb5750509088929192611ea9565b9450969750509697985092915061fffc6002831693169116171790555590565b878116159081611f29575b5015611f225738611ec3565b8080611eae565b9050151538611f16565b50600096505050505050565b508215611e9f565b6001600160a01b03811615908115611f5d575090565b60408051338152637c9c64bb60e11b602082015260019181019190915260809250906bffffffffffffffffffffffff199060601b1660608201522054151590565b80519060005b828110611fb057505050565b611fd66bffffffffffffffffffffffff19611fcb8385611877565b5160601b1633612027565b15611fe357600101611fa4565b611163916001600160a01b0391611ff991611877565b51604051635b01bbf160e01b815233600482015291166001600160a01b031660248201529081906044820190565b9061ffff19169081156120af57604080516001600160a01b039092168252637c9c64bb60e11b6020830152600190820152606081018281526080822080549092906120a65760016080925220918254928315801561209c575b1561209057600193505555600190565b90600217905555600190565b5060018416612080565b50505050600090565b5050600090565b604080516001600160a01b039092168252637c9c64bb60e11b60208301526001828201819052606083018181526080808520549351808201969560009591949391929186855b612116575b5050505050820160051b016080016040528252565b90919293968588161580612169575b156121635761fffe198816908601600581901b88018601829052976002161561215b57825283832054855b9493929190946120fc565b508085612150565b96612101565b50871515612125565b805160005b81811061218357505090565b8061219060019285611877565b5160601c61219e8286611877565b520161217756fea264697066735822122014abbb6566c58fe6471ec28a916579496934460972bc5ded953ad26ad9cd0fc664736f6c63430008180033",
}

// AddressBookPluginABI is the input ABI used to generate the binding from.
// Deprecated: Use AddressBookPluginMetaData.ABI instead.
var AddressBookPluginABI = AddressBookPluginMetaData.ABI

// AddressBookPluginBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use AddressBookPluginMetaData.Bin instead.
var AddressBookPluginBin = AddressBookPluginMetaData.Bin

// DeployAddressBookPlugin deploys a new Ethereum contract, binding an instance of AddressBookPlugin to it.
func DeployAddressBookPlugin(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *AddressBookPlugin, error) {
	parsed, err := AddressBookPluginMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(AddressBookPluginBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &AddressBookPlugin{AddressBookPluginCaller: AddressBookPluginCaller{contract: contract}, AddressBookPluginTransactor: AddressBookPluginTransactor{contract: contract}, AddressBookPluginFilterer: AddressBookPluginFilterer{contract: contract}}, nil
}

// AddressBookPlugin is an auto generated Go binding around an Ethereum contract.
type AddressBookPlugin struct {
	AddressBookPluginCaller     // Read-only binding to the contract
	AddressBookPluginTransactor // Write-only binding to the contract
	AddressBookPluginFilterer   // Log filterer for contract events
}

// AddressBookPluginCaller is an auto generated read-only Go binding around an Ethereum contract.
type AddressBookPluginCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AddressBookPluginTransactor is an auto generated write-only Go binding around an Ethereum contract.
type AddressBookPluginTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AddressBookPluginFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type AddressBookPluginFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AddressBookPluginSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type AddressBookPluginSession struct {
	Contract     *AddressBookPlugin // Generic contract binding to set the session for
	CallOpts     bind.CallOpts      // Call options to use throughout this session
	TransactOpts bind.TransactOpts  // Transaction auth options to use throughout this session
}

// AddressBookPluginCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type AddressBookPluginCallerSession struct {
	Contract *AddressBookPluginCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts            // Call options to use throughout this session
}

// AddressBookPluginTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type AddressBookPluginTransactorSession struct {
	Contract     *AddressBookPluginTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts            // Transaction auth options to use throughout this session
}

// AddressBookPluginRaw is an auto generated low-level Go binding around an Ethereum contract.
type AddressBookPluginRaw struct {
	Contract *AddressBookPlugin // Generic contract binding to access the raw methods on
}

// AddressBookPluginCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type AddressBookPluginCallerRaw struct {
	Contract *AddressBookPluginCaller // Generic read-only contract binding to access the raw methods on
}

// AddressBookPluginTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type AddressBookPluginTransactorRaw struct {
	Contract *AddressBookPluginTransactor // Generic write-only contract binding to access the raw methods on
}

// NewAddressBookPlugin creates a new instance of AddressBookPlugin, bound to a specific deployed contract.
func NewAddressBookPlugin(address common.Address, backend bind.ContractBackend) (*AddressBookPlugin, error) {
	contract, err := bindAddressBookPlugin(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &AddressBookPlugin{AddressBookPluginCaller: AddressBookPluginCaller{contract: contract}, AddressBookPluginTransactor: AddressBookPluginTransactor{contract: contract}, AddressBookPluginFilterer: AddressBookPluginFilterer{contract: contract}}, nil
}

// NewAddressBookPluginCaller creates a new read-only instance of AddressBookPlugin, bound to a specific deployed contract.
func NewAddressBookPluginCaller(address common.Address, caller bind.ContractCaller) (*AddressBookPluginCaller, error) {
	contract, err := bindAddressBookPlugin(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &AddressBookPluginCaller{contract: contract}, nil
}

// NewAddressBookPluginTransactor creates a new write-only instance of AddressBookPlugin, bound to a specific deployed contract.
func NewAddressBookPluginTransactor(address common.Address, transactor bind.ContractTransactor) (*AddressBookPluginTransactor, error) {
	contract, err := bindAddressBookPlugin(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &AddressBookPluginTransactor{contract: contract}, nil
}

// NewAddressBookPluginFilterer creates a new log filterer instance of AddressBookPlugin, bound to a specific deployed contract.
func NewAddressBookPluginFilterer(address common.Address, filterer bind.ContractFilterer) (*AddressBookPluginFilterer, error) {
	contract, err := bindAddressBookPlugin(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &AddressBookPluginFilterer{contract: contract}, nil
}

// bindAddressBookPlugin binds a generic wrapper to an already deployed contract.
func bindAddressBookPlugin(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := AddressBookPluginMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_AddressBookPlugin *AddressBookPluginRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _AddressBookPlugin.Contract.AddressBookPluginCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_AddressBookPlugin *AddressBookPluginRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AddressBookPlugin.Contract.AddressBookPluginTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_AddressBookPlugin *AddressBookPluginRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _AddressBookPlugin.Contract.AddressBookPluginTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_AddressBookPlugin *AddressBookPluginCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _AddressBookPlugin.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_AddressBookPlugin *AddressBookPluginTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AddressBookPlugin.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_AddressBookPlugin *AddressBookPluginTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _AddressBookPlugin.Contract.contract.Transact(opts, method, params...)
}

// NAME is a free data retrieval call binding the contract method 0xa3f4df7e.
//
// Solidity: function NAME() view returns(string)
func (_AddressBookPlugin *AddressBookPluginCaller) NAME(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _AddressBookPlugin.contract.Call(opts, &out, "NAME")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// NAME is a free data retrieval call binding the contract method 0xa3f4df7e.
//
// Solidity: function NAME() view returns(string)
func (_AddressBookPlugin *AddressBookPluginSession) NAME() (string, error) {
	return _AddressBookPlugin.Contract.NAME(&_AddressBookPlugin.CallOpts)
}

// NAME is a free data retrieval call binding the contract method 0xa3f4df7e.
//
// Solidity: function NAME() view returns(string)
func (_AddressBookPlugin *AddressBookPluginCallerSession) NAME() (string, error) {
	return _AddressBookPlugin.Contract.NAME(&_AddressBookPlugin.CallOpts)
}

// GetAllowedRecipients is a free data retrieval call binding the contract method 0xcf01c349.
//
// Solidity: function getAllowedRecipients(address account) view returns(address[])
func (_AddressBookPlugin *AddressBookPluginCaller) GetAllowedRecipients(opts *bind.CallOpts, account common.Address) ([]common.Address, error) {
	var out []interface{}
	err := _AddressBookPlugin.contract.Call(opts, &out, "getAllowedRecipients", account)

	if err != nil {
		return *new([]common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new([]common.Address)).(*[]common.Address)

	return out0, err

}

// GetAllowedRecipients is a free data retrieval call binding the contract method 0xcf01c349.
//
// Solidity: function getAllowedRecipients(address account) view returns(address[])
func (_AddressBookPlugin *AddressBookPluginSession) GetAllowedRecipients(account common.Address) ([]common.Address, error) {
	return _AddressBookPlugin.Contract.GetAllowedRecipients(&_AddressBookPlugin.CallOpts, account)
}

// GetAllowedRecipients is a free data retrieval call binding the contract method 0xcf01c349.
//
// Solidity: function getAllowedRecipients(address account) view returns(address[])
func (_AddressBookPlugin *AddressBookPluginCallerSession) GetAllowedRecipients(account common.Address) ([]common.Address, error) {
	return _AddressBookPlugin.Contract.GetAllowedRecipients(&_AddressBookPlugin.CallOpts, account)
}

// PluginManifest is a free data retrieval call binding the contract method 0xc7763130.
//
// Solidity: function pluginManifest() pure returns((bytes4[],bytes4[],bytes4[],bytes4[],bool,bool,(address,bool,bytes4[])[],(bytes4,(uint8,uint8,uint256))[],(bytes4,(uint8,uint8,uint256))[],(bytes4,(uint8,uint8,uint256))[],(bytes4,(uint8,uint8,uint256))[],(bytes4,(uint8,uint8,uint256),(uint8,uint8,uint256))[]))
func (_AddressBookPlugin *AddressBookPluginCaller) PluginManifest(opts *bind.CallOpts) (PluginManifest, error) {
	var out []interface{}
	err := _AddressBookPlugin.contract.Call(opts, &out, "pluginManifest")

	if err != nil {
		return *new(PluginManifest), err
	}

	out0 := *abi.ConvertType(out[0], new(PluginManifest)).(*PluginManifest)

	return out0, err

}

// PluginManifest is a free data retrieval call binding the contract method 0xc7763130.
//
// Solidity: function pluginManifest() pure returns((bytes4[],bytes4[],bytes4[],bytes4[],bool,bool,(address,bool,bytes4[])[],(bytes4,(uint8,uint8,uint256))[],(bytes4,(uint8,uint8,uint256))[],(bytes4,(uint8,uint8,uint256))[],(bytes4,(uint8,uint8,uint256))[],(bytes4,(uint8,uint8,uint256),(uint8,uint8,uint256))[]))
func (_AddressBookPlugin *AddressBookPluginSession) PluginManifest() (PluginManifest, error) {
	return _AddressBookPlugin.Contract.PluginManifest(&_AddressBookPlugin.CallOpts)
}

// PluginManifest is a free data retrieval call binding the contract method 0xc7763130.
//
// Solidity: function pluginManifest() pure returns((bytes4[],bytes4[],bytes4[],bytes4[],bool,bool,(address,bool,bytes4[])[],(bytes4,(uint8,uint8,uint256))[],(bytes4,(uint8,uint8,uint256))[],(bytes4,(uint8,uint8,uint256))[],(bytes4,(uint8,uint8,uint256))[],(bytes4,(uint8,uint8,uint256),(uint8,uint8,uint256))[]))
func (_AddressBookPlugin *AddressBookPluginCallerSession) PluginManifest() (PluginManifest, error) {
	return _AddressBookPlugin.Contract.PluginManifest(&_AddressBookPlugin.CallOpts)
}

// PluginMetadata is a free data retrieval call binding the contract method 0x118a5389.
//
// Solidity: function pluginMetadata() pure returns((string,string,string,(bytes4,string)[]))
func (_AddressBookPlugin *AddressBookPluginCaller) PluginMetadata(opts *bind.CallOpts) (PluginMetadata, error) {
	var out []interface{}
	err := _AddressBookPlugin.contract.Call(opts, &out, "pluginMetadata")

	if err != nil {
		return *new(PluginMetadata), err
	}

	out0 := *abi.ConvertType(out[0], new(PluginMetadata)).(*PluginMetadata)

	return out0, err

}

// PluginMetadata is a free data retrieval call binding the contract method 0x118a5389.
//
// Solidity: function pluginMetadata() pure returns((string,string,string,(bytes4,string)[]))
func (_AddressBookPlugin *AddressBookPluginSession) PluginMetadata() (PluginMetadata, error) {
	return _AddressBookPlugin.Contract.PluginMetadata(&_AddressBookPlugin.CallOpts)
}

// PluginMetadata is a free data retrieval call binding the contract method 0x118a5389.
//
// Solidity: function pluginMetadata() pure returns((string,string,string,(bytes4,string)[]))
func (_AddressBookPlugin *AddressBookPluginCallerSession) PluginMetadata() (PluginMetadata, error) {
	return _AddressBookPlugin.Contract.PluginMetadata(&_AddressBookPlugin.CallOpts)
}

// PreRuntimeValidationHook is a free data retrieval call binding the contract method 0x0c7ecd84.
//
// Solidity: function preRuntimeValidationHook(uint8 functionId, address sender, uint256 value, bytes data) view returns()
func (_AddressBookPlugin *AddressBookPluginCaller) PreRuntimeValidationHook(opts *bind.CallOpts, functionId uint8, sender common.Address, value *big.Int, data []byte) error {
	var out []interface{}
	err := _AddressBookPlugin.contract.Call(opts, &out, "preRuntimeValidationHook", functionId, sender, value, data)

	if err != nil {
		return err
	}

	return err

}

// PreRuntimeValidationHook is a free data retrieval call binding the contract method 0x0c7ecd84.
//
// Solidity: function preRuntimeValidationHook(uint8 functionId, address sender, uint256 value, bytes data) view returns()
func (_AddressBookPlugin *AddressBookPluginSession) PreRuntimeValidationHook(functionId uint8, sender common.Address, value *big.Int, data []byte) error {
	return _AddressBookPlugin.Contract.PreRuntimeValidationHook(&_AddressBookPlugin.CallOpts, functionId, sender, value, data)
}

// PreRuntimeValidationHook is a free data retrieval call binding the contract method 0x0c7ecd84.
//
// Solidity: function preRuntimeValidationHook(uint8 functionId, address sender, uint256 value, bytes data) view returns()
func (_AddressBookPlugin *AddressBookPluginCallerSession) PreRuntimeValidationHook(functionId uint8, sender common.Address, value *big.Int, data []byte) error {
	return _AddressBookPlugin.Contract.PreRuntimeValidationHook(&_AddressBookPlugin.CallOpts, functionId, sender, value, data)
}

// PreUserOpValidationHook is a free data retrieval call binding the contract method 0x15b76b84.
//
// Solidity: function preUserOpValidationHook(uint8 functionId, (address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes) userOp, bytes32 userOpHash) view returns(uint256 validationData)
func (_AddressBookPlugin *AddressBookPluginCaller) PreUserOpValidationHook(opts *bind.CallOpts, functionId uint8, userOp PackedUserOperation, userOpHash [32]byte) (*big.Int, error) {
	var out []interface{}
	err := _AddressBookPlugin.contract.Call(opts, &out, "preUserOpValidationHook", functionId, userOp, userOpHash)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// PreUserOpValidationHook is a free data retrieval call binding the contract method 0x15b76b84.
//
// Solidity: function preUserOpValidationHook(uint8 functionId, (address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes) userOp, bytes32 userOpHash) view returns(uint256 validationData)
func (_AddressBookPlugin *AddressBookPluginSession) PreUserOpValidationHook(functionId uint8, userOp PackedUserOperation, userOpHash [32]byte) (*big.Int, error) {
	return _AddressBookPlugin.Contract.PreUserOpValidationHook(&_AddressBookPlugin.CallOpts, functionId, userOp, userOpHash)
}

// PreUserOpValidationHook is a free data retrieval call binding the contract method 0x15b76b84.
//
// Solidity: function preUserOpValidationHook(uint8 functionId, (address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes) userOp, bytes32 userOpHash) view returns(uint256 validationData)
func (_AddressBookPlugin *AddressBookPluginCallerSession) PreUserOpValidationHook(functionId uint8, userOp PackedUserOperation, userOpHash [32]byte) (*big.Int, error) {
	return _AddressBookPlugin.Contract.PreUserOpValidationHook(&_AddressBookPlugin.CallOpts, functionId, userOp, userOpHash)
}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_AddressBookPlugin *AddressBookPluginCaller) SupportsInterface(opts *bind.CallOpts, interfaceId [4]byte) (bool, error) {
	var out []interface{}
	err := _AddressBookPlugin.contract.Call(opts, &out, "supportsInterface", interfaceId)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_AddressBookPlugin *AddressBookPluginSession) SupportsInterface(interfaceId [4]byte) (bool, error) {
	return _AddressBookPlugin.Contract.SupportsInterface(&_AddressBookPlugin.CallOpts, interfaceId)
}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_AddressBookPlugin *AddressBookPluginCallerSession) SupportsInterface(interfaceId [4]byte) (bool, error) {
	return _AddressBookPlugin.Contract.SupportsInterface(&_AddressBookPlugin.CallOpts, interfaceId)
}

// AddAllowedRecipients is a paid mutator transaction binding the contract method 0x47b19eee.
//
// Solidity: function addAllowedRecipients(address[] recipients) returns()
func (_AddressBookPlugin *AddressBookPluginTransactor) AddAllowedRecipients(opts *bind.TransactOpts, recipients []common.Address) (*types.Transaction, error) {
	return _AddressBookPlugin.contract.Transact(opts, "addAllowedRecipients", recipients)
}

// AddAllowedRecipients is a paid mutator transaction binding the contract method 0x47b19eee.
//
// Solidity: function addAllowedRecipients(address[] recipients) returns()
func (_AddressBookPlugin *AddressBookPluginSession) AddAllowedRecipients(recipients []common.Address) (*types.Transaction, error) {
	return _AddressBookPlugin.Contract.AddAllowedRecipients(&_AddressBookPlugin.TransactOpts, recipients)
}

// AddAllowedRecipients is a paid mutator transaction binding the contract method 0x47b19eee.
//
// Solidity: function addAllowedRecipients(address[] recipients) returns()
func (_AddressBookPlugin *AddressBookPluginTransactorSession) AddAllowedRecipients(recipients []common.Address) (*types.Transaction, error) {
	return _AddressBookPlugin.Contract.AddAllowedRecipients(&_AddressBookPlugin.TransactOpts, recipients)
}

// ExecuteBatchWithAddressBook is a paid mutator transaction binding the contract method 0xb1c46f4a.
//
// Solidity: function executeBatchWithAddressBook(address[] target, uint256[] value, bytes[] data, address[] recipients) returns(bytes[])
func (_AddressBookPlugin *AddressBookPluginTransactor) ExecuteBatchWithAddressBook(opts *bind.TransactOpts, target []common.Address, value []*big.Int, data [][]byte, recipients []common.Address) (*types.Transaction, error) {
	return _AddressBookPlugin.contract.Transact(opts, "executeBatchWithAddressBook", target, value, data, recipients)
}

// ExecuteBatchWithAddressBook is a paid mutator transaction binding the contract method 0xb1c46f4a.
//
// Solidity: function executeBatchWithAddressBook(address[] target, uint256[] value, bytes[] data, address[] recipients) returns(bytes[])
func (_AddressBookPlugin *AddressBookPluginSession) ExecuteBatchWithAddressBook(target []common.Address, value []*big.Int, data [][]byte, recipients []common.Address) (*types.Transaction, error) {
	return _AddressBookPlugin.Contract.ExecuteBatchWithAddressBook(&_AddressBookPlugin.TransactOpts, target, value, data, recipients)
}

// ExecuteBatchWithAddressBook is a paid mutator transaction binding the contract method 0xb1c46f4a.
//
// Solidity: function executeBatchWithAddressBook(address[] target, uint256[] value, bytes[] data, address[] recipients) returns(bytes[])
func (_AddressBookPlugin *AddressBookPluginTransactorSession) ExecuteBatchWithAddressBook(target []common.Address, value []*big.Int, data [][]byte, recipients []common.Address) (*types.Transaction, error) {
	return _AddressBookPlugin.Contract.ExecuteBatchWithAddressBook(&_AddressBookPlugin.TransactOpts, target, value, data, recipients)
}

// ExecuteWithAddressBook is a paid mutator transaction binding the contract method 0x01fcb2fc.
//
// Solidity: function executeWithAddressBook(address target, uint256 value, bytes data, address recipient) returns(bytes)
func (_AddressBookPlugin *AddressBookPluginTransactor) ExecuteWithAddressBook(opts *bind.TransactOpts, target common.Address, value *big.Int, data []byte, recipient common.Address) (*types.Transaction, error) {
	return _AddressBookPlugin.contract.Transact(opts, "executeWithAddressBook", target, value, data, recipient)
}

// ExecuteWithAddressBook is a paid mutator transaction binding the contract method 0x01fcb2fc.
//
// Solidity: function executeWithAddressBook(address target, uint256 value, bytes data, address recipient) returns(bytes)
func (_AddressBookPlugin *AddressBookPluginSession) ExecuteWithAddressBook(target common.Address, value *big.Int, data []byte, recipient common.Address) (*types.Transaction, error) {
	return _AddressBookPlugin.Contract.ExecuteWithAddressBook(&_AddressBookPlugin.TransactOpts, target, value, data, recipient)
}

// ExecuteWithAddressBook is a paid mutator transaction binding the contract method 0x01fcb2fc.
//
// Solidity: function executeWithAddressBook(address target, uint256 value, bytes data, address recipient) returns(bytes)
func (_AddressBookPlugin *AddressBookPluginTransactorSession) ExecuteWithAddressBook(target common.Address, value *big.Int, data []byte, recipient common.Address) (*types.Transaction, error) {
	return _AddressBookPlugin.Contract.ExecuteWithAddressBook(&_AddressBookPlugin.TransactOpts, target, value, data, recipient)
}

// OnInstall is a paid mutator transaction binding the contract method 0x6d61fe70.
//
// Solidity: function onInstall(bytes data) returns()
func (_AddressBookPlugin *AddressBookPluginTransactor) OnInstall(opts *bind.TransactOpts, data []byte) (*types.Transaction, error) {
	return _AddressBookPlugin.contract.Transact(opts, "onInstall", data)
}

// OnInstall is a paid mutator transaction binding the contract method 0x6d61fe70.
//
// Solidity: function onInstall(bytes data) returns()
func (_AddressBookPlugin *AddressBookPluginSession) OnInstall(data []byte) (*types.Transaction, error) {
	return _AddressBookPlugin.Contract.OnInstall(&_AddressBookPlugin.TransactOpts, data)
}

// OnInstall is a paid mutator transaction binding the contract method 0x6d61fe70.
//
// Solidity: function onInstall(bytes data) returns()
func (_AddressBookPlugin *AddressBookPluginTransactorSession) OnInstall(data []byte) (*types.Transaction, error) {
	return _AddressBookPlugin.Contract.OnInstall(&_AddressBookPlugin.TransactOpts, data)
}

// OnUninstall is a paid mutator transaction binding the contract method 0x8a91b0e3.
//
// Solidity: function onUninstall(bytes data) returns()
func (_AddressBookPlugin *AddressBookPluginTransactor) OnUninstall(opts *bind.TransactOpts, data []byte) (*types.Transaction, error) {
	return _AddressBookPlugin.contract.Transact(opts, "onUninstall", data)
}

// OnUninstall is a paid mutator transaction binding the contract method 0x8a91b0e3.
//
// Solidity: function onUninstall(bytes data) returns()
func (_AddressBookPlugin *AddressBookPluginSession) OnUninstall(data []byte) (*types.Transaction, error) {
	return _AddressBookPlugin.Contract.OnUninstall(&_AddressBookPlugin.TransactOpts, data)
}

// OnUninstall is a paid mutator transaction binding the contract method 0x8a91b0e3.
//
// Solidity: function onUninstall(bytes data) returns()
func (_AddressBookPlugin *AddressBookPluginTransactorSession) OnUninstall(data []byte) (*types.Transaction, error) {
	return _AddressBookPlugin.Contract.OnUninstall(&_AddressBookPlugin.TransactOpts, data)
}

// PostExecutionHook is a paid mutator transaction binding the contract method 0x1128186d.
//
// Solidity: function postExecutionHook(uint8 functionId, bytes preExecHookData) returns()
func (_AddressBookPlugin *AddressBookPluginTransactor) PostExecutionHook(opts *bind.TransactOpts, functionId uint8, preExecHookData []byte) (*types.Transaction, error) {
	return _AddressBookPlugin.contract.Transact(opts, "postExecutionHook", functionId, preExecHookData)
}

// PostExecutionHook is a paid mutator transaction binding the contract method 0x1128186d.
//
// Solidity: function postExecutionHook(uint8 functionId, bytes preExecHookData) returns()
func (_AddressBookPlugin *AddressBookPluginSession) PostExecutionHook(functionId uint8, preExecHookData []byte) (*types.Transaction, error) {
	return _AddressBookPlugin.Contract.PostExecutionHook(&_AddressBookPlugin.TransactOpts, functionId, preExecHookData)
}

// PostExecutionHook is a paid mutator transaction binding the contract method 0x1128186d.
//
// Solidity: function postExecutionHook(uint8 functionId, bytes preExecHookData) returns()
func (_AddressBookPlugin *AddressBookPluginTransactorSession) PostExecutionHook(functionId uint8, preExecHookData []byte) (*types.Transaction, error) {
	return _AddressBookPlugin.Contract.PostExecutionHook(&_AddressBookPlugin.TransactOpts, functionId, preExecHookData)
}

// PreExecutionHook is a paid mutator transaction binding the contract method 0x46d60eb2.
//
// Solidity: function preExecutionHook(uint8 functionId, address sender, uint256 value, bytes data) returns(bytes context)
func (_AddressBookPlugin *AddressBookPluginTransactor) PreExecutionHook(opts *bind.TransactOpts, functionId uint8, sender common.Address, value *big.Int, data []byte) (*types.Transaction, error) {
	return _AddressBookPlugin.contract.Transact(opts, "preExecutionHook", functionId, sender, value, data)
}

// PreExecutionHook is a paid mutator transaction binding the contract method 0x46d60eb2.
//
// Solidity: function preExecutionHook(uint8 functionId, address sender, uint256 value, bytes data) returns(bytes context)
func (_AddressBookPlugin *AddressBookPluginSession) PreExecutionHook(functionId uint8, sender common.Address, value *big.Int, data []byte) (*types.Transaction, error) {
	return _AddressBookPlugin.Contract.PreExecutionHook(&_AddressBookPlugin.TransactOpts, functionId, sender, value, data)
}

// PreExecutionHook is a paid mutator transaction binding the contract method 0x46d60eb2.
//
// Solidity: function preExecutionHook(uint8 functionId, address sender, uint256 value, bytes data) returns(bytes context)
func (_AddressBookPlugin *AddressBookPluginTransactorSession) PreExecutionHook(functionId uint8, sender common.Address, value *big.Int, data []byte) (*types.Transaction, error) {
	return _AddressBookPlugin.Contract.PreExecutionHook(&_AddressBookPlugin.TransactOpts, functionId, sender, value, data)
}

// RemoveAllowedRecipients is a paid mutator transaction binding the contract method 0x0ae779e1.
//
// Solidity: function removeAllowedRecipients(address[] recipients) returns()
func (_AddressBookPlugin *AddressBookPluginTransactor) RemoveAllowedRecipients(opts *bind.TransactOpts, recipients []common.Address) (*types.Transaction, error) {
	return _AddressBookPlugin.contract.Transact(opts, "removeAllowedRecipients", recipients)
}

// RemoveAllowedRecipients is a paid mutator transaction binding the contract method 0x0ae779e1.
//
// Solidity: function removeAllowedRecipients(address[] recipients) returns()
func (_AddressBookPlugin *AddressBookPluginSession) RemoveAllowedRecipients(recipients []common.Address) (*types.Transaction, error) {
	return _AddressBookPlugin.Contract.RemoveAllowedRecipients(&_AddressBookPlugin.TransactOpts, recipients)
}

// RemoveAllowedRecipients is a paid mutator transaction binding the contract method 0x0ae779e1.
//
// Solidity: function removeAllowedRecipients(address[] recipients) returns()
func (_AddressBookPlugin *AddressBookPluginTransactorSession) RemoveAllowedRecipients(recipients []common.Address) (*types.Transaction, error) {
	return _AddressBookPlugin.Contract.RemoveAllowedRecipients(&_AddressBookPlugin.TransactOpts, recipients)
}

// RuntimeValidationFunction is a paid mutator transaction binding the contract method 0xbfd151c1.
//
// Solidity: function runtimeValidationFunction(uint8 functionId, address sender, uint256 value, bytes data) returns()
func (_AddressBookPlugin *AddressBookPluginTransactor) RuntimeValidationFunction(opts *bind.TransactOpts, functionId uint8, sender common.Address, value *big.Int, data []byte) (*types.Transaction, error) {
	return _AddressBookPlugin.contract.Transact(opts, "runtimeValidationFunction", functionId, sender, value, data)
}

// RuntimeValidationFunction is a paid mutator transaction binding the contract method 0xbfd151c1.
//
// Solidity: function runtimeValidationFunction(uint8 functionId, address sender, uint256 value, bytes data) returns()
func (_AddressBookPlugin *AddressBookPluginSession) RuntimeValidationFunction(functionId uint8, sender common.Address, value *big.Int, data []byte) (*types.Transaction, error) {
	return _AddressBookPlugin.Contract.RuntimeValidationFunction(&_AddressBookPlugin.TransactOpts, functionId, sender, value, data)
}

// RuntimeValidationFunction is a paid mutator transaction binding the contract method 0xbfd151c1.
//
// Solidity: function runtimeValidationFunction(uint8 functionId, address sender, uint256 value, bytes data) returns()
func (_AddressBookPlugin *AddressBookPluginTransactorSession) RuntimeValidationFunction(functionId uint8, sender common.Address, value *big.Int, data []byte) (*types.Transaction, error) {
	return _AddressBookPlugin.Contract.RuntimeValidationFunction(&_AddressBookPlugin.TransactOpts, functionId, sender, value, data)
}

// UserOpValidationFunction is a paid mutator transaction binding the contract method 0xc4db8dd9.
//
// Solidity: function userOpValidationFunction(uint8 functionId, (address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes) userOp, bytes32 userOpHash) returns(uint256 validationData)
func (_AddressBookPlugin *AddressBookPluginTransactor) UserOpValidationFunction(opts *bind.TransactOpts, functionId uint8, userOp PackedUserOperation, userOpHash [32]byte) (*types.Transaction, error) {
	return _AddressBookPlugin.contract.Transact(opts, "userOpValidationFunction", functionId, userOp, userOpHash)
}

// UserOpValidationFunction is a paid mutator transaction binding the contract method 0xc4db8dd9.
//
// Solidity: function userOpValidationFunction(uint8 functionId, (address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes) userOp, bytes32 userOpHash) returns(uint256 validationData)
func (_AddressBookPlugin *AddressBookPluginSession) UserOpValidationFunction(functionId uint8, userOp PackedUserOperation, userOpHash [32]byte) (*types.Transaction, error) {
	return _AddressBookPlugin.Contract.UserOpValidationFunction(&_AddressBookPlugin.TransactOpts, functionId, userOp, userOpHash)
}

// UserOpValidationFunction is a paid mutator transaction binding the contract method 0xc4db8dd9.
//
// Solidity: function userOpValidationFunction(uint8 functionId, (address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes) userOp, bytes32 userOpHash) returns(uint256 validationData)
func (_AddressBookPlugin *AddressBookPluginTransactorSession) UserOpValidationFunction(functionId uint8, userOp PackedUserOperation, userOpHash [32]byte) (*types.Transaction, error) {
	return _AddressBookPlugin.Contract.UserOpValidationFunction(&_AddressBookPlugin.TransactOpts, functionId, userOp, userOpHash)
}

// AddressBookPluginAllowedAddressesAddedIterator is returned from FilterAllowedAddressesAdded and is used to iterate over the raw logs and unpacked data for AllowedAddressesAdded events raised by the AddressBookPlugin contract.
type AddressBookPluginAllowedAddressesAddedIterator struct {
	Event *AddressBookPluginAllowedAddressesAdded // Event containing the contract specifics and raw log

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
func (it *AddressBookPluginAllowedAddressesAddedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(AddressBookPluginAllowedAddressesAdded)
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
		it.Event = new(AddressBookPluginAllowedAddressesAdded)
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
func (it *AddressBookPluginAllowedAddressesAddedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *AddressBookPluginAllowedAddressesAddedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// AddressBookPluginAllowedAddressesAdded represents a AllowedAddressesAdded event raised by the AddressBookPlugin contract.
type AddressBookPluginAllowedAddressesAdded struct {
	Account    common.Address
	Recipients []common.Address
	Raw        types.Log // Blockchain specific contextual infos
}

// FilterAllowedAddressesAdded is a free log retrieval operation binding the contract event 0x2762cf05265ec47ebbfe12ce03afa1f82fa948b789548da6e83f3a083ffb10e4.
//
// Solidity: event AllowedAddressesAdded(address indexed account, address[] recipients)
func (_AddressBookPlugin *AddressBookPluginFilterer) FilterAllowedAddressesAdded(opts *bind.FilterOpts, account []common.Address) (*AddressBookPluginAllowedAddressesAddedIterator, error) {

	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _AddressBookPlugin.contract.FilterLogs(opts, "AllowedAddressesAdded", accountRule)
	if err != nil {
		return nil, err
	}
	return &AddressBookPluginAllowedAddressesAddedIterator{contract: _AddressBookPlugin.contract, event: "AllowedAddressesAdded", logs: logs, sub: sub}, nil
}

// WatchAllowedAddressesAdded is a free log subscription operation binding the contract event 0x2762cf05265ec47ebbfe12ce03afa1f82fa948b789548da6e83f3a083ffb10e4.
//
// Solidity: event AllowedAddressesAdded(address indexed account, address[] recipients)
func (_AddressBookPlugin *AddressBookPluginFilterer) WatchAllowedAddressesAdded(opts *bind.WatchOpts, sink chan<- *AddressBookPluginAllowedAddressesAdded, account []common.Address) (event.Subscription, error) {

	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _AddressBookPlugin.contract.WatchLogs(opts, "AllowedAddressesAdded", accountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(AddressBookPluginAllowedAddressesAdded)
				if err := _AddressBookPlugin.contract.UnpackLog(event, "AllowedAddressesAdded", log); err != nil {
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

// ParseAllowedAddressesAdded is a log parse operation binding the contract event 0x2762cf05265ec47ebbfe12ce03afa1f82fa948b789548da6e83f3a083ffb10e4.
//
// Solidity: event AllowedAddressesAdded(address indexed account, address[] recipients)
func (_AddressBookPlugin *AddressBookPluginFilterer) ParseAllowedAddressesAdded(log types.Log) (*AddressBookPluginAllowedAddressesAdded, error) {
	event := new(AddressBookPluginAllowedAddressesAdded)
	if err := _AddressBookPlugin.contract.UnpackLog(event, "AllowedAddressesAdded", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// AddressBookPluginAllowedAddressesNotRemovedIterator is returned from FilterAllowedAddressesNotRemoved and is used to iterate over the raw logs and unpacked data for AllowedAddressesNotRemoved events raised by the AddressBookPlugin contract.
type AddressBookPluginAllowedAddressesNotRemovedIterator struct {
	Event *AddressBookPluginAllowedAddressesNotRemoved // Event containing the contract specifics and raw log

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
func (it *AddressBookPluginAllowedAddressesNotRemovedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(AddressBookPluginAllowedAddressesNotRemoved)
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
		it.Event = new(AddressBookPluginAllowedAddressesNotRemoved)
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
func (it *AddressBookPluginAllowedAddressesNotRemovedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *AddressBookPluginAllowedAddressesNotRemovedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// AddressBookPluginAllowedAddressesNotRemoved represents a AllowedAddressesNotRemoved event raised by the AddressBookPlugin contract.
type AddressBookPluginAllowedAddressesNotRemoved struct {
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterAllowedAddressesNotRemoved is a free log retrieval operation binding the contract event 0xe7286f689afa21e4be11e804963cab3150095657dda0d218dc22bf2eb0c682ca.
//
// Solidity: event AllowedAddressesNotRemoved(address indexed account)
func (_AddressBookPlugin *AddressBookPluginFilterer) FilterAllowedAddressesNotRemoved(opts *bind.FilterOpts, account []common.Address) (*AddressBookPluginAllowedAddressesNotRemovedIterator, error) {

	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _AddressBookPlugin.contract.FilterLogs(opts, "AllowedAddressesNotRemoved", accountRule)
	if err != nil {
		return nil, err
	}
	return &AddressBookPluginAllowedAddressesNotRemovedIterator{contract: _AddressBookPlugin.contract, event: "AllowedAddressesNotRemoved", logs: logs, sub: sub}, nil
}

// WatchAllowedAddressesNotRemoved is a free log subscription operation binding the contract event 0xe7286f689afa21e4be11e804963cab3150095657dda0d218dc22bf2eb0c682ca.
//
// Solidity: event AllowedAddressesNotRemoved(address indexed account)
func (_AddressBookPlugin *AddressBookPluginFilterer) WatchAllowedAddressesNotRemoved(opts *bind.WatchOpts, sink chan<- *AddressBookPluginAllowedAddressesNotRemoved, account []common.Address) (event.Subscription, error) {

	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _AddressBookPlugin.contract.WatchLogs(opts, "AllowedAddressesNotRemoved", accountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(AddressBookPluginAllowedAddressesNotRemoved)
				if err := _AddressBookPlugin.contract.UnpackLog(event, "AllowedAddressesNotRemoved", log); err != nil {
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

// ParseAllowedAddressesNotRemoved is a log parse operation binding the contract event 0xe7286f689afa21e4be11e804963cab3150095657dda0d218dc22bf2eb0c682ca.
//
// Solidity: event AllowedAddressesNotRemoved(address indexed account)
func (_AddressBookPlugin *AddressBookPluginFilterer) ParseAllowedAddressesNotRemoved(log types.Log) (*AddressBookPluginAllowedAddressesNotRemoved, error) {
	event := new(AddressBookPluginAllowedAddressesNotRemoved)
	if err := _AddressBookPlugin.contract.UnpackLog(event, "AllowedAddressesNotRemoved", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// AddressBookPluginAllowedAddressesRemovedIterator is returned from FilterAllowedAddressesRemoved and is used to iterate over the raw logs and unpacked data for AllowedAddressesRemoved events raised by the AddressBookPlugin contract.
type AddressBookPluginAllowedAddressesRemovedIterator struct {
	Event *AddressBookPluginAllowedAddressesRemoved // Event containing the contract specifics and raw log

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
func (it *AddressBookPluginAllowedAddressesRemovedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(AddressBookPluginAllowedAddressesRemoved)
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
		it.Event = new(AddressBookPluginAllowedAddressesRemoved)
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
func (it *AddressBookPluginAllowedAddressesRemovedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *AddressBookPluginAllowedAddressesRemovedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// AddressBookPluginAllowedAddressesRemoved represents a AllowedAddressesRemoved event raised by the AddressBookPlugin contract.
type AddressBookPluginAllowedAddressesRemoved struct {
	Account    common.Address
	Recipients []common.Address
	Raw        types.Log // Blockchain specific contextual infos
}

// FilterAllowedAddressesRemoved is a free log retrieval operation binding the contract event 0x8342bc442963161fe55b209fbfc4dafccac754f61a43438af2615c68dac75ed3.
//
// Solidity: event AllowedAddressesRemoved(address indexed account, address[] recipients)
func (_AddressBookPlugin *AddressBookPluginFilterer) FilterAllowedAddressesRemoved(opts *bind.FilterOpts, account []common.Address) (*AddressBookPluginAllowedAddressesRemovedIterator, error) {

	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _AddressBookPlugin.contract.FilterLogs(opts, "AllowedAddressesRemoved", accountRule)
	if err != nil {
		return nil, err
	}
	return &AddressBookPluginAllowedAddressesRemovedIterator{contract: _AddressBookPlugin.contract, event: "AllowedAddressesRemoved", logs: logs, sub: sub}, nil
}

// WatchAllowedAddressesRemoved is a free log subscription operation binding the contract event 0x8342bc442963161fe55b209fbfc4dafccac754f61a43438af2615c68dac75ed3.
//
// Solidity: event AllowedAddressesRemoved(address indexed account, address[] recipients)
func (_AddressBookPlugin *AddressBookPluginFilterer) WatchAllowedAddressesRemoved(opts *bind.WatchOpts, sink chan<- *AddressBookPluginAllowedAddressesRemoved, account []common.Address) (event.Subscription, error) {

	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _AddressBookPlugin.contract.WatchLogs(opts, "AllowedAddressesRemoved", accountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(AddressBookPluginAllowedAddressesRemoved)
				if err := _AddressBookPlugin.contract.UnpackLog(event, "AllowedAddressesRemoved", log); err != nil {
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

// ParseAllowedAddressesRemoved is a log parse operation binding the contract event 0x8342bc442963161fe55b209fbfc4dafccac754f61a43438af2615c68dac75ed3.
//
// Solidity: event AllowedAddressesRemoved(address indexed account, address[] recipients)
func (_AddressBookPlugin *AddressBookPluginFilterer) ParseAllowedAddressesRemoved(log types.Log) (*AddressBookPluginAllowedAddressesRemoved, error) {
	event := new(AddressBookPluginAllowedAddressesRemoved)
	if err := _AddressBookPlugin.contract.UnpackLog(event, "AllowedAddressesRemoved", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
