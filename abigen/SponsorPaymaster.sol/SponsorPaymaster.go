// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package SponsorPaymaster

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

// IStakeManagerDepositInfo is an auto generated low-level Go binding around an user-defined struct.
type IStakeManagerDepositInfo struct {
	Deposit         *big.Int
	Staked          bool
	Stake           *big.Int
	UnstakeDelaySec uint32
	WithdrawTime    *big.Int
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

// SponsorPaymasterMetaData contains all meta data concerning the SponsorPaymaster contract.
var SponsorPaymasterMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[{\"name\":\"_newEntryPoint\",\"type\":\"address\",\"internalType\":\"contractIEntryPoint\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"receive\",\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"UPGRADE_INTERFACE_VERSION\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"addStake\",\"inputs\":[{\"name\":\"unstakeDelaySec\",\"type\":\"uint32\",\"internalType\":\"uint32\"}],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"addVerifyingSigners\",\"inputs\":[{\"name\":\"_newVerifyingSigners\",\"type\":\"address[]\",\"internalType\":\"address[]\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"deposit\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"entryPoint\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"contractIEntryPoint\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getAllSigners\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address[]\",\"internalType\":\"address[]\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getDeposit\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getDepositInfo\",\"inputs\":[],\"outputs\":[{\"name\":\"info\",\"type\":\"tuple\",\"internalType\":\"structIStakeManager.DepositInfo\",\"components\":[{\"name\":\"deposit\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"staked\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"stake\",\"type\":\"uint112\",\"internalType\":\"uint112\"},{\"name\":\"unstakeDelaySec\",\"type\":\"uint32\",\"internalType\":\"uint32\"},{\"name\":\"withdrawTime\",\"type\":\"uint48\",\"internalType\":\"uint48\"}]}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getHash\",\"inputs\":[{\"name\":\"userOp\",\"type\":\"tuple\",\"internalType\":\"structPackedUserOperation\",\"components\":[{\"name\":\"sender\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"nonce\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"initCode\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"callData\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"accountGasLimits\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"preVerificationGas\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"gasFees\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"paymasterAndData\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"signature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]},{\"name\":\"validUntil\",\"type\":\"uint48\",\"internalType\":\"uint48\"},{\"name\":\"validAfter\",\"type\":\"uint48\",\"internalType\":\"uint48\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"initialize\",\"inputs\":[{\"name\":\"_newOwner\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_verifyingSigners\",\"type\":\"address[]\",\"internalType\":\"address[]\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"owner\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"parsePaymasterAndData\",\"inputs\":[{\"name\":\"paymasterAndData\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"validUntil\",\"type\":\"uint48\",\"internalType\":\"uint48\"},{\"name\":\"validAfter\",\"type\":\"uint48\",\"internalType\":\"uint48\"},{\"name\":\"signature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"pause\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"paused\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"postOp\",\"inputs\":[{\"name\":\"mode\",\"type\":\"uint8\",\"internalType\":\"enumIPaymaster.PostOpMode\"},{\"name\":\"context\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"actualGasCost\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"actualUserOpFeePerGas\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"proxiableUUID\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"removeVerifyingSigners\",\"inputs\":[{\"name\":\"_verifyingSigners\",\"type\":\"address[]\",\"internalType\":\"address[]\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"renounceOwnership\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"transferOwnership\",\"inputs\":[{\"name\":\"newOwner\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"unlockStake\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"unpause\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"upgradeToAndCall\",\"inputs\":[{\"name\":\"newImplementation\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"validatePaymasterUserOp\",\"inputs\":[{\"name\":\"userOp\",\"type\":\"tuple\",\"internalType\":\"structPackedUserOperation\",\"components\":[{\"name\":\"sender\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"nonce\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"initCode\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"callData\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"accountGasLimits\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"preVerificationGas\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"gasFees\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"paymasterAndData\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"signature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]},{\"name\":\"userOpHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"maxCost\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"context\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"validationData\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"withdrawStake\",\"inputs\":[{\"name\":\"withdrawAddress\",\"type\":\"address\",\"internalType\":\"addresspayable\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"withdrawTo\",\"inputs\":[{\"name\":\"withdrawAddress\",\"type\":\"address\",\"internalType\":\"addresspayable\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"event\",\"name\":\"Initialized\",\"inputs\":[{\"name\":\"version\",\"type\":\"uint64\",\"indexed\":false,\"internalType\":\"uint64\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"OwnershipTransferred\",\"inputs\":[{\"name\":\"previousOwner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"newOwner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"Paused\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"indexed\":false,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"Unpaused\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"indexed\":false,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"Upgraded\",\"inputs\":[{\"name\":\"implementation\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"error\",\"name\":\"AddressEmptyCode\",\"inputs\":[{\"name\":\"target\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"ERC1967InvalidImplementation\",\"inputs\":[{\"name\":\"implementation\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"ERC1967NonPayable\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"EnforcedPause\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"ExpectedPause\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"FailedInnerCall\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"InvalidInitialization\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"NotInitializing\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"OwnableInvalidOwner\",\"inputs\":[{\"name\":\"owner\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"OwnableUnauthorizedAccount\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"UUPSUnauthorizedCallContext\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"UUPSUnsupportedProxiableUUID\",\"inputs\":[{\"name\":\"slot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]},{\"type\":\"error\",\"name\":\"VerifyingSignerAlreadyExists\",\"inputs\":[{\"name\":\"verifyingSigner\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"VerifyingSignerDoesNotExist\",\"inputs\":[{\"name\":\"verifyingSigner\",\"type\":\"address\",\"internalType\":\"address\"}]}]",
	Bin: "0x60c034620000d057601f62001d1138819003918201601f19168301916001600160401b03831184841017620000d557808492602094604052833981010312620000d057516001600160a01b0381168103620000d0573060805260a05262000065620000eb565b6200006f620000eb565b604051611b8690816200018b82396080518181816105a50152610796015260a0518181816101f7015281816102bc01528181610a3601528181610d8901528181610ddd01528181610e6d01528181610ef20152818161137801526114f20152f35b600080fd5b634e487b7160e01b600052604160045260246000fd5b7ff0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00805460ff8160401c1662000178576001600160401b036002600160401b0319828216016200013957505050565b6001600160401b031990911681179091556040519081527fc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d290602090a1565b60405163f92ee8a960e01b8152600490fdfe60806040526004361015610023575b361561001957600080fd5b610021611364565b005b60003560e01c80630396cb60146101b3578063205c2878146101ae5780633f4ba83a146101a957806343e3b518146101a45780634f1ef2861461019f57806352b7512c1461019a57806352d1902d146101955780635829c5f5146101905780635c975abb1461018b578063715018a6146101865780637c627b21146101815780638456cb591461017c5780638969e0f9146101775780638da5cb5b14610172578063946d92041461016d57806394d4ad6014610168578063ad3cb1cc14610163578063b0d691fe1461015e578063bb9fe6bf14610159578063c23a5cea14610154578063c399ec881461014f578063d0e30db01461014a578063d42f2f3514610145578063d88c13e0146101405763f2fde38b0361000e576110d6565b611046565b610f88565b610f6c565b610ec5565b610e34565b610db8565b610d73565b610d1b565b610c79565b610b2f565b610af9565b6109dd565b61096e565b610921565b610889565b610859565b6107fe565b610783565b61071a565b610552565b6103ea565b610320565b610283565b6101cb565b63ffffffff8116036101c657565b600080fd5b6000602036600319011261026f576004356101e5816101b8565b6101ed611451565b6101f561148a565b7f00000000000000000000000000000000000000000000000000000000000000006001600160a01b0316908290823b1561026b57602463ffffffff916040519485938492621cb65b60e51b845216600483015234905af180156102665761025a575080f35b61026390610490565b80f35b611103565b5080fd5b80fd5b6001600160a01b038116036101c657565b346101c6576000604036600319011261026f576004356102a281610272565b6102aa611451565b6102b261148a565b6001600160a01b037f0000000000000000000000000000000000000000000000000000000000000000811691839190833b1561031c5760449083604051958694859363040b850f60e31b855216600484015260243560248401525af180156102665761025a575080f35b8280fd5b346101c65760003660031901126101c657610339611451565b6103416114b5565b6103496114b5565b600080516020611b1183398151915260ff1981541690557f5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa6020604051338152a1005b9181601f840112156101c6578235916001600160401b0383116101c6576020808501948460051b0101116101c657565b60206003198201126101c657600435906001600160401b0382116101c6576103e69160040161038c565b9091565b346101c6576103f8366103bc565b90610401611451565b61040961148a565b60005b82811061041557005b610420818484611125565b3561042a81610272565b6001600160a01b039061043e9082166116d4565b1561044c575060010161040c565b6104596024928585611125565b359061046482610272565b604051630a07962b60e11b815291166004820152fd5b634e487b7160e01b600052604160045260246000fd5b6001600160401b0381116104a357604052565b61047a565b60a081019081106001600160401b038211176104a357604052565b61010081019081106001600160401b038211176104a357604052565b90601f801991011681019081106001600160401b038211176104a357604052565b6001600160401b0381116104a357601f01601f191660200190565b92919261052782610500565b9161053560405193846104df565b8294818452818301116101c6578281602093846000960137010152565b60403660031901126101c657600480359061056c82610272565b6024356001600160401b0381116101c657366023820112156101c65761059b903690602481850135910161051b565b6001600160a01b037f000000000000000000000000000000000000000000000000000000000000000081163081149081156106af575b5061069e5790602083926105e3611451565b6040516352d1902d60e01b8152938491829088165afa6000928161066d575b50610630575050604051634c9c8ce360e01b81526001600160a01b0390921690820190815281906020010390fd5b8383600080516020611af1833981519152840361065157610021838361174b565b604051632a87526960e21b815290810184815281906020010390fd5b61069091935060203d602011610697575b61068881836104df565b8101906114e1565b9138610602565b503d61067e565b60405163703e46dd60e11b81528390fd5b905081600080516020611af183398151915254161415386105d1565b90816101209103126101c65790565b919082519283825260005b848110610706575050826000602080949584010152601f8019910116010190565b6020818301810151848301820152016106e5565b346101c65760603660031901126101c6576004356001600160401b0381116101c6576107656107506107799236906004016106cb565b61075861148a565b6107606114f0565b611591565b6040519283926040845260408401906106da565b9060208301520390f35b346101c65760003660031901126101c6577f00000000000000000000000000000000000000000000000000000000000000006001600160a01b031630036107dc576020604051600080516020611af18339815191528152f35b60405163703e46dd60e11b8152600490fd5b65ffffffffffff8116036101c657565b346101c65760603660031901126101c6576004356001600160401b0381116101c65761085161083360209236906004016106cb565b60243561083f816107ee565b6044359161084c836107ee565b611181565b604051908152f35b346101c65760003660031901126101c657602060ff600080516020611b1183398151915254166040519015158152f35b346101c65760008060031936011261026f576108a3611451565b600080516020611ad183398151915280546001600160a01b0319811690915581906001600160a01b03167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e08280a380f35b9181601f840112156101c6578235916001600160401b0383116101c657602083818601950101116101c657565b346101c65760803660031901126101c657600360043510156101c6576024356001600160401b0381116101c65761095c9036906004016108f4565b505061096661148a565b6100216114f0565b346101c65760003660031901126101c657610987611451565b61098f61148a565b61099761148a565b600080516020611b11833981519152600160ff198254161790557f62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a2586020604051338152a1005b346101c65760008060031936011261026f578060806040516109fe816104a8565b8281526020810183905260408082018490526060820184905291019190915251632943e70960e11b815230600482015260a0816024817f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03165afa90811561026657610ac69291610aca575b5060405191829182919091608065ffffffffffff8160a0840195805185526020810151151560208601526001600160701b03604082015116604086015263ffffffff6060820151166060860152015116910152565b0390f35b610aec915060a03d60a011610af2575b610ae481836104df565b81019061122c565b38610a71565b503d610ada565b346101c65760003660031901126101c657600080516020611ad1833981519152546040516001600160a01b039091168152602090f35b346101c65760403660031901126101c657600435610b4c81610272565b6001600160401b03906024358281116101c657610b6d90369060040161038c565b90600080516020611b31833981519152549360ff8560401c1615941680159081610c71575b6001149081610c67575b159081610c5e575b50610c4c57600080516020611b31833981519152805467ffffffffffffffff19166001179055610bd89284610c275761129f565b610bde57005b600080516020611b31833981519152805460ff60401b19169055604051600181527fc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d290602090a1005b600080516020611b31833981519152805460ff60401b1916600160401b17905561129f565b60405163f92ee8a960e01b8152600490fd5b90501538610ba4565b303b159150610b9c565b859150610b92565b346101c65760203660031901126101c6576004356001600160401b0381116101c657610cb4610cae60809236906004016108f4565b90611330565b809160409594955195869465ffffffffffff809216865216602085015260606040850152816060850152848401376000828201840152601f01601f19168101030190f35b60405190602082018281106001600160401b038211176104a35760405260008252565b346101c65760003660031901126101c65760405160408101908082106001600160401b038311176104a357610ac69160405260058152640352e302e360dc1b60208201526040519182916020835260208301906106da565b346101c65760003660031901126101c6576040517f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03168152602090f35b346101c65760008060031936011261026f57610dd2611451565b610dda61148a565b807f00000000000000000000000000000000000000000000000000000000000000006001600160a01b0316803b15610e3157819060046040518094819363bb9fe6bf60e01b83525af180156102665761025a575080f35b50fd5b346101c6576000602036600319011261026f57600435610e5381610272565b610e5b611451565b610e6361148a565b6001600160a01b037f0000000000000000000000000000000000000000000000000000000000000000811691839190833b1561031c5760249083604051958694859363611d2e7560e11b85521660048401525af180156102665761025a575080f35b346101c65760008060031936011261026f576040516370a0823160e01b81523060048201526020816024817f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03165afa908115610266578291610f35575b604051828152602090f35b90506020813d602011610f64575b81610f50602093836104df565b8101031261026b57610ac691505138610f2a565b3d9150610f43565b60003660031901126101c657610f8061148a565b610021611376565b346101c65760008060031936011261026f5760405180916032549081835260208093018092603283527f11df491316f14931039edfd4f8964c9a443b862f02d4c7611d18c2bc4e6ff69790835b8181106110325750505084610feb9103856104df565b60405193838594850191818652518092526040850193925b82811061101257505050500390f35b83516001600160a01b031685528695509381019392810192600101611003565b825484529286019260019283019201610fd5565b346101c657611054366103bc565b9061105d611451565b61106561148a565b60005b82811061107157005b61107c818484611125565b3561108681610272565b6001600160a01b039061109a9082166118de565b156110a85750600101611068565b6110b56024928585611125565b35906110c082610272565b60405163281c4e0360e11b815291166004820152fd5b346101c65760203660031901126101c6576100216004356110f681610272565b6110fe611451565b6113dd565b6040513d6000823e3d90fd5b634e487b7160e01b600052603260045260246000fd5b91908110156111355760051b0190565b61110f565b949261115560a095929897939860c0885260c08801906106da565b976020870152600180861b03166040860152606085015265ffffffffffff809216608085015216910152565b9161122690611218602085013591604060c061119f8289018961155f565b9081845191823720976111b5606082018261155f565b908185519182372083519960018060a01b0383351660208c015287858c015260608b015260808a0152608081013560a08a015260a0810135828a0152013560e088015260e08752611205876104c3565b519485936020850197309046908a61113a565b03601f1981018352826104df565b51902090565b908160a09103126101c65760405190611244826104a8565b80518252602081015180151581036101c65760208301526040810151906001600160701b03821682036101c65760809160408401526060810151611287816101b8565b60608401520151611297816107ee565b608082015290565b6112c3906112ab61182e565b6112b361182e565b6112bb61182e565b6110fe61182e565b6112cb61182e565b6112d361182e565b600080516020611b11833981519152805460ff1916905560005b8281106112f957505050565b611304818484611125565b3561130e81610272565b6001600160a01b03906113229082166116d4565b1561044c57506001016112ed565b9190806074116101c657603483013591611349836107ee565b60746054850135611359816107ee565b939401916073190190565b61136c61148a565b611374611376565b565b7f00000000000000000000000000000000000000000000000000000000000000006001600160a01b0316803b156101c65760006024916040519283809263b760faf960e01b825230600483015234905af18015610266576113d45750565b61137490610490565b6001600160a01b0390811690811561143857600080516020611ad183398151915280546001600160a01b031981168417909155167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0600080a3565b604051631e4fbdf760e01b815260006004820152602490fd5b600080516020611ad1833981519152546001600160a01b0316330361147257565b60405163118cdaa760e01b8152336004820152602490fd5b60ff600080516020611b1183398151915254166114a357565b60405163d93c066560e01b8152600490fd5b60ff600080516020611b118339815191525416156114cf57565b604051638dfc202b60e01b8152600490fd5b908160209103126101c6575190565b7f00000000000000000000000000000000000000000000000000000000000000006001600160a01b0316330361152257565b60405162461bcd60e51b815260206004820152601560248201527414d95b99195c881b9bdd08115b9d1c9e541bda5b9d605a1b6044820152606490fd5b903590601e19813603018212156101c657018035906001600160401b0382116101c6576020019181360383136101c657565b6115c06115ba916115f36115ab610cae60e084018461155f565b9683979183979492369161051b565b94611181565b916000927f19457468657265756d205369676e6564204d6573736167653a0a3332000000008452601c52603c83206117f2565b50600481939293101561168957159182159261166a575b50506116405760a09190911b65ffffffffffff60a01b1660d09190911b6001600160d01b031916175b9061163c610cf8565b9190565b60a09190911b65ffffffffffff60a01b1660d09190911b6001600160d01b03191617600117611633565b6001600160a01b0316815260336020526040902054159050388061160a565b634e487b7160e01b82526021600452602482fd5b6032548110156111355760326000527f11df491316f14931039edfd4f8964c9a443b862f02d4c7611d18c2bc4e6ff6970190600090565b8060005260336020526040600020541560001461174557603254600160401b8110156104a35760018101806032558110156111355781907f11df491316f14931039edfd4f8964c9a443b862f02d4c7611d18c2bc4e6ff6970155603254906000526033602052604060002055600190565b50600090565b90813b156117d157600080516020611af183398151915280546001600160a01b0319166001600160a01b0384169081179091557fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b600080a28051156117b6576117b3916119a0565b50565b5050346117bf57565b60405163b398979f60e01b8152600490fd5b604051634c9c8ce360e01b81526001600160a01b0383166004820152602490fd5b81519190604183036118235761181c92506020820151906060604084015193015160001a906119e9565b9192909190565b505060009160029190565b60ff600080516020611b318339815191525460401c161561184b57565b604051631afcd79f60e31b8152600490fd5b60001981019190821161186c57565b634e487b7160e01b600052601160045260246000fd5b60325480156118c85760001981019080821015611135577f11df491316f14931039edfd4f8964c9a443b862f02d4c7611d18c2bc4e6ff696600091603283520155603255565b634e487b7160e01b600052603160045260246000fd5b600081815260336020526040812054909190801561199b5760001981018181116119875790611937929161191360325461185d565b9081810361193d575b505050611927611882565b6000526033602052604060002090565b55600190565b6119276119659161195d61195361197e9561169d565b90549060031b1c90565b92839161169d565b90919082549060031b91821b91600019901b1916179055565b5538808061191c565b634e487b7160e01b84526011600452602484fd5b505090565b6000806119de93602081519101845af43d156119e1573d916119c183610500565b926119cf60405194856104df565b83523d6000602085013e611a6d565b90565b606091611a6d565b91907f7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a08411611a6157926020929160ff608095604051948552168484015260408301526060820152600092839182805260015afa156102665780516001600160a01b03811615611a5857918190565b50809160019190565b50505060009160039190565b90611a945750805115611a8257805190602001fd5b604051630a12f52160e11b8152600490fd5b81511580611ac7575b611aa5575090565b604051639996b31560e01b81526001600160a01b039091166004820152602490fd5b50803b15611a9d56fe9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbccd5ed15c6e187e77e9aee88184c21f4f2182ab5827cb3b7e07fbedcd63f03300f0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00a2646970667358221220155a5ce7d01b92aa13115f5f160cb39781875524e1390fff8464965796bb92f164736f6c63430008180033",
}

// SponsorPaymasterABI is the input ABI used to generate the binding from.
// Deprecated: Use SponsorPaymasterMetaData.ABI instead.
var SponsorPaymasterABI = SponsorPaymasterMetaData.ABI

// SponsorPaymasterBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use SponsorPaymasterMetaData.Bin instead.
var SponsorPaymasterBin = SponsorPaymasterMetaData.Bin

// DeploySponsorPaymaster deploys a new Ethereum contract, binding an instance of SponsorPaymaster to it.
func DeploySponsorPaymaster(auth *bind.TransactOpts, backend bind.ContractBackend, _newEntryPoint common.Address) (common.Address, *types.Transaction, *SponsorPaymaster, error) {
	parsed, err := SponsorPaymasterMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(SponsorPaymasterBin), backend, _newEntryPoint)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &SponsorPaymaster{SponsorPaymasterCaller: SponsorPaymasterCaller{contract: contract}, SponsorPaymasterTransactor: SponsorPaymasterTransactor{contract: contract}, SponsorPaymasterFilterer: SponsorPaymasterFilterer{contract: contract}}, nil
}

// SponsorPaymaster is an auto generated Go binding around an Ethereum contract.
type SponsorPaymaster struct {
	SponsorPaymasterCaller     // Read-only binding to the contract
	SponsorPaymasterTransactor // Write-only binding to the contract
	SponsorPaymasterFilterer   // Log filterer for contract events
}

// SponsorPaymasterCaller is an auto generated read-only Go binding around an Ethereum contract.
type SponsorPaymasterCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SponsorPaymasterTransactor is an auto generated write-only Go binding around an Ethereum contract.
type SponsorPaymasterTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SponsorPaymasterFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type SponsorPaymasterFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SponsorPaymasterSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type SponsorPaymasterSession struct {
	Contract     *SponsorPaymaster // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// SponsorPaymasterCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type SponsorPaymasterCallerSession struct {
	Contract *SponsorPaymasterCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts           // Call options to use throughout this session
}

// SponsorPaymasterTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type SponsorPaymasterTransactorSession struct {
	Contract     *SponsorPaymasterTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts           // Transaction auth options to use throughout this session
}

// SponsorPaymasterRaw is an auto generated low-level Go binding around an Ethereum contract.
type SponsorPaymasterRaw struct {
	Contract *SponsorPaymaster // Generic contract binding to access the raw methods on
}

// SponsorPaymasterCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type SponsorPaymasterCallerRaw struct {
	Contract *SponsorPaymasterCaller // Generic read-only contract binding to access the raw methods on
}

// SponsorPaymasterTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type SponsorPaymasterTransactorRaw struct {
	Contract *SponsorPaymasterTransactor // Generic write-only contract binding to access the raw methods on
}

// NewSponsorPaymaster creates a new instance of SponsorPaymaster, bound to a specific deployed contract.
func NewSponsorPaymaster(address common.Address, backend bind.ContractBackend) (*SponsorPaymaster, error) {
	contract, err := bindSponsorPaymaster(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &SponsorPaymaster{SponsorPaymasterCaller: SponsorPaymasterCaller{contract: contract}, SponsorPaymasterTransactor: SponsorPaymasterTransactor{contract: contract}, SponsorPaymasterFilterer: SponsorPaymasterFilterer{contract: contract}}, nil
}

// NewSponsorPaymasterCaller creates a new read-only instance of SponsorPaymaster, bound to a specific deployed contract.
func NewSponsorPaymasterCaller(address common.Address, caller bind.ContractCaller) (*SponsorPaymasterCaller, error) {
	contract, err := bindSponsorPaymaster(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &SponsorPaymasterCaller{contract: contract}, nil
}

// NewSponsorPaymasterTransactor creates a new write-only instance of SponsorPaymaster, bound to a specific deployed contract.
func NewSponsorPaymasterTransactor(address common.Address, transactor bind.ContractTransactor) (*SponsorPaymasterTransactor, error) {
	contract, err := bindSponsorPaymaster(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &SponsorPaymasterTransactor{contract: contract}, nil
}

// NewSponsorPaymasterFilterer creates a new log filterer instance of SponsorPaymaster, bound to a specific deployed contract.
func NewSponsorPaymasterFilterer(address common.Address, filterer bind.ContractFilterer) (*SponsorPaymasterFilterer, error) {
	contract, err := bindSponsorPaymaster(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &SponsorPaymasterFilterer{contract: contract}, nil
}

// bindSponsorPaymaster binds a generic wrapper to an already deployed contract.
func bindSponsorPaymaster(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := SponsorPaymasterMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_SponsorPaymaster *SponsorPaymasterRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _SponsorPaymaster.Contract.SponsorPaymasterCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_SponsorPaymaster *SponsorPaymasterRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.SponsorPaymasterTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_SponsorPaymaster *SponsorPaymasterRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.SponsorPaymasterTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_SponsorPaymaster *SponsorPaymasterCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _SponsorPaymaster.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_SponsorPaymaster *SponsorPaymasterTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_SponsorPaymaster *SponsorPaymasterTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.contract.Transact(opts, method, params...)
}

// UPGRADEINTERFACEVERSION is a free data retrieval call binding the contract method 0xad3cb1cc.
//
// Solidity: function UPGRADE_INTERFACE_VERSION() view returns(string)
func (_SponsorPaymaster *SponsorPaymasterCaller) UPGRADEINTERFACEVERSION(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _SponsorPaymaster.contract.Call(opts, &out, "UPGRADE_INTERFACE_VERSION")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// UPGRADEINTERFACEVERSION is a free data retrieval call binding the contract method 0xad3cb1cc.
//
// Solidity: function UPGRADE_INTERFACE_VERSION() view returns(string)
func (_SponsorPaymaster *SponsorPaymasterSession) UPGRADEINTERFACEVERSION() (string, error) {
	return _SponsorPaymaster.Contract.UPGRADEINTERFACEVERSION(&_SponsorPaymaster.CallOpts)
}

// UPGRADEINTERFACEVERSION is a free data retrieval call binding the contract method 0xad3cb1cc.
//
// Solidity: function UPGRADE_INTERFACE_VERSION() view returns(string)
func (_SponsorPaymaster *SponsorPaymasterCallerSession) UPGRADEINTERFACEVERSION() (string, error) {
	return _SponsorPaymaster.Contract.UPGRADEINTERFACEVERSION(&_SponsorPaymaster.CallOpts)
}

// EntryPoint is a free data retrieval call binding the contract method 0xb0d691fe.
//
// Solidity: function entryPoint() view returns(address)
func (_SponsorPaymaster *SponsorPaymasterCaller) EntryPoint(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _SponsorPaymaster.contract.Call(opts, &out, "entryPoint")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// EntryPoint is a free data retrieval call binding the contract method 0xb0d691fe.
//
// Solidity: function entryPoint() view returns(address)
func (_SponsorPaymaster *SponsorPaymasterSession) EntryPoint() (common.Address, error) {
	return _SponsorPaymaster.Contract.EntryPoint(&_SponsorPaymaster.CallOpts)
}

// EntryPoint is a free data retrieval call binding the contract method 0xb0d691fe.
//
// Solidity: function entryPoint() view returns(address)
func (_SponsorPaymaster *SponsorPaymasterCallerSession) EntryPoint() (common.Address, error) {
	return _SponsorPaymaster.Contract.EntryPoint(&_SponsorPaymaster.CallOpts)
}

// GetAllSigners is a free data retrieval call binding the contract method 0xd42f2f35.
//
// Solidity: function getAllSigners() view returns(address[])
func (_SponsorPaymaster *SponsorPaymasterCaller) GetAllSigners(opts *bind.CallOpts) ([]common.Address, error) {
	var out []interface{}
	err := _SponsorPaymaster.contract.Call(opts, &out, "getAllSigners")

	if err != nil {
		return *new([]common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new([]common.Address)).(*[]common.Address)

	return out0, err

}

// GetAllSigners is a free data retrieval call binding the contract method 0xd42f2f35.
//
// Solidity: function getAllSigners() view returns(address[])
func (_SponsorPaymaster *SponsorPaymasterSession) GetAllSigners() ([]common.Address, error) {
	return _SponsorPaymaster.Contract.GetAllSigners(&_SponsorPaymaster.CallOpts)
}

// GetAllSigners is a free data retrieval call binding the contract method 0xd42f2f35.
//
// Solidity: function getAllSigners() view returns(address[])
func (_SponsorPaymaster *SponsorPaymasterCallerSession) GetAllSigners() ([]common.Address, error) {
	return _SponsorPaymaster.Contract.GetAllSigners(&_SponsorPaymaster.CallOpts)
}

// GetDeposit is a free data retrieval call binding the contract method 0xc399ec88.
//
// Solidity: function getDeposit() view returns(uint256)
func (_SponsorPaymaster *SponsorPaymasterCaller) GetDeposit(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _SponsorPaymaster.contract.Call(opts, &out, "getDeposit")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetDeposit is a free data retrieval call binding the contract method 0xc399ec88.
//
// Solidity: function getDeposit() view returns(uint256)
func (_SponsorPaymaster *SponsorPaymasterSession) GetDeposit() (*big.Int, error) {
	return _SponsorPaymaster.Contract.GetDeposit(&_SponsorPaymaster.CallOpts)
}

// GetDeposit is a free data retrieval call binding the contract method 0xc399ec88.
//
// Solidity: function getDeposit() view returns(uint256)
func (_SponsorPaymaster *SponsorPaymasterCallerSession) GetDeposit() (*big.Int, error) {
	return _SponsorPaymaster.Contract.GetDeposit(&_SponsorPaymaster.CallOpts)
}

// GetDepositInfo is a free data retrieval call binding the contract method 0x8969e0f9.
//
// Solidity: function getDepositInfo() view returns((uint256,bool,uint112,uint32,uint48) info)
func (_SponsorPaymaster *SponsorPaymasterCaller) GetDepositInfo(opts *bind.CallOpts) (IStakeManagerDepositInfo, error) {
	var out []interface{}
	err := _SponsorPaymaster.contract.Call(opts, &out, "getDepositInfo")

	if err != nil {
		return *new(IStakeManagerDepositInfo), err
	}

	out0 := *abi.ConvertType(out[0], new(IStakeManagerDepositInfo)).(*IStakeManagerDepositInfo)

	return out0, err

}

// GetDepositInfo is a free data retrieval call binding the contract method 0x8969e0f9.
//
// Solidity: function getDepositInfo() view returns((uint256,bool,uint112,uint32,uint48) info)
func (_SponsorPaymaster *SponsorPaymasterSession) GetDepositInfo() (IStakeManagerDepositInfo, error) {
	return _SponsorPaymaster.Contract.GetDepositInfo(&_SponsorPaymaster.CallOpts)
}

// GetDepositInfo is a free data retrieval call binding the contract method 0x8969e0f9.
//
// Solidity: function getDepositInfo() view returns((uint256,bool,uint112,uint32,uint48) info)
func (_SponsorPaymaster *SponsorPaymasterCallerSession) GetDepositInfo() (IStakeManagerDepositInfo, error) {
	return _SponsorPaymaster.Contract.GetDepositInfo(&_SponsorPaymaster.CallOpts)
}

// GetHash is a free data retrieval call binding the contract method 0x5829c5f5.
//
// Solidity: function getHash((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes) userOp, uint48 validUntil, uint48 validAfter) view returns(bytes32)
func (_SponsorPaymaster *SponsorPaymasterCaller) GetHash(opts *bind.CallOpts, userOp PackedUserOperation, validUntil *big.Int, validAfter *big.Int) ([32]byte, error) {
	var out []interface{}
	err := _SponsorPaymaster.contract.Call(opts, &out, "getHash", userOp, validUntil, validAfter)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// GetHash is a free data retrieval call binding the contract method 0x5829c5f5.
//
// Solidity: function getHash((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes) userOp, uint48 validUntil, uint48 validAfter) view returns(bytes32)
func (_SponsorPaymaster *SponsorPaymasterSession) GetHash(userOp PackedUserOperation, validUntil *big.Int, validAfter *big.Int) ([32]byte, error) {
	return _SponsorPaymaster.Contract.GetHash(&_SponsorPaymaster.CallOpts, userOp, validUntil, validAfter)
}

// GetHash is a free data retrieval call binding the contract method 0x5829c5f5.
//
// Solidity: function getHash((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes) userOp, uint48 validUntil, uint48 validAfter) view returns(bytes32)
func (_SponsorPaymaster *SponsorPaymasterCallerSession) GetHash(userOp PackedUserOperation, validUntil *big.Int, validAfter *big.Int) ([32]byte, error) {
	return _SponsorPaymaster.Contract.GetHash(&_SponsorPaymaster.CallOpts, userOp, validUntil, validAfter)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_SponsorPaymaster *SponsorPaymasterCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _SponsorPaymaster.contract.Call(opts, &out, "owner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_SponsorPaymaster *SponsorPaymasterSession) Owner() (common.Address, error) {
	return _SponsorPaymaster.Contract.Owner(&_SponsorPaymaster.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_SponsorPaymaster *SponsorPaymasterCallerSession) Owner() (common.Address, error) {
	return _SponsorPaymaster.Contract.Owner(&_SponsorPaymaster.CallOpts)
}

// ParsePaymasterAndData is a free data retrieval call binding the contract method 0x94d4ad60.
//
// Solidity: function parsePaymasterAndData(bytes paymasterAndData) pure returns(uint48 validUntil, uint48 validAfter, bytes signature)
func (_SponsorPaymaster *SponsorPaymasterCaller) ParsePaymasterAndData(opts *bind.CallOpts, paymasterAndData []byte) (struct {
	ValidUntil *big.Int
	ValidAfter *big.Int
	Signature  []byte
}, error) {
	var out []interface{}
	err := _SponsorPaymaster.contract.Call(opts, &out, "parsePaymasterAndData", paymasterAndData)

	outstruct := new(struct {
		ValidUntil *big.Int
		ValidAfter *big.Int
		Signature  []byte
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.ValidUntil = *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)
	outstruct.ValidAfter = *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)
	outstruct.Signature = *abi.ConvertType(out[2], new([]byte)).(*[]byte)

	return *outstruct, err

}

// ParsePaymasterAndData is a free data retrieval call binding the contract method 0x94d4ad60.
//
// Solidity: function parsePaymasterAndData(bytes paymasterAndData) pure returns(uint48 validUntil, uint48 validAfter, bytes signature)
func (_SponsorPaymaster *SponsorPaymasterSession) ParsePaymasterAndData(paymasterAndData []byte) (struct {
	ValidUntil *big.Int
	ValidAfter *big.Int
	Signature  []byte
}, error) {
	return _SponsorPaymaster.Contract.ParsePaymasterAndData(&_SponsorPaymaster.CallOpts, paymasterAndData)
}

// ParsePaymasterAndData is a free data retrieval call binding the contract method 0x94d4ad60.
//
// Solidity: function parsePaymasterAndData(bytes paymasterAndData) pure returns(uint48 validUntil, uint48 validAfter, bytes signature)
func (_SponsorPaymaster *SponsorPaymasterCallerSession) ParsePaymasterAndData(paymasterAndData []byte) (struct {
	ValidUntil *big.Int
	ValidAfter *big.Int
	Signature  []byte
}, error) {
	return _SponsorPaymaster.Contract.ParsePaymasterAndData(&_SponsorPaymaster.CallOpts, paymasterAndData)
}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_SponsorPaymaster *SponsorPaymasterCaller) Paused(opts *bind.CallOpts) (bool, error) {
	var out []interface{}
	err := _SponsorPaymaster.contract.Call(opts, &out, "paused")

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_SponsorPaymaster *SponsorPaymasterSession) Paused() (bool, error) {
	return _SponsorPaymaster.Contract.Paused(&_SponsorPaymaster.CallOpts)
}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_SponsorPaymaster *SponsorPaymasterCallerSession) Paused() (bool, error) {
	return _SponsorPaymaster.Contract.Paused(&_SponsorPaymaster.CallOpts)
}

// ProxiableUUID is a free data retrieval call binding the contract method 0x52d1902d.
//
// Solidity: function proxiableUUID() view returns(bytes32)
func (_SponsorPaymaster *SponsorPaymasterCaller) ProxiableUUID(opts *bind.CallOpts) ([32]byte, error) {
	var out []interface{}
	err := _SponsorPaymaster.contract.Call(opts, &out, "proxiableUUID")

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// ProxiableUUID is a free data retrieval call binding the contract method 0x52d1902d.
//
// Solidity: function proxiableUUID() view returns(bytes32)
func (_SponsorPaymaster *SponsorPaymasterSession) ProxiableUUID() ([32]byte, error) {
	return _SponsorPaymaster.Contract.ProxiableUUID(&_SponsorPaymaster.CallOpts)
}

// ProxiableUUID is a free data retrieval call binding the contract method 0x52d1902d.
//
// Solidity: function proxiableUUID() view returns(bytes32)
func (_SponsorPaymaster *SponsorPaymasterCallerSession) ProxiableUUID() ([32]byte, error) {
	return _SponsorPaymaster.Contract.ProxiableUUID(&_SponsorPaymaster.CallOpts)
}

// AddStake is a paid mutator transaction binding the contract method 0x0396cb60.
//
// Solidity: function addStake(uint32 unstakeDelaySec) payable returns()
func (_SponsorPaymaster *SponsorPaymasterTransactor) AddStake(opts *bind.TransactOpts, unstakeDelaySec uint32) (*types.Transaction, error) {
	return _SponsorPaymaster.contract.Transact(opts, "addStake", unstakeDelaySec)
}

// AddStake is a paid mutator transaction binding the contract method 0x0396cb60.
//
// Solidity: function addStake(uint32 unstakeDelaySec) payable returns()
func (_SponsorPaymaster *SponsorPaymasterSession) AddStake(unstakeDelaySec uint32) (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.AddStake(&_SponsorPaymaster.TransactOpts, unstakeDelaySec)
}

// AddStake is a paid mutator transaction binding the contract method 0x0396cb60.
//
// Solidity: function addStake(uint32 unstakeDelaySec) payable returns()
func (_SponsorPaymaster *SponsorPaymasterTransactorSession) AddStake(unstakeDelaySec uint32) (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.AddStake(&_SponsorPaymaster.TransactOpts, unstakeDelaySec)
}

// AddVerifyingSigners is a paid mutator transaction binding the contract method 0x43e3b518.
//
// Solidity: function addVerifyingSigners(address[] _newVerifyingSigners) returns()
func (_SponsorPaymaster *SponsorPaymasterTransactor) AddVerifyingSigners(opts *bind.TransactOpts, _newVerifyingSigners []common.Address) (*types.Transaction, error) {
	return _SponsorPaymaster.contract.Transact(opts, "addVerifyingSigners", _newVerifyingSigners)
}

// AddVerifyingSigners is a paid mutator transaction binding the contract method 0x43e3b518.
//
// Solidity: function addVerifyingSigners(address[] _newVerifyingSigners) returns()
func (_SponsorPaymaster *SponsorPaymasterSession) AddVerifyingSigners(_newVerifyingSigners []common.Address) (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.AddVerifyingSigners(&_SponsorPaymaster.TransactOpts, _newVerifyingSigners)
}

// AddVerifyingSigners is a paid mutator transaction binding the contract method 0x43e3b518.
//
// Solidity: function addVerifyingSigners(address[] _newVerifyingSigners) returns()
func (_SponsorPaymaster *SponsorPaymasterTransactorSession) AddVerifyingSigners(_newVerifyingSigners []common.Address) (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.AddVerifyingSigners(&_SponsorPaymaster.TransactOpts, _newVerifyingSigners)
}

// Deposit is a paid mutator transaction binding the contract method 0xd0e30db0.
//
// Solidity: function deposit() payable returns()
func (_SponsorPaymaster *SponsorPaymasterTransactor) Deposit(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SponsorPaymaster.contract.Transact(opts, "deposit")
}

// Deposit is a paid mutator transaction binding the contract method 0xd0e30db0.
//
// Solidity: function deposit() payable returns()
func (_SponsorPaymaster *SponsorPaymasterSession) Deposit() (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.Deposit(&_SponsorPaymaster.TransactOpts)
}

// Deposit is a paid mutator transaction binding the contract method 0xd0e30db0.
//
// Solidity: function deposit() payable returns()
func (_SponsorPaymaster *SponsorPaymasterTransactorSession) Deposit() (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.Deposit(&_SponsorPaymaster.TransactOpts)
}

// Initialize is a paid mutator transaction binding the contract method 0x946d9204.
//
// Solidity: function initialize(address _newOwner, address[] _verifyingSigners) returns()
func (_SponsorPaymaster *SponsorPaymasterTransactor) Initialize(opts *bind.TransactOpts, _newOwner common.Address, _verifyingSigners []common.Address) (*types.Transaction, error) {
	return _SponsorPaymaster.contract.Transact(opts, "initialize", _newOwner, _verifyingSigners)
}

// Initialize is a paid mutator transaction binding the contract method 0x946d9204.
//
// Solidity: function initialize(address _newOwner, address[] _verifyingSigners) returns()
func (_SponsorPaymaster *SponsorPaymasterSession) Initialize(_newOwner common.Address, _verifyingSigners []common.Address) (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.Initialize(&_SponsorPaymaster.TransactOpts, _newOwner, _verifyingSigners)
}

// Initialize is a paid mutator transaction binding the contract method 0x946d9204.
//
// Solidity: function initialize(address _newOwner, address[] _verifyingSigners) returns()
func (_SponsorPaymaster *SponsorPaymasterTransactorSession) Initialize(_newOwner common.Address, _verifyingSigners []common.Address) (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.Initialize(&_SponsorPaymaster.TransactOpts, _newOwner, _verifyingSigners)
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns()
func (_SponsorPaymaster *SponsorPaymasterTransactor) Pause(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SponsorPaymaster.contract.Transact(opts, "pause")
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns()
func (_SponsorPaymaster *SponsorPaymasterSession) Pause() (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.Pause(&_SponsorPaymaster.TransactOpts)
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns()
func (_SponsorPaymaster *SponsorPaymasterTransactorSession) Pause() (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.Pause(&_SponsorPaymaster.TransactOpts)
}

// PostOp is a paid mutator transaction binding the contract method 0x7c627b21.
//
// Solidity: function postOp(uint8 mode, bytes context, uint256 actualGasCost, uint256 actualUserOpFeePerGas) returns()
func (_SponsorPaymaster *SponsorPaymasterTransactor) PostOp(opts *bind.TransactOpts, mode uint8, context []byte, actualGasCost *big.Int, actualUserOpFeePerGas *big.Int) (*types.Transaction, error) {
	return _SponsorPaymaster.contract.Transact(opts, "postOp", mode, context, actualGasCost, actualUserOpFeePerGas)
}

// PostOp is a paid mutator transaction binding the contract method 0x7c627b21.
//
// Solidity: function postOp(uint8 mode, bytes context, uint256 actualGasCost, uint256 actualUserOpFeePerGas) returns()
func (_SponsorPaymaster *SponsorPaymasterSession) PostOp(mode uint8, context []byte, actualGasCost *big.Int, actualUserOpFeePerGas *big.Int) (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.PostOp(&_SponsorPaymaster.TransactOpts, mode, context, actualGasCost, actualUserOpFeePerGas)
}

// PostOp is a paid mutator transaction binding the contract method 0x7c627b21.
//
// Solidity: function postOp(uint8 mode, bytes context, uint256 actualGasCost, uint256 actualUserOpFeePerGas) returns()
func (_SponsorPaymaster *SponsorPaymasterTransactorSession) PostOp(mode uint8, context []byte, actualGasCost *big.Int, actualUserOpFeePerGas *big.Int) (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.PostOp(&_SponsorPaymaster.TransactOpts, mode, context, actualGasCost, actualUserOpFeePerGas)
}

// RemoveVerifyingSigners is a paid mutator transaction binding the contract method 0xd88c13e0.
//
// Solidity: function removeVerifyingSigners(address[] _verifyingSigners) returns()
func (_SponsorPaymaster *SponsorPaymasterTransactor) RemoveVerifyingSigners(opts *bind.TransactOpts, _verifyingSigners []common.Address) (*types.Transaction, error) {
	return _SponsorPaymaster.contract.Transact(opts, "removeVerifyingSigners", _verifyingSigners)
}

// RemoveVerifyingSigners is a paid mutator transaction binding the contract method 0xd88c13e0.
//
// Solidity: function removeVerifyingSigners(address[] _verifyingSigners) returns()
func (_SponsorPaymaster *SponsorPaymasterSession) RemoveVerifyingSigners(_verifyingSigners []common.Address) (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.RemoveVerifyingSigners(&_SponsorPaymaster.TransactOpts, _verifyingSigners)
}

// RemoveVerifyingSigners is a paid mutator transaction binding the contract method 0xd88c13e0.
//
// Solidity: function removeVerifyingSigners(address[] _verifyingSigners) returns()
func (_SponsorPaymaster *SponsorPaymasterTransactorSession) RemoveVerifyingSigners(_verifyingSigners []common.Address) (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.RemoveVerifyingSigners(&_SponsorPaymaster.TransactOpts, _verifyingSigners)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_SponsorPaymaster *SponsorPaymasterTransactor) RenounceOwnership(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SponsorPaymaster.contract.Transact(opts, "renounceOwnership")
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_SponsorPaymaster *SponsorPaymasterSession) RenounceOwnership() (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.RenounceOwnership(&_SponsorPaymaster.TransactOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_SponsorPaymaster *SponsorPaymasterTransactorSession) RenounceOwnership() (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.RenounceOwnership(&_SponsorPaymaster.TransactOpts)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_SponsorPaymaster *SponsorPaymasterTransactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _SponsorPaymaster.contract.Transact(opts, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_SponsorPaymaster *SponsorPaymasterSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.TransferOwnership(&_SponsorPaymaster.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_SponsorPaymaster *SponsorPaymasterTransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.TransferOwnership(&_SponsorPaymaster.TransactOpts, newOwner)
}

// UnlockStake is a paid mutator transaction binding the contract method 0xbb9fe6bf.
//
// Solidity: function unlockStake() returns()
func (_SponsorPaymaster *SponsorPaymasterTransactor) UnlockStake(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SponsorPaymaster.contract.Transact(opts, "unlockStake")
}

// UnlockStake is a paid mutator transaction binding the contract method 0xbb9fe6bf.
//
// Solidity: function unlockStake() returns()
func (_SponsorPaymaster *SponsorPaymasterSession) UnlockStake() (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.UnlockStake(&_SponsorPaymaster.TransactOpts)
}

// UnlockStake is a paid mutator transaction binding the contract method 0xbb9fe6bf.
//
// Solidity: function unlockStake() returns()
func (_SponsorPaymaster *SponsorPaymasterTransactorSession) UnlockStake() (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.UnlockStake(&_SponsorPaymaster.TransactOpts)
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns()
func (_SponsorPaymaster *SponsorPaymasterTransactor) Unpause(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SponsorPaymaster.contract.Transact(opts, "unpause")
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns()
func (_SponsorPaymaster *SponsorPaymasterSession) Unpause() (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.Unpause(&_SponsorPaymaster.TransactOpts)
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns()
func (_SponsorPaymaster *SponsorPaymasterTransactorSession) Unpause() (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.Unpause(&_SponsorPaymaster.TransactOpts)
}

// UpgradeToAndCall is a paid mutator transaction binding the contract method 0x4f1ef286.
//
// Solidity: function upgradeToAndCall(address newImplementation, bytes data) payable returns()
func (_SponsorPaymaster *SponsorPaymasterTransactor) UpgradeToAndCall(opts *bind.TransactOpts, newImplementation common.Address, data []byte) (*types.Transaction, error) {
	return _SponsorPaymaster.contract.Transact(opts, "upgradeToAndCall", newImplementation, data)
}

// UpgradeToAndCall is a paid mutator transaction binding the contract method 0x4f1ef286.
//
// Solidity: function upgradeToAndCall(address newImplementation, bytes data) payable returns()
func (_SponsorPaymaster *SponsorPaymasterSession) UpgradeToAndCall(newImplementation common.Address, data []byte) (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.UpgradeToAndCall(&_SponsorPaymaster.TransactOpts, newImplementation, data)
}

// UpgradeToAndCall is a paid mutator transaction binding the contract method 0x4f1ef286.
//
// Solidity: function upgradeToAndCall(address newImplementation, bytes data) payable returns()
func (_SponsorPaymaster *SponsorPaymasterTransactorSession) UpgradeToAndCall(newImplementation common.Address, data []byte) (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.UpgradeToAndCall(&_SponsorPaymaster.TransactOpts, newImplementation, data)
}

// ValidatePaymasterUserOp is a paid mutator transaction binding the contract method 0x52b7512c.
//
// Solidity: function validatePaymasterUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes) userOp, bytes32 userOpHash, uint256 maxCost) returns(bytes context, uint256 validationData)
func (_SponsorPaymaster *SponsorPaymasterTransactor) ValidatePaymasterUserOp(opts *bind.TransactOpts, userOp PackedUserOperation, userOpHash [32]byte, maxCost *big.Int) (*types.Transaction, error) {
	return _SponsorPaymaster.contract.Transact(opts, "validatePaymasterUserOp", userOp, userOpHash, maxCost)
}

// ValidatePaymasterUserOp is a paid mutator transaction binding the contract method 0x52b7512c.
//
// Solidity: function validatePaymasterUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes) userOp, bytes32 userOpHash, uint256 maxCost) returns(bytes context, uint256 validationData)
func (_SponsorPaymaster *SponsorPaymasterSession) ValidatePaymasterUserOp(userOp PackedUserOperation, userOpHash [32]byte, maxCost *big.Int) (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.ValidatePaymasterUserOp(&_SponsorPaymaster.TransactOpts, userOp, userOpHash, maxCost)
}

// ValidatePaymasterUserOp is a paid mutator transaction binding the contract method 0x52b7512c.
//
// Solidity: function validatePaymasterUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes) userOp, bytes32 userOpHash, uint256 maxCost) returns(bytes context, uint256 validationData)
func (_SponsorPaymaster *SponsorPaymasterTransactorSession) ValidatePaymasterUserOp(userOp PackedUserOperation, userOpHash [32]byte, maxCost *big.Int) (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.ValidatePaymasterUserOp(&_SponsorPaymaster.TransactOpts, userOp, userOpHash, maxCost)
}

// WithdrawStake is a paid mutator transaction binding the contract method 0xc23a5cea.
//
// Solidity: function withdrawStake(address withdrawAddress) returns()
func (_SponsorPaymaster *SponsorPaymasterTransactor) WithdrawStake(opts *bind.TransactOpts, withdrawAddress common.Address) (*types.Transaction, error) {
	return _SponsorPaymaster.contract.Transact(opts, "withdrawStake", withdrawAddress)
}

// WithdrawStake is a paid mutator transaction binding the contract method 0xc23a5cea.
//
// Solidity: function withdrawStake(address withdrawAddress) returns()
func (_SponsorPaymaster *SponsorPaymasterSession) WithdrawStake(withdrawAddress common.Address) (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.WithdrawStake(&_SponsorPaymaster.TransactOpts, withdrawAddress)
}

// WithdrawStake is a paid mutator transaction binding the contract method 0xc23a5cea.
//
// Solidity: function withdrawStake(address withdrawAddress) returns()
func (_SponsorPaymaster *SponsorPaymasterTransactorSession) WithdrawStake(withdrawAddress common.Address) (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.WithdrawStake(&_SponsorPaymaster.TransactOpts, withdrawAddress)
}

// WithdrawTo is a paid mutator transaction binding the contract method 0x205c2878.
//
// Solidity: function withdrawTo(address withdrawAddress, uint256 amount) returns()
func (_SponsorPaymaster *SponsorPaymasterTransactor) WithdrawTo(opts *bind.TransactOpts, withdrawAddress common.Address, amount *big.Int) (*types.Transaction, error) {
	return _SponsorPaymaster.contract.Transact(opts, "withdrawTo", withdrawAddress, amount)
}

// WithdrawTo is a paid mutator transaction binding the contract method 0x205c2878.
//
// Solidity: function withdrawTo(address withdrawAddress, uint256 amount) returns()
func (_SponsorPaymaster *SponsorPaymasterSession) WithdrawTo(withdrawAddress common.Address, amount *big.Int) (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.WithdrawTo(&_SponsorPaymaster.TransactOpts, withdrawAddress, amount)
}

// WithdrawTo is a paid mutator transaction binding the contract method 0x205c2878.
//
// Solidity: function withdrawTo(address withdrawAddress, uint256 amount) returns()
func (_SponsorPaymaster *SponsorPaymasterTransactorSession) WithdrawTo(withdrawAddress common.Address, amount *big.Int) (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.WithdrawTo(&_SponsorPaymaster.TransactOpts, withdrawAddress, amount)
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_SponsorPaymaster *SponsorPaymasterTransactor) Receive(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SponsorPaymaster.contract.RawTransact(opts, nil) // calldata is disallowed for receive function
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_SponsorPaymaster *SponsorPaymasterSession) Receive() (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.Receive(&_SponsorPaymaster.TransactOpts)
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_SponsorPaymaster *SponsorPaymasterTransactorSession) Receive() (*types.Transaction, error) {
	return _SponsorPaymaster.Contract.Receive(&_SponsorPaymaster.TransactOpts)
}

// SponsorPaymasterInitializedIterator is returned from FilterInitialized and is used to iterate over the raw logs and unpacked data for Initialized events raised by the SponsorPaymaster contract.
type SponsorPaymasterInitializedIterator struct {
	Event *SponsorPaymasterInitialized // Event containing the contract specifics and raw log

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
func (it *SponsorPaymasterInitializedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SponsorPaymasterInitialized)
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
		it.Event = new(SponsorPaymasterInitialized)
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
func (it *SponsorPaymasterInitializedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SponsorPaymasterInitializedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SponsorPaymasterInitialized represents a Initialized event raised by the SponsorPaymaster contract.
type SponsorPaymasterInitialized struct {
	Version uint64
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterInitialized is a free log retrieval operation binding the contract event 0xc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d2.
//
// Solidity: event Initialized(uint64 version)
func (_SponsorPaymaster *SponsorPaymasterFilterer) FilterInitialized(opts *bind.FilterOpts) (*SponsorPaymasterInitializedIterator, error) {

	logs, sub, err := _SponsorPaymaster.contract.FilterLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return &SponsorPaymasterInitializedIterator{contract: _SponsorPaymaster.contract, event: "Initialized", logs: logs, sub: sub}, nil
}

// WatchInitialized is a free log subscription operation binding the contract event 0xc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d2.
//
// Solidity: event Initialized(uint64 version)
func (_SponsorPaymaster *SponsorPaymasterFilterer) WatchInitialized(opts *bind.WatchOpts, sink chan<- *SponsorPaymasterInitialized) (event.Subscription, error) {

	logs, sub, err := _SponsorPaymaster.contract.WatchLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SponsorPaymasterInitialized)
				if err := _SponsorPaymaster.contract.UnpackLog(event, "Initialized", log); err != nil {
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
func (_SponsorPaymaster *SponsorPaymasterFilterer) ParseInitialized(log types.Log) (*SponsorPaymasterInitialized, error) {
	event := new(SponsorPaymasterInitialized)
	if err := _SponsorPaymaster.contract.UnpackLog(event, "Initialized", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SponsorPaymasterOwnershipTransferredIterator is returned from FilterOwnershipTransferred and is used to iterate over the raw logs and unpacked data for OwnershipTransferred events raised by the SponsorPaymaster contract.
type SponsorPaymasterOwnershipTransferredIterator struct {
	Event *SponsorPaymasterOwnershipTransferred // Event containing the contract specifics and raw log

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
func (it *SponsorPaymasterOwnershipTransferredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SponsorPaymasterOwnershipTransferred)
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
		it.Event = new(SponsorPaymasterOwnershipTransferred)
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
func (it *SponsorPaymasterOwnershipTransferredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SponsorPaymasterOwnershipTransferredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SponsorPaymasterOwnershipTransferred represents a OwnershipTransferred event raised by the SponsorPaymaster contract.
type SponsorPaymasterOwnershipTransferred struct {
	PreviousOwner common.Address
	NewOwner      common.Address
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterOwnershipTransferred is a free log retrieval operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_SponsorPaymaster *SponsorPaymasterFilterer) FilterOwnershipTransferred(opts *bind.FilterOpts, previousOwner []common.Address, newOwner []common.Address) (*SponsorPaymasterOwnershipTransferredIterator, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _SponsorPaymaster.contract.FilterLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return &SponsorPaymasterOwnershipTransferredIterator{contract: _SponsorPaymaster.contract, event: "OwnershipTransferred", logs: logs, sub: sub}, nil
}

// WatchOwnershipTransferred is a free log subscription operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_SponsorPaymaster *SponsorPaymasterFilterer) WatchOwnershipTransferred(opts *bind.WatchOpts, sink chan<- *SponsorPaymasterOwnershipTransferred, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _SponsorPaymaster.contract.WatchLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SponsorPaymasterOwnershipTransferred)
				if err := _SponsorPaymaster.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
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
func (_SponsorPaymaster *SponsorPaymasterFilterer) ParseOwnershipTransferred(log types.Log) (*SponsorPaymasterOwnershipTransferred, error) {
	event := new(SponsorPaymasterOwnershipTransferred)
	if err := _SponsorPaymaster.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SponsorPaymasterPausedIterator is returned from FilterPaused and is used to iterate over the raw logs and unpacked data for Paused events raised by the SponsorPaymaster contract.
type SponsorPaymasterPausedIterator struct {
	Event *SponsorPaymasterPaused // Event containing the contract specifics and raw log

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
func (it *SponsorPaymasterPausedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SponsorPaymasterPaused)
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
		it.Event = new(SponsorPaymasterPaused)
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
func (it *SponsorPaymasterPausedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SponsorPaymasterPausedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SponsorPaymasterPaused represents a Paused event raised by the SponsorPaymaster contract.
type SponsorPaymasterPaused struct {
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterPaused is a free log retrieval operation binding the contract event 0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258.
//
// Solidity: event Paused(address account)
func (_SponsorPaymaster *SponsorPaymasterFilterer) FilterPaused(opts *bind.FilterOpts) (*SponsorPaymasterPausedIterator, error) {

	logs, sub, err := _SponsorPaymaster.contract.FilterLogs(opts, "Paused")
	if err != nil {
		return nil, err
	}
	return &SponsorPaymasterPausedIterator{contract: _SponsorPaymaster.contract, event: "Paused", logs: logs, sub: sub}, nil
}

// WatchPaused is a free log subscription operation binding the contract event 0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258.
//
// Solidity: event Paused(address account)
func (_SponsorPaymaster *SponsorPaymasterFilterer) WatchPaused(opts *bind.WatchOpts, sink chan<- *SponsorPaymasterPaused) (event.Subscription, error) {

	logs, sub, err := _SponsorPaymaster.contract.WatchLogs(opts, "Paused")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SponsorPaymasterPaused)
				if err := _SponsorPaymaster.contract.UnpackLog(event, "Paused", log); err != nil {
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
func (_SponsorPaymaster *SponsorPaymasterFilterer) ParsePaused(log types.Log) (*SponsorPaymasterPaused, error) {
	event := new(SponsorPaymasterPaused)
	if err := _SponsorPaymaster.contract.UnpackLog(event, "Paused", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SponsorPaymasterUnpausedIterator is returned from FilterUnpaused and is used to iterate over the raw logs and unpacked data for Unpaused events raised by the SponsorPaymaster contract.
type SponsorPaymasterUnpausedIterator struct {
	Event *SponsorPaymasterUnpaused // Event containing the contract specifics and raw log

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
func (it *SponsorPaymasterUnpausedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SponsorPaymasterUnpaused)
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
		it.Event = new(SponsorPaymasterUnpaused)
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
func (it *SponsorPaymasterUnpausedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SponsorPaymasterUnpausedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SponsorPaymasterUnpaused represents a Unpaused event raised by the SponsorPaymaster contract.
type SponsorPaymasterUnpaused struct {
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterUnpaused is a free log retrieval operation binding the contract event 0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa.
//
// Solidity: event Unpaused(address account)
func (_SponsorPaymaster *SponsorPaymasterFilterer) FilterUnpaused(opts *bind.FilterOpts) (*SponsorPaymasterUnpausedIterator, error) {

	logs, sub, err := _SponsorPaymaster.contract.FilterLogs(opts, "Unpaused")
	if err != nil {
		return nil, err
	}
	return &SponsorPaymasterUnpausedIterator{contract: _SponsorPaymaster.contract, event: "Unpaused", logs: logs, sub: sub}, nil
}

// WatchUnpaused is a free log subscription operation binding the contract event 0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa.
//
// Solidity: event Unpaused(address account)
func (_SponsorPaymaster *SponsorPaymasterFilterer) WatchUnpaused(opts *bind.WatchOpts, sink chan<- *SponsorPaymasterUnpaused) (event.Subscription, error) {

	logs, sub, err := _SponsorPaymaster.contract.WatchLogs(opts, "Unpaused")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SponsorPaymasterUnpaused)
				if err := _SponsorPaymaster.contract.UnpackLog(event, "Unpaused", log); err != nil {
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
func (_SponsorPaymaster *SponsorPaymasterFilterer) ParseUnpaused(log types.Log) (*SponsorPaymasterUnpaused, error) {
	event := new(SponsorPaymasterUnpaused)
	if err := _SponsorPaymaster.contract.UnpackLog(event, "Unpaused", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SponsorPaymasterUpgradedIterator is returned from FilterUpgraded and is used to iterate over the raw logs and unpacked data for Upgraded events raised by the SponsorPaymaster contract.
type SponsorPaymasterUpgradedIterator struct {
	Event *SponsorPaymasterUpgraded // Event containing the contract specifics and raw log

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
func (it *SponsorPaymasterUpgradedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SponsorPaymasterUpgraded)
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
		it.Event = new(SponsorPaymasterUpgraded)
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
func (it *SponsorPaymasterUpgradedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SponsorPaymasterUpgradedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SponsorPaymasterUpgraded represents a Upgraded event raised by the SponsorPaymaster contract.
type SponsorPaymasterUpgraded struct {
	Implementation common.Address
	Raw            types.Log // Blockchain specific contextual infos
}

// FilterUpgraded is a free log retrieval operation binding the contract event 0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b.
//
// Solidity: event Upgraded(address indexed implementation)
func (_SponsorPaymaster *SponsorPaymasterFilterer) FilterUpgraded(opts *bind.FilterOpts, implementation []common.Address) (*SponsorPaymasterUpgradedIterator, error) {

	var implementationRule []interface{}
	for _, implementationItem := range implementation {
		implementationRule = append(implementationRule, implementationItem)
	}

	logs, sub, err := _SponsorPaymaster.contract.FilterLogs(opts, "Upgraded", implementationRule)
	if err != nil {
		return nil, err
	}
	return &SponsorPaymasterUpgradedIterator{contract: _SponsorPaymaster.contract, event: "Upgraded", logs: logs, sub: sub}, nil
}

// WatchUpgraded is a free log subscription operation binding the contract event 0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b.
//
// Solidity: event Upgraded(address indexed implementation)
func (_SponsorPaymaster *SponsorPaymasterFilterer) WatchUpgraded(opts *bind.WatchOpts, sink chan<- *SponsorPaymasterUpgraded, implementation []common.Address) (event.Subscription, error) {

	var implementationRule []interface{}
	for _, implementationItem := range implementation {
		implementationRule = append(implementationRule, implementationItem)
	}

	logs, sub, err := _SponsorPaymaster.contract.WatchLogs(opts, "Upgraded", implementationRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SponsorPaymasterUpgraded)
				if err := _SponsorPaymaster.contract.UnpackLog(event, "Upgraded", log); err != nil {
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
func (_SponsorPaymaster *SponsorPaymasterFilterer) ParseUpgraded(log types.Log) (*SponsorPaymasterUpgraded, error) {
	event := new(SponsorPaymasterUpgraded)
	if err := _SponsorPaymaster.contract.UnpackLog(event, "Upgraded", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
