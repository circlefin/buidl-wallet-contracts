/*
 * Copyright 2024 Circle Internet Group, Inc. All rights reserved.

 * SPDX-License-Identifier: GPL-3.0-or-later

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
pragma solidity 0.8.24;

import {
    EIP1271_INVALID_SIGNATURE,
    EIP1271_VALID_SIGNATURE,
    EMPTY_MODULE_ENTITY,
    WALLET_AUTHOR,
    WALLET_VERSION_1
} from "../../../../common/Constants.sol";
import {ExecutionUtils} from "../../../../utils/ExecutionUtils.sol";
import {
    InvalidAuthorizer,
    InvalidExecutionFunction,
    NotFoundSelector,
    UnauthorizedCaller
} from "../../shared/common/Errors.sol";
import {AddressDLL, Bytes32DLL, Bytes4DLL, ValidationData} from "../../shared/common/Structs.sol";
import {AddressDLLLib} from "../../shared/libs/AddressDLLLib.sol";
import {Bytes32DLLLib} from "../../shared/libs/Bytes32DLLLib.sol";

import {Bytes32DLLLib} from "../../shared/libs/Bytes32DLLLib.sol";

import {Bytes4DLLLib} from "../../shared/libs/Bytes4DLLLib.sol";
import {ValidationDataLib} from "../../shared/libs/ValidationDataLib.sol";
import {GLOBAL_VALIDATION_FLAG, RESERVED_VALIDATION_DATA_INDEX} from "../common/Constants.sol";
import {
    Bytes32DLL,
    Call,
    ExecutionDetail,
    ExecutionHook,
    PostExecHookToRun,
    ValidationDetail
} from "../common/Structs.sol";

import {ModuleEntity, ValidationConfig} from "../common/Types.sol";
import {IAccountExecute} from "../interfaces/IAccountExecute.sol";
import {IAccountLoupe} from "../interfaces/IAccountLoupe.sol";
import {IPluginManager} from "../interfaces/IPluginManager.sol";
import {IStandardExecutor} from "../interfaces/IStandardExecutor.sol";
import {IValidation} from "../interfaces/IValidation.sol";
import {IValidationHook} from "../interfaces/IValidationHook.sol";
import {ExecutionHookLib} from "../libs/ExecutionHookLib.sol";
import {SelectorRegistryLib} from "../libs/SelectorRegistryLib.sol";
import {WalletStorageLib} from "../libs/WalletStorageLib.sol";
import {ModuleEntityLib} from "../libs/thirdparty/ModuleEntityLib.sol";

import {ModuleEntityLib} from "../libs/thirdparty/ModuleEntityLib.sol";
import {SparseCalldataSegmentLib} from "../libs/thirdparty/SparseCalldataSegmentLib.sol";
import {PluginManager} from "../managers/PluginManager.sol";
import {StandardExecutor} from "../managers/StandardExecutor.sol";
import {WalletStorageInitializable} from "./WalletStorageInitializable.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @dev Base MSCA implementation with **authentication**.
 * This contract provides the basic logic for implementing the MSCA interfaces;
 * specific account implementation should inherit this contract.
 */
abstract contract BaseMSCA is
    WalletStorageInitializable,
    IPluginManager,
    IAccountLoupe,
    IStandardExecutor,
    IAccountExecute,
    IERC165,
    IERC1271
{
    using Bytes32DLLLib for Bytes32DLL;
    using ModuleEntityLib for ModuleEntity;
    using ExecutionHookLib for Bytes32DLL;
    using ExecutionHookLib for PostExecHookToRun[];
    using ExecutionUtils for address;
    using StandardExecutor for address;
    using StandardExecutor for Call[];
    using AddressDLLLib for AddressDLL;
    using ValidationDataLib for ValidationData;
    using SelectorRegistryLib for bytes4;
    using SparseCalldataSegmentLib for bytes;
    using Bytes4DLLLib for Bytes4DLL;

    string public constant AUTHOR = WALLET_AUTHOR;
    string public constant VERSION = WALLET_VERSION_1;
    // 4337 related immutable storage
    IEntryPoint public immutable ENTRY_POINT;
    PluginManager public immutable pluginManager;

    error NotNativeFunctionSelector(bytes4 selector);
    error PreRuntimeValidationHookFailed(address plugin, uint32 entityId, bytes revertReason);
    error RuntimeValidationFailed(address plugin, uint32 entityId, bytes revertReason);
    error AlwaysDenyRule();
    error InvalidSignatureValidation(ModuleEntity sigValidation);
    error ExecFromPluginToSelectorNotPermitted(address plugin, bytes4 selector);
    error RuntimeValidationFunctionMissing(bytes4 selector, ModuleEntity validation);
    error UserOpValidationFunctionMissing(bytes4 selector, ModuleEntity validation);
    error InvalidCalldataLength(uint256 actualLength, uint256 requiredLength);
    error SignatureSegmentOutOfOrder();
    error InvalidSignatureSegmentPacking();
    error ZeroSignatureSegment();
    error RequireUserOperationContext();
    error SelfCallRecursionDepthExceeded();
    error InvalidAuthorizationOrSigLength(uint256 actualLength, uint256 requiredLength);
    error InvalidModuleEntity(ModuleEntity moduleEntity);

    /**
     * @dev Wraps execution of a native function (as opposed to a function added by plugins) with runtime validations
     * (not from EP)
     *      and hooks. Used by execute, executeBatch, installPlugin, uninstallPlugin, upgradeTo and upgradeToAndCall.
     *      If the call is from entry point, then validateUserOp will run.
     *      https://eips.ethereum.org/assets/eip-6900/Modular_Account_Call_Flow.svg
     */
    modifier validateNativeFunction() {
        if (!msg.sig._isNativeFunctionSelector()) {
            revert NotNativeFunctionSelector(msg.sig);
        }
        ExecutionDetail storage executionDetail = WalletStorageLib.getLayout().executionDetails[msg.sig];
        _checkPermittedCallerIfNotFromEP(executionDetail);
        PostExecHookToRun[] memory postExecHooks = executionDetail.executionHooks._processPreExecHooks(msg.data);
        _;
        postExecHooks._processPostExecHooks();
    }

    /**
     * @dev This function allows entry point or SA itself to execute certain actions.
     * If the caller is not authorized, the function will revert with an error message.
     */
    modifier onlyFromEntryPointOrSelf() {
        _checkAccessRuleFromEPOrAcctItself();
        _;
    }

    constructor(IEntryPoint _newEntryPoint, PluginManager _newPluginManager) {
        ENTRY_POINT = _newEntryPoint;
        pluginManager = _newPluginManager;
        // lock the implementation contract so it can only be called from proxies
        _disableWalletStorageInitializers();
    }

    receive() external payable {}

    /// @notice Manage fallback calls made to the plugins.
    /// @dev Route calls to execution functions based on incoming msg.sig
    ///      If there's no plugin associated with this function selector, revert
    fallback(bytes calldata) external payable returns (bytes memory result) {
        // load the executionDetail before we run the preExecHooks because they may modify the plugins
        ExecutionDetail storage executionDetail = WalletStorageLib.getLayout().executionDetails[msg.sig];
        address executionFunctionPlugin = executionDetail.plugin;
        // valid plugin address should not be 0
        if (executionFunctionPlugin == address(0)) {
            revert InvalidExecutionFunction(msg.sig);
        }
        _checkPermittedCallerIfNotFromEP(executionDetail);
        PostExecHookToRun[] memory postExecHooks = executionDetail.executionHooks._processPreExecHooks(msg.data);
        result = executionFunctionPlugin.callWithReturnDataOrRevert(msg.value, msg.data);
        postExecHooks._processPostExecHooks();
        return result;
    }

    /**
     * @dev Return the entryPoint used by this account.
     * subclass should return the current entryPoint used by this account.
     */
    function getEntryPoint() external view returns (IEntryPoint) {
        return ENTRY_POINT;
    }

    /**
     * @dev Validate user's signature and nonce.
     * subclass doesn't need to override this method. Instead, it should override the specific internal validation
     * methods.
     */
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        virtual
        returns (uint256 validationData)
    {
        if (msg.sender != address(ENTRY_POINT)) {
            revert UnauthorizedCaller();
        }
        validationData = _authenticateAndAuthorizeUserOp(userOp, userOpHash);
        if (missingAccountFunds != 0) {
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds, gas: type(uint256).max}("");
            (success);
            // ignore failure (its EntryPoint's job to verify, not account.)
        }
    }

    /// @notice ERC165 introspection https://eips.ethereum.org/EIPS/eip-165
    /// @dev returns true for `IERC165.interfaceId` and false for `0xFFFFFFFF`
    /// @param interfaceId interface id to check against
    /// @return bool support for specific interface
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        if (interfaceId == 0xffffffff) {
            return false;
        }
        if (interfaceId == type(IERC165).interfaceId) {
            return true;
        }
        return WalletStorageLib.getLayout().supportedInterfaces[interfaceId] > 0;
    }

    /// @inheritdoc IERC1271
    function isValidSignature(bytes32 hash, bytes calldata signature) public view override returns (bytes4) {
        ModuleEntity sigValidation = ModuleEntity.wrap(bytes24(signature));
        if (!WalletStorageLib.getLayout().validationDetails[sigValidation].isSignatureValidation) {
            revert InvalidSignatureValidation(sigValidation);
        }
        (address plugin, uint32 entityId) = sigValidation.unpack();
        if (
            IValidation(plugin).validateSignature(address(this), entityId, msg.sender, hash, signature[24:])
                == EIP1271_VALID_SIGNATURE
        ) {
            return EIP1271_VALID_SIGNATURE;
        }
        return EIP1271_INVALID_SIGNATURE;
    }

    /**
     * @dev Return the account nonce.
     * This method returns the next sequential nonce.
     * For a nonce of a specific key, use `entrypoint.getNonce(account, key)`
     */
    function getNonce() public view virtual returns (uint256) {
        return ENTRY_POINT.getNonce(address(this), 0);
    }

    /// @inheritdoc IPluginManager
    /// @notice Maybe be validated by a global validation.
    function installPlugin(address plugin, bytes memory pluginInstallData) external override validateNativeFunction {
        bytes memory data = abi.encodeCall(PluginManager.installPlugin, (plugin, pluginInstallData));
        address(pluginManager).delegateCall(data);
        emit PluginInstalled(plugin);
    }

    /// @inheritdoc IPluginManager
    /// @notice Maybe be validated by a global validation.
    function uninstallPlugin(address plugin, bytes memory config, bytes memory pluginUninstallData)
        external
        override
        validateNativeFunction
    {
        bytes memory data = abi.encodeCall(PluginManager.uninstallPlugin, (plugin, config, pluginUninstallData));
        address(pluginManager).delegateCall(data);
        emit PluginUninstalled(plugin, true);
    }

    /// @inheritdoc IPluginManager
    /// @notice Maybe be validated by a global validation.
    function installValidation(
        ValidationConfig validationConfig,
        bytes4[] calldata selectors,
        bytes calldata installData,
        bytes calldata hooks,
        bytes calldata permissionHooks
    ) external override validateNativeFunction {
        bytes memory data = abi.encodeCall(
            PluginManager.installValidation, (validationConfig, selectors, installData, hooks, permissionHooks)
        );
        address(pluginManager).delegateCall(data);
        emit ValidationInstalled(validationConfig, selectors);
    }

    /// @inheritdoc IPluginManager
    /// @notice Maybe be validated by a global validation.
    function uninstallValidation(
        ModuleEntity validationFunction,
        bytes calldata uninstallData,
        bytes calldata hookUninstallData,
        bytes calldata permissionHookUninstallData
    ) external override validateNativeFunction {
        bytes memory data = abi.encodeCall(
            PluginManager.uninstallValidation,
            (validationFunction, uninstallData, hookUninstallData, permissionHookUninstallData)
        );
        address(pluginManager).delegateCall(data);
        emit ValidationUnInstalled(validationFunction);
    }

    /// @inheritdoc IAccountExecute
    function executeUserOp(PackedUserOperation calldata userOp, bytes32) external {
        if (msg.sender != address(ENTRY_POINT)) {
            revert UnauthorizedCaller();
        }
        // use case: spending limits hook
        Bytes32DLL storage permissionHooks = WalletStorageLib.getLayout().validationDetails[ModuleEntity.wrap(
            bytes24(userOp.signature[:24])
        )].permissionHooks;
        PostExecHookToRun[] memory postPermissionHooks = permissionHooks._processPreExecHooks(msg.data);
        address(this).callWithReturnDataOrRevert(0, userOp.callData[4:]);
        postPermissionHooks._processPostExecHooks();
    }

    /// @inheritdoc IStandardExecutor
    /// @notice Maybe be validated by a global validation.
    function execute(address target, uint256 value, bytes calldata data)
        external
        payable
        override
        validateNativeFunction
        returns (bytes memory returnData)
    {
        return target.execute(value, data);
    }

    /// @inheritdoc IStandardExecutor
    /// @notice Maybe be validated by a global validation.
    function executeBatch(Call[] calldata calls)
        external
        payable
        override
        validateNativeFunction
        returns (bytes[] memory returnData)
    {
        return calls.executeBatch();
    }

    /// @inheritdoc IStandardExecutor
    /// @notice Maybe be validated by a global validation.
    function executeWithAuthorization(bytes calldata data, bytes calldata authorization)
        external
        payable
        returns (bytes memory result)
    {
        if (data.length < 4) {
            revert InvalidCalldataLength(data.length, 4);
        }
        if (bytes4(data[:4]) == bytes4(0)) {
            revert NotFoundSelector();
        }
        // TODO: update this check to include other fields
        if (authorization.length < 25) {
            revert InvalidAuthorizationOrSigLength(authorization.length, 25);
        }
        ModuleEntity validationFunction = ModuleEntity.wrap(bytes24(authorization[:24]));
        bool isGlobalValidation = uint8(authorization[24]) == GLOBAL_VALIDATION_FLAG;
        WalletStorageLib.Layout storage walletStorage = WalletStorageLib.getLayout();
        if (!_checkHookAndValidationForCalldata(walletStorage, data, validationFunction, isGlobalValidation)) {
            // just use the outer selector for error
            revert RuntimeValidationFunctionMissing(bytes4(data[:4]), validationFunction);
        }
        _processRuntimeHooksAndValidation(
            walletStorage.validationDetails[validationFunction].preValidationHooks,
            validationFunction,
            data,
            authorization[25:]
        );

        // run permission checks
        Bytes32DLL storage permissionHooks =
            WalletStorageLib.getLayout().validationDetails[validationFunction].permissionHooks;
        PostExecHookToRun[] memory postPermissionHooks = permissionHooks._processPreExecHooks(msg.data);
        // self execute call
        result = address(this).callWithReturnDataOrRevert(0, data);
        postPermissionHooks._processPostExecHooks();
        return result;
    }

    /// @inheritdoc IAccountLoupe
    function getExecutionData(bytes4 selector) external view returns (address) {
        WalletStorageLib.Layout storage walletStorage = WalletStorageLib.getLayout();
        if (selector._isNativeFunctionSelector()) {
            return address(this);
        } else {
            return walletStorage.executionDetails[selector].plugin;
        }
    }

    /// @inheritdoc IAccountLoupe
    function getSelectors(ModuleEntity validationFunction) external view returns (bytes4[] memory) {
        return WalletStorageLib.getLayout().validationDetails[validationFunction].selectors.getAll();
    }

    /// @inheritdoc IAccountLoupe
    function getExecutionHooks(bytes4 selector) external view returns (ExecutionHook[] memory) {
        return WalletStorageLib.getLayout().executionDetails[selector].executionHooks._getExecutionHooks();
    }

    /// @inheritdoc IAccountLoupe
    function getPermissionHooks(ModuleEntity validationFunction)
        external
        view
        override
        returns (ExecutionHook[] memory)
    {
        return WalletStorageLib.getLayout().validationDetails[validationFunction].permissionHooks._getExecutionHooks();
    }

    /// @inheritdoc IAccountLoupe
    function getPreValidationHooks(ModuleEntity validationFunction) external view returns (ModuleEntity[] memory) {
        return WalletStorageLib.getLayout().validationDetails[validationFunction].preValidationHooks;
    }

    /// @notice Gets an array of all installed plugins
    /// @return pluginAddresses The addresses of all installed plugins
    function getInstalledPlugins() external view returns (address[] memory pluginAddresses) {
        return WalletStorageLib.getLayout().installedPlugins.getAll();
    }

    /**
     * Check current account deposit in the entryPoint.
     */
    function getDeposit() public view returns (uint256) {
        return ENTRY_POINT.balanceOf(address(this));
    }

    /**
     * Deposit more funds for this account in the entryPoint.
     */
    function addDeposit() public payable {
        ENTRY_POINT.depositTo{value: msg.value}(address(this));
    }

    /**
     * Withdraw value from the account's deposit.
     * @param withdrawAddress target to send to
     * @param amount to withdraw
     */
    function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public onlyFromEntryPointOrSelf {
        ENTRY_POINT.withdrawTo(withdrawAddress, amount);
    }

    /**
     * @dev Authenticate and authorize this userOp. OnlyFromEntryPoint is applied in the caller.
     * @param userOp validate the userOp.signature field
     * @param userOpHash convenient field: the hash of the request, to check the signature against
     *          (also hashes the entrypoint and chain id)
     * @return validationData signature and time-range of this operation
     *      <20-byte> sigAuthorizer - 0 for valid signature, 1 to mark signature failure,
     *         otherwise, an address of an "authorizer" contract.
     *      <6-byte> validUntil - last timestamp this operation is valid. 0 for "indefinite"
     *      <6-byte> validAfter - first timestamp this operation is valid
     *      If the account doesn't use time-range, it is enough to return SIG_VALIDATION_FAILED value (1) for signature
     * failure.
     *      Note that the validation code cannot use block.timestamp (or block.number) directly due to the storage rule.
     */
    function _authenticateAndAuthorizeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        virtual
        returns (uint256 validationData)
    {
        // onlyFromEntryPoint is applied in the caller
        // if there is no function defined for the selector, or if userOp.callData.length < 4, then execution MUST
        // revert
        if (userOp.callData.length < 4) {
            revert InvalidCalldataLength(userOp.callData.length, 4);
        }
        if (bytes4(userOp.callData[:4]) == bytes4(0)) {
            revert NotFoundSelector();
        }
        // TODO: update this check to include other fields
        if (userOp.signature.length < 25) {
            revert InvalidAuthorizationOrSigLength(userOp.signature.length, 25);
        }
        ModuleEntity validationFunction = ModuleEntity.wrap(bytes24(userOp.signature[:24]));
        bool isGlobalValidation = uint8(userOp.signature[24]) == GLOBAL_VALIDATION_FLAG;
        WalletStorageLib.Layout storage walletStorage = WalletStorageLib.getLayout();
        if (!_checkHookAndValidationForCalldata(walletStorage, userOp.callData, validationFunction, isGlobalValidation))
        {
            // just use the outer selector for error
            revert UserOpValidationFunctionMissing(bytes4(userOp.callData[0:4]), validationFunction);
        }
        // check if there are permission hooks associated with the validation function, and revert if we're not calling
        // `executeUserOp`,
        // we need some userOp context (e.g. signature) from validation to execution to tell which permission hooks
        // should have ran because the hooks
        // are associated with validation function in storage,
        // only `executeUserOp` would have access to userOp
        ValidationDetail storage validationDetail = walletStorage.validationDetails[validationFunction];
        if (validationDetail.permissionHooks.size() > 0 && bytes4(userOp.callData[:4]) != this.executeUserOp.selector) {
            revert RequireUserOperationContext();
        }

        // use restored signature
        return _processUserOpHooksAndValidation(
            validationDetail.preValidationHooks, validationFunction, userOp, userOp.signature[25:], userOpHash
        );
    }

    function _processUserOpHooksAndValidation(
        ModuleEntity[] memory validationHookFunctions,
        ModuleEntity validationFunction,
        PackedUserOperation memory userOp,
        bytes calldata signature,
        bytes32 userOpHash
    ) internal virtual returns (uint256 validationData) {
        bytes calldata signatureSegment;
        (signatureSegment, signature) = signature.getNextSegment();
        ValidationData memory unpackedValidationData = ValidationData(0, 0xFFFFFFFFFFFF, address(0));
        // if the function selector has associated pre user operation validation hooks, then those hooks MUST be run
        // sequentially
        uint256 currentValidationData;
        for (uint256 i = 0; i < validationHookFunctions.length; ++i) {
            if (signatureSegment.getIndex() == i) {
                // exclude the index
                userOp.signature = signatureSegment.getBody();
                if (userOp.signature.length == 0) {
                    revert ZeroSignatureSegment();
                }
                // move forward both segment and calldata
                (signatureSegment, signature) = signature.getNextSegment();
                if (signatureSegment.getIndex() <= i) {
                    revert SignatureSegmentOutOfOrder();
                }
            } else {
                userOp.signature = "";
            }
            // send the userOp with signature segment for this particular hook function
            (address hookPlugin, uint32 hookEntityId) = validationHookFunctions[i].unpack();
            currentValidationData =
                IValidationHook(hookPlugin).preUserOpValidationHook(hookEntityId, userOp, userOpHash);
            unpackedValidationData = unpackedValidationData._intersectValidationData(currentValidationData);
            // if any return an authorizer value other than 0 or 1, execution MUST revert
            if (unpackedValidationData.authorizer != address(0) && unpackedValidationData.authorizer != address(1)) {
                revert InvalidAuthorizer();
            }
        }
        // a single byte index caps the total number of pre-validation hooks at 255
        if (signatureSegment.getIndex() != RESERVED_VALIDATION_DATA_INDEX) {
            revert InvalidSignatureSegmentPacking();
        }
        userOp.signature = signatureSegment.getBody();
        (address plugin, uint32 entityId) = validationFunction.unpack();
        // execute the validation function with the user operation and its hash as parameters using the call opcode
        currentValidationData = IValidation(plugin).validateUserOp(entityId, userOp, userOpHash);
        // intercept with validation function call
        unpackedValidationData = unpackedValidationData._intersectValidationData(currentValidationData);
        if (unpackedValidationData.authorizer != address(0) && unpackedValidationData.authorizer != address(1)) {
            // only revert on unexpected values
            revert InvalidAuthorizer();
        }
        return unpackedValidationData._packValidationData();
    }

    /**
     * @dev Default validation logic is from installed plugins. However, you can override this validation logic in MSCA
     *      implementations. For instance, semi MSCA such as single owner semi MSCA may want to honor the validation
     *      from native owner.
     */
    function _processRuntimeHooksAndValidation(
        ModuleEntity[] memory validationHookFunctions,
        ModuleEntity validationFunction,
        bytes calldata data,
        bytes calldata authorization
    ) internal virtual {
        bytes calldata authorizationSegment;
        (authorizationSegment, authorization) = authorization.getNextSegment();
        for (uint256 i = 0; i < validationHookFunctions.length; ++i) {
            bytes memory currentAuthorization;
            if (authorizationSegment.getIndex() == i) {
                // exclude the index
                currentAuthorization = authorizationSegment.getBody();
                if (currentAuthorization.length == 0) {
                    revert ZeroSignatureSegment();
                }
                // move forward both segment and calldata
                (authorizationSegment, authorization) = authorization.getNextSegment();
                if (authorizationSegment.getIndex() <= i) {
                    revert SignatureSegmentOutOfOrder();
                }
            } else {
                currentAuthorization = "";
            }
            // send the authorization segment for this particular hook function
            (address hookPlugin, uint32 hookEntityId) = validationHookFunctions[i].unpack();
            try IValidationHook(hookPlugin).preRuntimeValidationHook(
                hookEntityId, msg.sender, msg.value, data, currentAuthorization
            ) {} catch (bytes memory revertReason) {
                revert PreRuntimeValidationHookFailed(hookPlugin, hookEntityId, revertReason);
            }
        }
        // a single byte index caps the total number of pre-validation hooks at 255
        if (authorizationSegment.getIndex() != RESERVED_VALIDATION_DATA_INDEX) {
            revert InvalidSignatureSegmentPacking();
        }
        (address plugin, uint32 entityId) = validationFunction.unpack();
        try IValidation(plugin).validateRuntime(
            address(this), entityId, msg.sender, msg.value, data, authorizationSegment.getBody()
        ) {} catch (bytes memory revertReason) {
            revert RuntimeValidationFailed(plugin, entityId, revertReason);
        }
    }

    function _checkAccessRuleFromEPOrAcctItself() internal view {
        if (msg.sender != address(ENTRY_POINT) && msg.sender != address(this)) {
            revert UnauthorizedCaller();
        }
    }

    function _checkPermittedCallerIfNotFromEP(ExecutionDetail storage executionDetail) internal view {
        if (msg.sender != address(ENTRY_POINT) && msg.sender != address(this) && !executionDetail.skipRuntimeValidation)
        {
            revert ExecFromPluginToSelectorNotPermitted(msg.sender, msg.sig);
        }
    }

    /// @dev Check if the hook and validation function is enabled for the calldata.
    /// @notice Self-call rule: if the function selector is execute, we don't allow self call because the inner call may
    /// instead be pulled up to the top-level call,
    ///                         if the function selector is executeBatch, then we inspect the selector in each Call
    /// where the target is the account itself,
    ///                             * the validation currently being used must apply to inner call selector
    ///                             * the inner call selector must not recursively call into the account's execute or
    /// executeBatch functions
    function _checkHookAndValidationForCalldata(
        WalletStorageLib.Layout storage walletStorage,
        bytes calldata callData,
        ModuleEntity validationFunction,
        bool isGlobalValidationFunction
    ) internal view returns (bool) {
        bytes4 outerSelector = bytes4(callData[:4]);
        if (outerSelector == this.executeUserOp.selector) {
            // passing executeUserOp function selector at the beginning of callData will cause the entryPoint to pass
            // the
            // full UserOp (and hash) to the account
            // the account should skip executeUserOp function selector, and use the trimmed callData
            // please also refer to
            // https://github.com/eth-infinitism/account-abstraction/blob/7af70c8993a6f42973f520ae0752386a5032abe7/contracts/core/EntryPoint.sol#L101-L107
            outerSelector = bytes4(callData[4:8]);
            callData = callData[4:];
        }
        // check outer selector is allowed by the validation function
        if (
            !_checkHookAndValidationForSelector(
                walletStorage, outerSelector, validationFunction, isGlobalValidationFunction
            )
        ) {
            return false;
        }
        // executeBatch may be used to batch calls into the account itself, but not for execute
        if (outerSelector == IStandardExecutor.execute.selector) {
            (address target,,) = abi.decode(callData[4:], (address, uint256, bytes));
            if (target == address(this)) {
                revert SelfCallRecursionDepthExceeded();
            }
        } else if (outerSelector == IStandardExecutor.executeBatch.selector) {
            (Call[] memory calls) = abi.decode(callData[4:], (Call[]));
            for (uint256 i = 0; i < calls.length; ++i) {
                // to prevent arbitrarily-deep recursive checking, all self-calls must occur at the top level of the
                // batch
                if (calls[i].target == address(this)) {
                    bytes4 innerSelector = bytes4(calls[i].data);
                    if (
                        innerSelector == IStandardExecutor.execute.selector
                            || innerSelector == IStandardExecutor.executeBatch.selector
                    ) {
                        revert SelfCallRecursionDepthExceeded();
                    }
                    // check all of the inner calls are allowed by the validation function
                    if (
                        !_checkHookAndValidationForSelector(
                            walletStorage, innerSelector, validationFunction, isGlobalValidationFunction
                        )
                    ) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    /// @dev Check if the hook and validation function is enabled for the selector.
    function _checkHookAndValidationForSelector(
        WalletStorageLib.Layout storage walletStorage,
        bytes4 selector,
        ModuleEntity validationFunction,
        bool isGlobalValidationFunction
    ) internal view returns (bool) {
        if (ModuleEntity.unwrap(validationFunction) == EMPTY_MODULE_ENTITY) {
            revert InvalidModuleEntity(validationFunction);
        }
        if (isGlobalValidationFunction) {
            // 1. the function selector need to be enabled for global validation
            // 2. the global validation has been registered
            if (
                (selector._isNativeFunctionSelector() || walletStorage.executionDetails[selector].allowGlobalValidation)
                    && walletStorage.validationDetails[validationFunction].isGlobal
            ) {
                return true;
            }
        } else {
            // selector per validation
            if (walletStorage.validationDetails[validationFunction].selectors.contains(selector)) {
                return true;
            }
        }
        return false;
    }
}
