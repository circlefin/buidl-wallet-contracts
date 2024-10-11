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
    SENTINEL_BYTES32,
    SENTINEL_BYTES4
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
import {Bytes4DLLLib} from "../../shared/libs/Bytes4DLLLib.sol";
import {ValidationDataLib} from "../../shared/libs/ValidationDataLib.sol";
import {DIRECT_CALL_VALIDATION_ENTITY_ID, GLOBAL_VALIDATION_FLAG, MAX_VALIDATION_HOOKS} from "../common/Constants.sol";

import {ExecutionManifest, ManifestExecutionHook} from "../common/ModuleManifest.sol";
import {
    Bytes32DLL,
    Call,
    ExecutionDataView,
    ExecutionDetail,
    PostExecHookToRun,
    ValidationDataView,
    ValidationDetail
} from "../common/Structs.sol";

import {HookConfig, ModuleEntity, ValidationConfig} from "../common/Types.sol";

import {IExecutionHookModule} from "../interfaces/IExecutionHookModule.sol";
import {IModularAccount} from "../interfaces/IModularAccount.sol";
import {IModularAccountView} from "../interfaces/IModularAccountView.sol";
import {IModule} from "../interfaces/IModule.sol";

import {IValidationHookModule} from "../interfaces/IValidationHookModule.sol";
import {IValidationModule} from "../interfaces/IValidationModule.sol";

import {HookConfigLib} from "../libs/HookConfigLib.sol";
import {SelectorRegistryLib} from "../libs/SelectorRegistryLib.sol";
import {WalletStorageLib} from "../libs/WalletStorageLib.sol";
import {ModuleEntityLib} from "../libs/thirdparty/ModuleEntityLib.sol";
import {ValidationConfigLib} from "../libs/thirdparty/ValidationConfigLib.sol";

import {SparseCalldataSegmentLib} from "../libs/thirdparty/SparseCalldataSegmentLib.sol";
import {StandardExecutor} from "../managers/StandardExecutor.sol";
import {WalletStorageInitializable} from "./WalletStorageInitializable.sol";

import {IAccount} from "@account-abstraction/contracts/interfaces/IAccount.sol";
import {IAccountExecute} from "@account-abstraction/contracts/interfaces/IAccountExecute.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @dev Base MSCA implementation with **authentication**.
 * This contract provides the basic logic for implementing the MSCA interfaces;
 * specific account implementation should inherit this contract.
 */
abstract contract BaseMSCA is
    WalletStorageInitializable,
    IAccount,
    IAccountExecute,
    IModularAccount,
    IModularAccountView,
    IERC165,
    IERC1271
{
    using Bytes32DLLLib for Bytes32DLL;
    using ModuleEntityLib for ModuleEntity;
    using HookConfigLib for Bytes32DLL;
    using HookConfigLib for PostExecHookToRun[];
    using ExecutionUtils for address;
    using StandardExecutor for address;
    using StandardExecutor for Call[];
    using AddressDLLLib for AddressDLL;
    using ValidationDataLib for ValidationData;
    using SelectorRegistryLib for bytes4;
    using SparseCalldataSegmentLib for bytes;
    using Bytes4DLLLib for Bytes4DLL;
    using ValidationConfigLib for ValidationConfig;
    using HookConfigLib for HookConfig;
    using HookConfigLib for bytes32;

    enum ValidationCheckingType {
        GLOBAL,
        SELECTOR,
        EITHER
    }
    // 4337 related immutable storage

    IEntryPoint public immutable ENTRY_POINT;

    error NotNativeFunctionSelector(bytes4 selector);
    error PreRuntimeValidationHookFailed(address module, uint32 entityId, bytes revertReason);
    error RuntimeValidationFailed(address module, uint32 entityId, bytes revertReason);
    error AlwaysDenyRule();
    error InvalidSignatureValidation(ModuleEntity sigValidation);
    error InvalidUserOpValidation(ModuleEntity userOpValidation);
    error ExecFromModuleToSelectorNotPermitted(address module, bytes4 selector);
    error ValidationFunctionMissing(bytes4 selector, ModuleEntity validation);
    error InvalidCalldataLength(uint256 actualLength, uint256 requiredLength);
    error RequireUserOperationContext();
    error SelfCallRecursionDepthExceeded();
    error InvalidAuthorizationOrSigLength(uint256 actualLength, uint256 requiredLength);
    error InvalidModuleEntity(ModuleEntity moduleEntity);
    error ExecutionDetailAlreadySet(address module, bytes4 selector);
    error ValidationFunctionAlreadySet(bytes4 selector);
    error FailToCallOnInstall(address module, bytes revertReason);
    error InvalidExecutionSelector(address module, bytes4 selector);
    error InvalidExecutionHook(address module, bytes4 selector);
    error GlobalValidationFunctionAlreadySet(ModuleEntity validationFunction);
    error PreValidationHookLimitExceeded();
    error NullModule();
    error InterfaceNotSupported(address module, bytes4 interfaceId);
    error InvalidHookUninstallData();

    /**
     * @dev Wraps execution of a native function (as opposed to a function added by modules) with runtime validations
     * (not from EP)
     *      and hooks. Used by execute, executeBatch, installModule, uninstallModule, upgradeTo and upgradeToAndCall.
     *      If the call is from entry point, then validateUserOp will run.
     *      https://eips.ethereum.org/assets/eip-6900/Modular_Account_Call_Flow.svg
     */
    modifier validateNativeFunction() {
        if (!msg.sig._isNativeExecutionFunction()) {
            revert NotNativeFunctionSelector(msg.sig);
        }
        WalletStorageLib.Layout storage walletStorage = WalletStorageLib.getLayout();
        (
            PostExecHookToRun[] memory postExecHooksFromDirectCallValidation,
            PostExecHookToRun[] memory postExecHooksFromExecutionSelector
        ) = _checkCallPermission(walletStorage);
        _;
        postExecHooksFromExecutionSelector._processPostExecHooks();
        postExecHooksFromDirectCallValidation._processPostExecHooks();
    }

    /**
     * @dev This function allows entry point or SA itself to execute certain actions.
     * If the caller is not authorized, the function will revert with an error message.
     */
    modifier onlyFromEntryPointOrSelf() {
        _checkAccessRuleFromEPOrAcctItself();
        _;
    }

    constructor(IEntryPoint _newEntryPoint) {
        ENTRY_POINT = _newEntryPoint;
        // lock the implementation contract so it can only be called from proxies
        _disableWalletStorageInitializers();
    }

    receive() external payable {}

    /// @notice Manage fallback calls made to the modules.
    /// @dev Route calls to execution functions based on incoming msg.sig
    ///      If there's no module associated with this function selector, revert
    fallback(bytes calldata) external payable returns (bytes memory result) {
        WalletStorageLib.Layout storage walletStorage = WalletStorageLib.getLayout();
        address executionFunctionModule = walletStorage.executionDetails[msg.sig].module;
        // valid module address should not be address(0)
        if (executionFunctionModule == address(0)) {
            revert InvalidExecutionFunction(msg.sig);
        }
        (
            PostExecHookToRun[] memory postExecHooksFromDirectCallValidation,
            PostExecHookToRun[] memory postExecHooksFromExecutionSelector
        ) = _checkCallPermission(walletStorage);
        result = executionFunctionModule.callWithReturnDataOrRevert(msg.value, msg.data);
        postExecHooksFromExecutionSelector._processPostExecHooks();
        postExecHooksFromDirectCallValidation._processPostExecHooks();
        return result;
    }

    /**
     * @dev Return the entryPoint used by this account.
     * subclass should return the current entryPoint used by this account.
     */
    function entryPoint() public view returns (IEntryPoint) {
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
        override
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
        signature = signature[24:];
        HookConfig[] memory validationHooks =
            WalletStorageLib.getLayout().validationDetails[sigValidation].validationHooks;
        for (uint256 i = 0; i < validationHooks.length; ++i) {
            (address hookModule, uint32 hookEntityId) = validationHooks[i].unpackValidationHook().unpack();
            bytes memory currentSignatureSegment;
            (currentSignatureSegment, signature) = signature.advanceSegmentIfAtIndex(uint8(i));
            IValidationHookModule(hookModule).preSignatureValidationHook(
                hookEntityId, msg.sender, hash, currentSignatureSegment
            );
        }
        // validation function
        signature = signature.getFinalSegment();
        (address module, uint32 entityId) = sigValidation.unpack();
        if (
            IValidationModule(module).validateSignature(address(this), entityId, msg.sender, hash, signature)
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
    function getNonce() public view returns (uint256) {
        return entryPoint().getNonce(address(this), 0);
    }

    /// @inheritdoc IModularAccount
    /// @notice Maybe be validated by a global validation.
    function installExecution(address module, ExecutionManifest calldata manifest, bytes calldata moduleInstallData)
        external
        override
        validateNativeFunction
    {
        _installExecution(module, manifest, moduleInstallData);
        emit ExecutionInstalled(module, manifest);
    }

    /// @inheritdoc IModularAccount
    /// @notice Maybe be validated by a global validation.
    function uninstallExecution(address module, ExecutionManifest calldata manifest, bytes calldata moduleUninstallData)
        external
        override
        validateNativeFunction
    {
        bool onUninstallSuccess = _uninstallExecution(module, manifest, moduleUninstallData);
        emit ExecutionUninstalled(module, onUninstallSuccess, manifest);
    }

    /// @inheritdoc IModularAccount
    /// @notice Maybe be validated by a global validation.
    /// @dev This function can be used to update (to a certain degree) previously installed validation functions.
    ///      - preValidationHook, executionHooks, and selectors can be added later. Though they won't be deleted.
    ///      - isGlobal and isSignatureValidation can also be updated later.
    function installValidation(
        ValidationConfig validationConfig,
        bytes4[] calldata selectors,
        bytes calldata installData,
        bytes[] calldata hooks
    ) external override validateNativeFunction {
        _installValidation(validationConfig, selectors, installData, hooks);
        emit ValidationInstalled(validationConfig.module(), validationConfig.entityId());
    }

    /// @inheritdoc IModularAccount
    /// @notice Maybe be validated by a global validation.
    function uninstallValidation(
        ModuleEntity validationFunction,
        bytes calldata uninstallData,
        bytes[] calldata hookUninstallData
    ) external override validateNativeFunction {
        bool onUninstallSuccess = _uninstallValidation(validationFunction, uninstallData, hookUninstallData);
        (address module, uint32 entityId) = validationFunction.unpack();
        emit ValidationUninstalled(module, entityId, onUninstallSuccess);
    }

    /// @inheritdoc IAccountExecute
    function executeUserOp(PackedUserOperation calldata userOp, bytes32) external override {
        if (msg.sender != address(ENTRY_POINT)) {
            revert UnauthorizedCaller();
        }
        // use case: spending limits hook
        Bytes32DLL storage executionHooks = WalletStorageLib.getLayout().validationDetails[ModuleEntity.wrap(
            bytes24(userOp.signature[:24])
        )].executionHooks;
        PostExecHookToRun[] memory postExecHooks = executionHooks._processPreExecHooks(msg.data);
        address(this).callWithReturnDataOrRevert(0, userOp.callData[4:]);
        postExecHooks._processPostExecHooks();
    }

    /// @inheritdoc IModularAccount
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

    /// @inheritdoc IModularAccount
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

    /// @inheritdoc IModularAccount
    /// @notice Maybe be validated by a global validation.
    function executeWithRuntimeValidation(bytes calldata data, bytes calldata authorization)
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
        if (
            !_checkValidationForCalldata(
                walletStorage,
                data,
                validationFunction,
                isGlobalValidation ? ValidationCheckingType.GLOBAL : ValidationCheckingType.SELECTOR
            )
        ) {
            // just use the outer selector for error
            revert ValidationFunctionMissing(bytes4(data[:4]), validationFunction);
        }
        _processRuntimeHooksAndValidation(
            walletStorage.validationDetails[validationFunction].validationHooks,
            validationFunction,
            data,
            authorization[25:]
        );

        // run execution checks
        Bytes32DLL storage execHooks = WalletStorageLib.getLayout().validationDetails[validationFunction].executionHooks;
        PostExecHookToRun[] memory postExecHooks = execHooks._processPreExecHooks(msg.data);
        // self execute call
        result = address(this).callWithReturnDataOrRevert(0, data);
        postExecHooks._processPostExecHooks();
        return result;
    }

    /// @inheritdoc IModularAccountView
    function getExecutionData(bytes4 selector) external view returns (ExecutionDataView memory executionData) {
        if (selector._isGlobalValidationAllowedNativeExecutionFunction()) {
            executionData.module = address(this);
            executionData.allowGlobalValidation = true;
        } else {
            ExecutionDetail storage executionDetail = WalletStorageLib.getLayout().executionDetails[selector];
            executionData.module = executionDetail.module;
            executionData.skipRuntimeValidation = executionDetail.skipRuntimeValidation;
            executionData.allowGlobalValidation = executionDetail.allowGlobalValidation;
            executionData.executionHooks = executionDetail.executionHooks._getExecutionHooks();
        }
        return executionData;
    }

    /// @inheritdoc IModularAccountView
    function getValidationData(ModuleEntity validationFunction)
        external
        view
        returns (ValidationDataView memory validationData)
    {
        ValidationDetail storage validationDetail = WalletStorageLib.getLayout().validationDetails[validationFunction];
        validationData.isGlobal = validationDetail.isGlobal;
        validationData.isSignatureValidation = validationDetail.isSignatureValidation;
        validationData.isUserOpValidation = validationDetail.isUserOpValidation;
        validationData.validationHooks = validationDetail.validationHooks;
        validationData.executionHooks = validationDetail.executionHooks._getExecutionHooks();
        validationData.selectors = validationDetail.selectors.getAll();
        return validationData;
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
        if (
            !_checkValidationForCalldata(
                walletStorage,
                userOp.callData,
                validationFunction,
                isGlobalValidation ? ValidationCheckingType.GLOBAL : ValidationCheckingType.SELECTOR
            )
        ) {
            // just use the outer selector for error
            revert ValidationFunctionMissing(bytes4(userOp.callData[0:4]), validationFunction);
        }
        // check if there are permission hooks associated with the validation function, and revert if we're not calling
        // `executeUserOp`,
        // we need some userOp context (e.g. signature) from validation to execution to tell which permission hooks
        // should have ran because the hooks
        // are associated with validation function in storage,
        // only `executeUserOp` would have access to userOp
        ValidationDetail storage validationDetail = walletStorage.validationDetails[validationFunction];
        if (validationDetail.executionHooks.size() > 0 && bytes4(userOp.callData[:4]) != this.executeUserOp.selector) {
            revert RequireUserOperationContext();
        }

        if (!validationDetail.isUserOpValidation) {
            revert InvalidUserOpValidation(validationFunction);
        }

        // use restored signature
        return _processUserOpHooksAndValidation(
            validationDetail.validationHooks, validationFunction, userOp, userOp.signature[25:], userOpHash
        );
    }

    function _processUserOpHooksAndValidation(
        HookConfig[] memory validationHookFunctions,
        ModuleEntity validationFunction,
        PackedUserOperation memory userOp,
        bytes calldata signature,
        bytes32 userOpHash
    ) internal virtual returns (uint256 validationData) {
        ValidationData memory unpackedValidationData = ValidationData(0, 0xFFFFFFFFFFFF, address(0));
        // if the function selector has associated pre user operation validation hooks, then those hooks MUST be run
        // sequentially
        uint256 currentValidationData;
        for (uint256 i = 0; i < validationHookFunctions.length; ++i) {
            (userOp.signature, signature) = signature.advanceSegmentIfAtIndex(uint8(i));
            // send the userOp with signature segment for this particular hook function
            (address hookModule, uint32 hookEntityId) = validationHookFunctions[i].unpackValidationHook().unpack();
            currentValidationData =
                IValidationHookModule(hookModule).preUserOpValidationHook(hookEntityId, userOp, userOpHash);
            unpackedValidationData = unpackedValidationData._intersectValidationData(currentValidationData);
            // if any return an authorizer value other than 0 or 1, execution MUST revert
            if (unpackedValidationData.authorizer != address(0) && unpackedValidationData.authorizer != address(1)) {
                revert InvalidAuthorizer();
            }
        }
        // validation function
        userOp.signature = signature.getFinalSegment();
        (address module, uint32 entityId) = validationFunction.unpack();
        // execute the validation function with the user operation and its hash as parameters using the call opcode
        currentValidationData = IValidationModule(module).validateUserOp(entityId, userOp, userOpHash);
        // intersect with validation function call
        unpackedValidationData = unpackedValidationData._intersectValidationData(currentValidationData);
        if (unpackedValidationData.authorizer != address(0) && unpackedValidationData.authorizer != address(1)) {
            // only revert on unexpected values
            revert InvalidAuthorizer();
        }
        return unpackedValidationData._packValidationData();
    }

    /**
     * @dev Default validation logic is from installed modules. However, you can override this validation logic in MSCA
     *      implementations. For instance, semi MSCA such as single owner semi MSCA may want to honor the validation
     *      from native owner.
     */
    function _processRuntimeHooksAndValidation(
        HookConfig[] memory validationHookFunctions,
        ModuleEntity validationFunction,
        bytes calldata data,
        bytes calldata authorizationData
    ) internal virtual {
        for (uint256 i = 0; i < validationHookFunctions.length; ++i) {
            bytes memory currentAuthorization;
            (currentAuthorization, authorizationData) = authorizationData.advanceSegmentIfAtIndex(uint8(i));
            // send the authorization segment for this particular hook function
            (address hookModule, uint32 hookEntityId) = validationHookFunctions[i].unpackValidationHook().unpack();
            try IValidationHookModule(hookModule).preRuntimeValidationHook(
                hookEntityId, msg.sender, msg.value, data, currentAuthorization
            ) {} catch {
                bytes memory revertReason = ExecutionUtils.fetchReturnData();
                revert PreRuntimeValidationHookFailed(hookModule, hookEntityId, revertReason);
            }
        }
        // validation function
        authorizationData = authorizationData.getFinalSegment();
        (address module, uint32 entityId) = validationFunction.unpack();
        try IValidationModule(module).validateRuntime(
            address(this), entityId, msg.sender, msg.value, data, authorizationData
        ) {} catch {
            bytes memory revertReason = ExecutionUtils.fetchReturnData();
            revert RuntimeValidationFailed(module, entityId, revertReason);
        }
    }

    function _installExecution(address module, ExecutionManifest calldata manifest, bytes calldata moduleInstallData)
        internal
    {
        if (module == address(0)) {
            revert NullModule();
        }
        WalletStorageLib.Layout storage storageLayout = WalletStorageLib.getLayout();
        uint256 length = manifest.interfaceIds.length;
        for (uint256 i = 0; i < length; ++i) {
            storageLayout.supportedInterfaces[manifest.interfaceIds[i]] += 1;
        }

        // record execution details
        //////////////////////////////////////////////
        // install execution functions and hooks
        //////////////////////////////////////////////
        length = manifest.executionFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            bytes4 selector = manifest.executionFunctions[i].executionSelector;
            if (storageLayout.executionDetails[selector].module != address(0)) {
                revert ExecutionDetailAlreadySet(module, selector);
            }
            if (selector._isNativeFunction() || selector._isErc4337Function() || selector._isIModuleFunction()) {
                revert InvalidExecutionSelector(module, selector);
            }
            storageLayout.executionDetails[selector].module = module;
            storageLayout.executionDetails[selector].skipRuntimeValidation =
                manifest.executionFunctions[i].skipRuntimeValidation;
            storageLayout.executionDetails[selector].allowGlobalValidation =
                manifest.executionFunctions[i].allowGlobalValidation;
        }

        // install execution hooks
        length = manifest.executionHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestExecutionHook memory manifestExecHook = manifest.executionHooks[i];
            bytes4 selector = manifestExecHook.executionSelector;
            if (!manifestExecHook.isPreHook && !manifestExecHook.isPostHook) {
                revert InvalidExecutionHook(module, selector);
            }
            HookConfig hookConfig = HookConfigLib.packExecHook({
                _module: module,
                _entityId: manifestExecHook.entityId,
                _hasPre: manifestExecHook.isPreHook,
                _hasPost: manifestExecHook.isPostHook
            });
            storageLayout.executionDetails[selector].executionHooks.append(hookConfig.toBytes32());
        }

        // call onInstall to initialize module data for the modular account
        _onInstall(module, moduleInstallData, type(IModule).interfaceId);
    }

    function _uninstallExecution(
        address module,
        ExecutionManifest calldata manifest,
        bytes calldata moduleUninstallData
    ) internal returns (bool) {
        WalletStorageLib.Layout storage storageLayout = WalletStorageLib.getLayout();
        // uninstall the components in reverse order (by component type) of their installation
        //////////////////////////////////////////////
        // uninstall execution hooks and functions
        //////////////////////////////////////////////
        uint256 length = manifest.executionHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestExecutionHook memory manifestExecHook = manifest.executionHooks[i];
            HookConfig hookConfig = HookConfigLib.packExecHook({
                _module: module,
                _entityId: manifestExecHook.entityId,
                _hasPre: manifestExecHook.isPreHook,
                _hasPost: manifestExecHook.isPostHook
            });
            storageLayout.executionDetails[manifestExecHook.executionSelector].executionHooks.remove(
                hookConfig.toBytes32()
            );
        }

        length = manifest.executionFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            bytes4 selector = manifest.executionFunctions[i].executionSelector;
            storageLayout.executionDetails[selector].module = address(0);
            storageLayout.executionDetails[selector].skipRuntimeValidation = false;
            storageLayout.executionDetails[selector].allowGlobalValidation = false;
        }

        length = manifest.interfaceIds.length;
        for (uint256 i = 0; i < length; ++i) {
            storageLayout.supportedInterfaces[manifest.interfaceIds[i]] -= 1;
        }
        // call the module’s onUninstall callback with the data provided in the uninstallData parameter;
        // This serves to clear the module state for the modular account;
        // If onUninstall reverts, execution SHOULD continue to allow the uninstall to complete
        return _onUninstall(module, moduleUninstallData);
    }

    function _installValidation(
        ValidationConfig validationConfig,
        bytes4[] calldata selectors,
        bytes calldata installData,
        bytes[] calldata hooks
    ) internal {
        ModuleEntity validationModuleEntity = validationConfig.moduleEntity();
        ValidationDetail storage validationDetail =
            WalletStorageLib.getLayout().validationDetails[validationModuleEntity];
        uint256 hooksLength = hooks.length;
        for (uint256 i = 0; i < hooksLength; ++i) {
            HookConfig hookConfig = HookConfig.wrap(bytes25(hooks[i][:25]));
            bytes calldata hookData = hooks[i][25:];
            if (hookConfig.isValidationHook()) {
                validationDetail.validationHooks.push(hookConfig);
                // Avoid collision between reserved index and actual indices
                if (validationDetail.validationHooks.length > MAX_VALIDATION_HOOKS) {
                    revert PreValidationHookLimitExceeded();
                }
                _onInstall(hookConfig.getModule(), hookData, type(IValidationHookModule).interfaceId);
            } else {
                validationDetail.executionHooks.append(hookConfig.toBytes32());
                _onInstall(hookConfig.getModule(), hookData, type(IExecutionHookModule).interfaceId);
            }
        }

        uint256 selectorsLength = selectors.length;
        for (uint256 i = 0; i < selectorsLength; ++i) {
            // revert internally
            validationDetail.selectors.append(selectors[i]);
        }

        validationDetail.isGlobal = validationConfig.isGlobal();
        validationDetail.isSignatureValidation = validationConfig.isSignatureValidation();
        validationDetail.isUserOpValidation = validationConfig.isUserOpValidation();
        // call onInstall to initialize module data for the modular account
        _onInstall(validationModuleEntity.module(), installData, type(IValidationModule).interfaceId);
    }

    function _uninstallValidation(
        ModuleEntity validationFunction,
        bytes calldata uninstallData,
        bytes[] calldata hookUninstallData
    ) internal returns (bool) {
        ValidationDetail storage validationDetail = WalletStorageLib.getLayout().validationDetails[validationFunction];
        validationDetail.isGlobal = false;
        validationDetail.isSignatureValidation = false;
        validationDetail.isUserOpValidation = false;

        bool onUninstallSucceeded = true;
        if (hookUninstallData.length > 0) {
            // verify the structure of uninstall data is provided correctly
            if (
                hookUninstallData.length
                    != validationDetail.validationHooks.length + validationDetail.executionHooks.size()
            ) {
                revert InvalidHookUninstallData();
            }
            // uninstall pre validation hooks
            uint256 uninstalled = 0;
            uint256 hooksLength = validationDetail.validationHooks.length;
            for (uint256 i = 0; i < hooksLength; ++i) {
                bytes calldata hookData = hookUninstallData[uninstalled];
                address hookModule = ModuleEntityLib.module(validationDetail.validationHooks[i].getModuleEntity());
                onUninstallSucceeded = onUninstallSucceeded && _onUninstall(hookModule, hookData);
                uninstalled++;
            }

            delete validationDetail.validationHooks;

            // uninstall execution hooks
            Bytes32DLL storage executionHooks = validationDetail.executionHooks;
            hooksLength = executionHooks.size();
            bytes32 startHook = SENTINEL_BYTES32;
            for (uint256 i = 0; i < hooksLength; ++i) {
                (bytes32[] memory hooksToRemove, bytes32 nextHook) = executionHooks.getPaginated(startHook, 10);
                for (uint256 j = 0; j < hooksToRemove.length; ++j) {
                    onUninstallSucceeded = onUninstallSucceeded
                        && _onUninstall(hooksToRemove[j].toHookConfig().getModule(), hookUninstallData[uninstalled]);
                    executionHooks.remove(hooksToRemove[j]);
                    uninstalled++;
                }
                if (nextHook == SENTINEL_BYTES32) {
                    break;
                }
                startHook = nextHook;
            }
        }

        Bytes4DLL storage selectors = validationDetail.selectors;
        uint256 selectorsLength = selectors.size();
        bytes4 startSelector = SENTINEL_BYTES4;
        for (uint256 i = 0; i < selectorsLength; ++i) {
            (bytes4[] memory selectorsToRemove, bytes4 nextSelector) = selectors.getPaginated(startSelector, 10);
            for (uint256 j = 0; j < selectorsToRemove.length; ++j) {
                selectors.remove(selectorsToRemove[j]);
            }
            if (nextSelector == SENTINEL_BYTES4) {
                break;
            }
            startSelector = nextSelector;
        }

        // call validation uninstall
        return onUninstallSucceeded && _onUninstall(validationFunction.module(), uninstallData);
    }

    function _onInstall(address module, bytes calldata data, bytes4 interfaceId) internal {
        if (data.length > 0) {
            if (!ERC165Checker.supportsInterface(module, interfaceId)) {
                revert InterfaceNotSupported(module, interfaceId);
            }
            // solhint-disable-next-line no-empty-blocks
            try IModule(module).onInstall(data) {}
            catch {
                bytes memory revertReason = ExecutionUtils.fetchReturnData();
                revert FailToCallOnInstall(module, revertReason);
            }
        }
    }

    // @dev return bool onUninstallSuccess.
    function _onUninstall(address module, bytes calldata data) internal returns (bool) {
        if (data.length > 0) {
            // solhint-disable-next-line no-empty-blocks
            try IModule(module).onUninstall(data) {}
            catch {
                return false;
            }
        }
        return true;
    }

    function _checkAccessRuleFromEPOrAcctItself() internal view {
        if (msg.sender != address(ENTRY_POINT) && msg.sender != address(this)) {
            revert UnauthorizedCaller();
        }
    }

    // @notice If a call is from entry point, account itself, or skips runtime validation, it's already accessing
    // account storage.
    // For other calls (e.g. from modules), we need directCallValidation to protect the account storage. This is
    // done by running the associated preRuntimeValidationHooks and preExecutionHooks.
    // For both scenarios, we run preExecutionHooks associated with the selector (msg.sig).
    function _checkCallPermission(WalletStorageLib.Layout storage walletStorage)
        internal
        returns (
            PostExecHookToRun[] memory postExecHooksFromDirectCallValidation,
            PostExecHookToRun[] memory postExecHooksFromExecutionSelector
        )
    {
        ExecutionDetail storage executionDetail = WalletStorageLib.getLayout().executionDetails[msg.sig];
        if (msg.sender == address(ENTRY_POINT) || msg.sender == address(this) || executionDetail.skipRuntimeValidation)
        {
            // no directCallValidation associated pre hooks
            postExecHooksFromDirectCallValidation = new PostExecHookToRun[](0);
        } else {
            ModuleEntity directCallValidation = ModuleEntityLib.pack(msg.sender, DIRECT_CALL_VALIDATION_ENTITY_ID);
            // check directCallValidation
            if (
                !_checkValidationForCalldata(
                    walletStorage, msg.data, directCallValidation, ValidationCheckingType.EITHER
                )
            ) {
                revert ValidationFunctionMissing(msg.sig, directCallValidation);
            }
            // if direct call is allowed, run associated validationHooks
            ValidationDetail storage validationDetail = walletStorage.validationDetails[directCallValidation];
            HookConfig[] memory validationHooks = validationDetail.validationHooks;
            uint256 length = validationHooks.length;
            for (uint256 i = 0; i < length; ++i) {
                (address module, uint32 entityId) = validationHooks[i].unpackValidationHook().unpack();
                // solhint-disable-next-line no-empty-blocks
                try IValidationHookModule(module).preRuntimeValidationHook(
                    entityId, msg.sender, msg.value, msg.data, ""
                ) {} catch {
                    bytes memory revertReason = ExecutionUtils.fetchReturnData();
                    revert PreRuntimeValidationHookFailed(module, entityId, revertReason);
                }
            }
            // if direct call is allowed, run associated preExecutionHooks
            postExecHooksFromDirectCallValidation = validationDetail.executionHooks._processPreExecHooks(msg.data);
        }
        // run preExecutionHooks for the selector (msg.sig)
        postExecHooksFromExecutionSelector = executionDetail.executionHooks._processPreExecHooks(msg.data);
        return (postExecHooksFromDirectCallValidation, postExecHooksFromExecutionSelector);
    }

    /// @dev Check if the validation function is enabled for the calldata.
    /// @notice Self-call rule: if the function selector is execute, we don't allow self call because the inner call may
    /// instead be pulled up to the top-level call,
    ///                         if the function selector is executeBatch, then we inspect the selector in each Call
    /// where the target is the account itself,
    ///                             * the validation currently being used must apply to inner call selector
    ///                             * the inner call selector must not recursively call into the account's execute or
    /// executeBatch functions
    function _checkValidationForCalldata(
        WalletStorageLib.Layout storage walletStorage,
        bytes calldata callData,
        ModuleEntity validationFunction,
        ValidationCheckingType validationCheckingType
    ) internal view returns (bool) {
        if (ModuleEntity.unwrap(validationFunction) == EMPTY_MODULE_ENTITY) {
            revert InvalidModuleEntity(validationFunction);
        }
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
        if (!_checkValidationForSelector(walletStorage, outerSelector, validationFunction, validationCheckingType)) {
            return false;
        }
        // executeBatch may be used to batch calls into the account itself, but not for execute
        if (outerSelector == IModularAccount.execute.selector) {
            (address target,,) = abi.decode(callData[4:], (address, uint256, bytes));
            if (target == address(this)) {
                revert SelfCallRecursionDepthExceeded();
            }
        } else if (outerSelector == IModularAccount.executeBatch.selector) {
            (Call[] memory calls) = abi.decode(callData[4:], (Call[]));
            for (uint256 i = 0; i < calls.length; ++i) {
                // to prevent arbitrarily-deep recursive checking, all self-calls must occur at the top level of the
                // batch
                if (calls[i].target == address(this)) {
                    bytes4 innerSelector = bytes4(calls[i].data);
                    if (
                        innerSelector == IModularAccount.execute.selector
                            || innerSelector == IModularAccount.executeBatch.selector
                    ) {
                        revert SelfCallRecursionDepthExceeded();
                    }
                    // check all of the inner calls are allowed by the validation function
                    if (
                        !_checkValidationForSelector(
                            walletStorage, innerSelector, validationFunction, validationCheckingType
                        )
                    ) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    /// @dev Check if the validation function is enabled for the selector, either global or per selector.
    function _checkValidationForSelector(
        WalletStorageLib.Layout storage walletStorage,
        bytes4 selector,
        ModuleEntity validationFunction,
        ValidationCheckingType validationCheckingType
    ) internal view returns (bool) {
        if (validationCheckingType == ValidationCheckingType.GLOBAL) {
            if (_isAllowedForGlobalValidation(walletStorage, selector, validationFunction)) {
                return true;
            }
        } else if (validationCheckingType == ValidationCheckingType.SELECTOR) {
            if (_isAllowedForSelectorValidation(walletStorage, selector, validationFunction)) {
                return true;
            }
        } else if (validationCheckingType == ValidationCheckingType.EITHER) {
            if (
                _isAllowedForGlobalValidation(walletStorage, selector, validationFunction)
                    || _isAllowedForSelectorValidation(walletStorage, selector, validationFunction)
            ) {
                return true;
            }
        }
        return false;
    }

    function _isAllowedForGlobalValidation(
        WalletStorageLib.Layout storage walletStorage,
        bytes4 selector,
        ModuleEntity validationFunction
    ) internal view returns (bool) {
        // 1. the function selector need to be enabled for global validation
        // 2. the global validation has been registered
        return (selector._isNativeExecutionFunction() || walletStorage.executionDetails[selector].allowGlobalValidation)
            && walletStorage.validationDetails[validationFunction].isGlobal;
    }

    function _isAllowedForSelectorValidation(
        WalletStorageLib.Layout storage walletStorage,
        bytes4 selector,
        ModuleEntity validationFunction
    ) internal view returns (bool) {
        return walletStorage.validationDetails[validationFunction].selectors.contains(selector);
    }
}
