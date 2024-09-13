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
    EMPTY_FUNCTION_REFERENCE,
    SENTINEL_BYTES21,
    WALLET_AUTHOR,
    WALLET_VERSION_1
} from "../../../../common/Constants.sol";
import {ExecutionUtils} from "../../../../utils/ExecutionUtils.sol";
import {
    InvalidAuthorizer,
    InvalidExecutionFunction,
    InvalidValidationFunctionId,
    NotFoundSelector,
    UnauthorizedCaller
} from "../../shared/common/Errors.sol";
import {AddressDLL, ValidationData} from "../../shared/common/Structs.sol";
import {AddressDLLLib} from "../../shared/libs/AddressDLLLib.sol";
import {ValidationDataLib} from "../../shared/libs/ValidationDataLib.sol";
import {
    PRE_HOOK_ALWAYS_DENY_FUNCTION_REFERENCE,
    RUNTIME_VALIDATION_ALWAYS_ALLOW_FUNCTION_REFERENCE
} from "../common/Constants.sol";
import "../common/Structs.sol";
import {IAccountLoupe} from "../interfaces/IAccountLoupe.sol";
import {IPlugin} from "../interfaces/IPlugin.sol";
import {IPluginExecutor} from "../interfaces/IPluginExecutor.sol";
import {IPluginManager} from "../interfaces/IPluginManager.sol";
import {IStandardExecutor} from "../interfaces/IStandardExecutor.sol";
import {ExecutionHookLib} from "../libs/ExecutionHookLib.sol";
import {FunctionReferenceLib} from "../libs/FunctionReferenceLib.sol";
import {RepeatableFunctionReferenceDLLLib} from "../libs/RepeatableFunctionReferenceDLLLib.sol";

import {SelectorRegistryLib} from "../libs/SelectorRegistryLib.sol";
import {WalletStorageV1Lib} from "../libs/WalletStorageV1Lib.sol";
import {PluginExecutor} from "../managers/PluginExecutor.sol";
import {PluginManager} from "../managers/PluginManager.sol";
import {StandardExecutor} from "../managers/StandardExecutor.sol";

import {WalletStorageInitializable} from "./WalletStorageInitializable.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
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
    IPluginExecutor,
    IERC165
{
    using RepeatableFunctionReferenceDLLLib for RepeatableBytes21DLL;
    using FunctionReferenceLib for bytes21;
    using FunctionReferenceLib for FunctionReference;
    using ExecutionHookLib for HookGroup;
    using ExecutionHookLib for PostExecHookToRun[];
    using ExecutionUtils for address;
    using PluginExecutor for bytes;
    using StandardExecutor for address;
    using StandardExecutor for Call[];
    using AddressDLLLib for AddressDLL;
    using ValidationDataLib for ValidationData;
    using SelectorRegistryLib for bytes4;

    string public constant author = WALLET_AUTHOR;
    string public constant version = WALLET_VERSION_1;
    // 4337 related immutable storage
    IEntryPoint public immutable entryPoint;
    PluginManager public immutable pluginManager;

    error NotNativeFunctionSelector(bytes4 selector);
    error InvalidHookFunctionId(uint8 functionId);
    error PreRuntimeValidationHookFailed(address plugin, uint8 functionId, bytes revertReason);
    error RuntimeValidationFailed(address plugin, uint8 functionId, bytes revertReason);

    /**
     * @dev Wraps execution of a native function (as opposed to a function added by plugins) with runtime validations
     * (not from EP)
     *      and hooks. Used by execute, executeBatch, installPlugin, uninstallPlugin, upgradeTo and upgradeToAndCall.
     *      If the call is from entry point, then validateUserOp will run.
     *      https://eips.ethereum.org/assets/eip-6900/Modular_Account_Call_Flow.svg
     */
    modifier validateNativeFunction() {
        PostExecHookToRun[] memory postExecHooks = _processPreExecHooks();
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
        entryPoint = _newEntryPoint;
        pluginManager = _newPluginManager;
        // lock the implementation contract so it can only be called from proxies
        _disableWalletStorageInitializers();
    }

    receive() external payable {}

    /// @notice Manage fallback calls made to the plugins.
    /// @dev Route calls to execution functions based on incoming msg.sig
    ///      If there's no plugin associated with this function selector, revert
    fallback(bytes calldata) external payable returns (bytes memory result) {
        // run runtime validation before we load the executionDetail because validation may update account state
        if (msg.sender != address(entryPoint)) {
            // entryPoint should go through validateUserOp flow which calls userOpValidationFunction
            _processPreRuntimeHooksAndValidation(msg.sig);
        }
        // load the executionDetail before we run the preExecHooks because they may modify the plugins
        ExecutionDetail storage executionDetail = WalletStorageV1Lib.getLayout().executionDetails[msg.sig];
        address executionFunctionPlugin = executionDetail.plugin;
        // valid plugin address should not be 0
        if (executionFunctionPlugin == address(0)) {
            revert InvalidExecutionFunction(msg.sig);
        }
        PostExecHookToRun[] memory postExecHooks = executionDetail.executionHooks._processPreExecHooks(msg.data);
        result = ExecutionUtils.callWithReturnDataOrRevert(executionFunctionPlugin, msg.value, msg.data);
        postExecHooks._processPostExecHooks();
        return result;
    }

    /**
     * @dev Return the entryPoint used by this account.
     * subclass should return the current entryPoint used by this account.
     */
    function getEntryPoint() external view returns (IEntryPoint) {
        return entryPoint;
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
        if (msg.sender != address(entryPoint)) {
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
        return WalletStorageV1Lib.getLayout().supportedInterfaces[interfaceId] > 0;
    }

    /**
     * @dev Return the account nonce.
     * This method returns the next sequential nonce.
     * For a nonce of a specific key, use `entrypoint.getNonce(account, key)`
     */
    function getNonce() public view virtual returns (uint256) {
        return entryPoint.getNonce(address(this), 0);
    }

    function installPlugin(
        address plugin,
        bytes32 manifestHash,
        bytes memory pluginInstallData,
        FunctionReference[] memory dependencies
    ) external override validateNativeFunction {
        bytes memory data = abi.encodeCall(
            PluginManager.install, (plugin, manifestHash, pluginInstallData, dependencies, address(this))
        );
        address(pluginManager).delegateCall(data);
        emit PluginInstalled(plugin, manifestHash, dependencies);
    }

    function uninstallPlugin(address plugin, bytes memory config, bytes memory pluginUninstallData)
        external
        override
        validateNativeFunction
    {
        bytes memory data = abi.encodeCall(PluginManager.uninstall, (plugin, config, pluginUninstallData));
        address(pluginManager).delegateCall(data);
        emit PluginUninstalled(plugin, true);
    }

    function execute(address target, uint256 value, bytes calldata data)
        external
        payable
        override
        validateNativeFunction
        returns (bytes memory returnData)
    {
        return target.execute(value, data);
    }

    function executeBatch(Call[] calldata calls)
        external
        payable
        override
        validateNativeFunction
        returns (bytes[] memory returnData)
    {
        return calls.executeBatch();
    }

    function executeFromPlugin(bytes calldata data) external payable override returns (bytes memory) {
        return data.executeFromPlugin();
    }

    function executeFromPluginExternal(address target, uint256 value, bytes calldata data)
        external
        payable
        override
        returns (bytes memory)
    {
        return data.executeFromPluginToExternal(target, value);
    }

    /// @notice Gets the validation functions and plugin address for a selector
    /// @dev If the selector is a native function, the plugin address will be the address of the account
    /// @param selector The selector to get the configuration for
    /// @return executionFunctionConfig The configuration for this selector
    function getExecutionFunctionConfig(bytes4 selector)
        external
        view
        returns (ExecutionFunctionConfig memory executionFunctionConfig)
    {
        WalletStorageV1Lib.Layout storage walletStorage = WalletStorageV1Lib.getLayout();
        if (selector._isNativeFunctionSelector()) {
            executionFunctionConfig.plugin = address(this);
        } else {
            executionFunctionConfig.plugin = walletStorage.executionDetails[selector].plugin;
        }
        executionFunctionConfig.userOpValidationFunction =
            walletStorage.executionDetails[selector].userOpValidationFunction;
        executionFunctionConfig.runtimeValidationFunction =
            walletStorage.executionDetails[selector].runtimeValidationFunction;
        return executionFunctionConfig;
    }

    /// @notice Gets the pre and post execution hooks for a selector
    /// @param selector The selector to get the hooks for
    /// @return executionHooks The pre and post execution hooks for this selector
    function getExecutionHooks(bytes4 selector) external view returns (ExecutionHooks[] memory executionHooks) {
        return WalletStorageV1Lib.getLayout().executionDetails[selector].executionHooks._getExecutionHooks();
    }

    /// @notice Gets the pre user op and runtime validation hooks associated with a selector
    /// @param selector The selector to get the hooks for
    /// @return preUserOpValidationHooks The pre user op validation hooks for this selector
    /// @return preRuntimeValidationHooks The pre runtime validation hooks for this selector
    function getPreValidationHooks(bytes4 selector)
        external
        view
        returns (
            FunctionReference[] memory preUserOpValidationHooks,
            FunctionReference[] memory preRuntimeValidationHooks
        )
    {
        preUserOpValidationHooks =
            WalletStorageV1Lib.getLayout().executionDetails[selector].preUserOpValidationHooks.getAll();
        preRuntimeValidationHooks =
            WalletStorageV1Lib.getLayout().executionDetails[selector].preRuntimeValidationHooks.getAll();
        return (preUserOpValidationHooks, preRuntimeValidationHooks);
    }

    /// @notice Gets an array of all installed plugins
    /// @return pluginAddresses The addresses of all installed plugins
    function getInstalledPlugins() external view returns (address[] memory pluginAddresses) {
        return WalletStorageV1Lib.getLayout().installedPlugins.getAll();
    }

    /**
     * Check current account deposit in the entryPoint.
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint.balanceOf(address(this));
    }

    /**
     * Deposit more funds for this account in the entryPoint.
     */
    function addDeposit() public payable {
        entryPoint.depositTo{value: msg.value}(address(this));
    }

    /**
     * Withdraw value from the account's deposit.
     * @param withdrawAddress target to send to
     * @param amount to withdraw
     */
    function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public onlyFromEntryPointOrSelf {
        entryPoint.withdrawTo(withdrawAddress, amount);
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
            revert NotFoundSelector();
        }
        bytes4 selector = bytes4(userOp.callData[0:4]);
        if (selector == bytes4(0)) {
            revert NotFoundSelector();
        }
        ExecutionDetail storage executionDetail = WalletStorageV1Lib.getLayout().executionDetails[selector];
        FunctionReference memory validationFunction = executionDetail.userOpValidationFunction;
        bytes21 packedValidationFunction = validationFunction.pack();
        if (
            packedValidationFunction == EMPTY_FUNCTION_REFERENCE
                || packedValidationFunction == RUNTIME_VALIDATION_ALWAYS_ALLOW_FUNCTION_REFERENCE
                || packedValidationFunction == PRE_HOOK_ALWAYS_DENY_FUNCTION_REFERENCE
        ) {
            revert InvalidValidationFunctionId(validationFunction.functionId);
        }
        // pre hook
        ValidationData memory unpackedValidationData =
            _processPreUserOpValidationHooks(executionDetail, userOp, userOpHash);
        IPlugin userOpValidatorPlugin = IPlugin(validationFunction.plugin);
        // execute the validation function with the user operation and its hash as parameters using the call opcode
        uint256 currentValidationData = userOpValidatorPlugin.userOpValidationFunction(
            executionDetail.userOpValidationFunction.functionId, userOp, userOpHash
        );
        // intercept with validation function call
        unpackedValidationData = unpackedValidationData._intersectValidationData(currentValidationData);
        if (unpackedValidationData.authorizer != address(0) && unpackedValidationData.authorizer != address(1)) {
            // only revert on unexpected values
            revert InvalidAuthorizer();
        }
        validationData = unpackedValidationData._packValidationData();
    }

    /**
     * @dev Default validation logic is from installed plugins. However, you can override this validation logic in MSCA
     *      implementations. For instance, semi MSCA such as single owner semi MSCA may want to honor the validation
     *      from native owner.
     */
    function _processPreRuntimeHooksAndValidation(bytes4 selector) internal virtual {
        FunctionReference memory validationFunction =
            WalletStorageV1Lib.getLayout().executionDetails[selector].runtimeValidationFunction;
        bytes21 packedValidationFunction = validationFunction.pack();
        if (
            packedValidationFunction == EMPTY_FUNCTION_REFERENCE
                || packedValidationFunction == PRE_HOOK_ALWAYS_DENY_FUNCTION_REFERENCE
        ) {
            revert InvalidValidationFunctionId(validationFunction.functionId);
        }
        RepeatableBytes21DLL storage preRuntimeValidationHooksDLL =
            WalletStorageV1Lib.getLayout().executionDetails[selector].preRuntimeValidationHooks;
        uint256 totalUniqueHookCount = preRuntimeValidationHooksDLL.getUniqueItems();
        FunctionReference memory startHook = EMPTY_FUNCTION_REFERENCE.unpack();
        FunctionReference[] memory preRuntimeValidationHooks;
        FunctionReference memory nextHook;
        for (uint256 i = 0; i < totalUniqueHookCount; ++i) {
            (preRuntimeValidationHooks, nextHook) = preRuntimeValidationHooksDLL.getPaginated(startHook, 10);
            for (uint256 j = 0; j < preRuntimeValidationHooks.length; ++j) {
                // revert on EMPTY_FUNCTION_REFERENCE, RUNTIME_VALIDATION_ALWAYS_ALLOW_FUNCTION_REFERENCE,
                // PRE_HOOK_ALWAYS_DENY_FUNCTION_REFERENCE
                // if any revert, the outer call MUST revert
                bytes21 packedPreRuntimeValidationHook = preRuntimeValidationHooks[j].pack();
                if (
                    packedPreRuntimeValidationHook == EMPTY_FUNCTION_REFERENCE
                        || packedPreRuntimeValidationHook == RUNTIME_VALIDATION_ALWAYS_ALLOW_FUNCTION_REFERENCE
                        || packedPreRuntimeValidationHook == PRE_HOOK_ALWAYS_DENY_FUNCTION_REFERENCE
                ) {
                    revert InvalidValidationFunctionId(preRuntimeValidationHooks[j].functionId);
                }
                IPlugin preRuntimeValidationHookPlugin = IPlugin(preRuntimeValidationHooks[j].plugin);
                try preRuntimeValidationHookPlugin.preRuntimeValidationHook(
                    preRuntimeValidationHooks[j].functionId, msg.sender, msg.value, msg.data
                ) {} catch (bytes memory revertReason) {
                    revert PreRuntimeValidationHookFailed(
                        preRuntimeValidationHooks[j].plugin, preRuntimeValidationHooks[j].functionId, revertReason
                    );
                }
            }
            if (nextHook.pack() == SENTINEL_BYTES21) {
                break;
            }
            startHook = nextHook;
        }
        // call runtimeValidationFunction if it's not always allowed
        if (packedValidationFunction != RUNTIME_VALIDATION_ALWAYS_ALLOW_FUNCTION_REFERENCE) {
            try IPlugin(validationFunction.plugin).runtimeValidationFunction(
                validationFunction.functionId, msg.sender, msg.value, msg.data
            ) {} catch (bytes memory revertReason) {
                revert RuntimeValidationFailed(validationFunction.plugin, validationFunction.functionId, revertReason);
            }
        }
    }

    /// @dev Also runs runtime hooks and validation if msg.sender is not from entry point.
    function _processPreExecHooks() internal returns (PostExecHookToRun[] memory) {
        if (!msg.sig._isNativeFunctionSelector()) {
            revert NotNativeFunctionSelector(msg.sig);
        }
        if (msg.sender != address(entryPoint)) {
            // entryPoint should go through validateUserOp flow which calls userOpValidationFunction
            _processPreRuntimeHooksAndValidation(msg.sig);
        }
        return WalletStorageV1Lib.getLayout().executionDetails[msg.sig].executionHooks._processPreExecHooks(msg.data);
    }

    function _processPreUserOpValidationHooks(
        ExecutionDetail storage executionDetail,
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal virtual returns (ValidationData memory unpackedValidationData) {
        unpackedValidationData = ValidationData(0, 0xFFFFFFFFFFFF, address(0));
        // if the function selector has associated pre user operation validation hooks, then those hooks MUST be run
        // sequentially
        uint256 totalUniqueHookCount = executionDetail.preUserOpValidationHooks.getUniqueItems();
        FunctionReference memory startHook = EMPTY_FUNCTION_REFERENCE.unpack();
        FunctionReference[] memory preUserOpValidatorHooks;
        FunctionReference memory nextHook;
        uint256 currentValidationData;
        for (uint256 i = 0; i < totalUniqueHookCount; ++i) {
            (preUserOpValidatorHooks, nextHook) = executionDetail.preUserOpValidationHooks.getPaginated(startHook, 10);
            for (uint256 j = 0; j < preUserOpValidatorHooks.length; ++j) {
                bytes21 packedUserOpValidatorHook = preUserOpValidatorHooks[j].pack();
                // if any revert, the outer call MUST revert
                if (
                    packedUserOpValidatorHook == EMPTY_FUNCTION_REFERENCE
                        || packedUserOpValidatorHook == RUNTIME_VALIDATION_ALWAYS_ALLOW_FUNCTION_REFERENCE
                        || packedUserOpValidatorHook == PRE_HOOK_ALWAYS_DENY_FUNCTION_REFERENCE
                ) {
                    revert InvalidHookFunctionId(preUserOpValidatorHooks[j].functionId);
                }
                IPlugin preUserOpValidationHookPlugin = IPlugin(preUserOpValidatorHooks[j].plugin);
                currentValidationData = preUserOpValidationHookPlugin.preUserOpValidationHook(
                    preUserOpValidatorHooks[j].functionId, userOp, userOpHash
                );
                unpackedValidationData = unpackedValidationData._intersectValidationData(currentValidationData);
                // if any return an authorizer value other than 0 or 1, execution MUST revert
                if (unpackedValidationData.authorizer != address(0) && unpackedValidationData.authorizer != address(1))
                {
                    revert InvalidAuthorizer();
                }
            }
            if (nextHook.pack() == SENTINEL_BYTES21) {
                break;
            }
            startHook = nextHook;
        }
        return unpackedValidationData;
    }

    function _checkAccessRuleFromEPOrAcctItself() internal view {
        if (msg.sender != address(entryPoint) && msg.sender != address(this)) {
            revert UnauthorizedCaller();
        }
    }
}
