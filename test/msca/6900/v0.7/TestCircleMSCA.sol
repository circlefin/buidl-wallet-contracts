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

import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {StorageSlot} from "@openzeppelin/contracts/utils/StorageSlot.sol";
import {UpgradableMSCA} from "../../../../src/msca/6900/v0.7/account/UpgradableMSCA.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {WalletStorageV1Lib} from "../../../../src/msca/6900/v0.7/libs/WalletStorageV1Lib.sol";
import {AddressDLLLib} from "../../../../src/msca/6900/shared/libs/AddressDLLLib.sol";
import {FunctionReferenceDLLLib} from "../../../../src/msca/6900/v0.7/libs/FunctionReferenceDLLLib.sol";
import {RepeatableFunctionReferenceDLLLib} from
    "../../../../src/msca/6900/v0.7/libs/RepeatableFunctionReferenceDLLLib.sol";
import {FunctionReferenceLib} from "../../../../src/msca/6900/v0.7/libs/FunctionReferenceLib.sol";
import {AddressDLL} from "../../../../src/msca/6900/shared/common/Structs.sol";
import {
    Bytes21DLL,
    RepeatableBytes21DLL,
    FunctionReference,
    ExecutionHooks,
    ExecutionFunctionConfig,
    ExecutionDetail,
    PluginDetail,
    PermittedExternalCall
} from "../../../../src/msca/6900/v0.7/common/Structs.sol";
import {PluginManager} from "../../../../src/msca/6900/v0.7/managers/PluginManager.sol";

// testing contract with some convenience methods
contract TestCircleMSCA is UpgradableMSCA {
    using WalletStorageV1Lib for WalletStorageV1Lib.Layout;
    using AddressDLLLib for AddressDLL;
    using FunctionReferenceDLLLib for Bytes21DLL;
    using RepeatableFunctionReferenceDLLLib for RepeatableBytes21DLL;
    using FunctionReferenceLib for bytes21;
    using FunctionReferenceLib for FunctionReference;

    // just for testing
    struct ExecutionDetailWrapper {
        address plugin; // plugin address that implements the execution function, for native functions, the value is set
            // to address(0)
        FunctionReference userOpValidationFunction;
        FunctionReference[] preUserOpValidationHooks;
        FunctionReference runtimeValidationFunction;
        FunctionReference[] preRuntimeValidationHooks;
        ExecutionHooks[] executionHooks;
    }

    struct PluginDetailWrapper {
        // permitted to call any external contracts and selectors
        bool anyExternalAddressPermitted;
        bool canSpendNativeToken;
        // tracks the count this plugin has been used as a dependency function
        uint256 dependentCounter;
        bytes32 manifestHash;
        FunctionReference[] dependencies;
    }

    constructor(IEntryPoint _newEntryPoint, PluginManager _newPluginManager)
        UpgradableMSCA(_newEntryPoint, _newPluginManager)
    {}

    function initExecutionDetail(bytes4 selector, ExecutionFunctionConfig memory executionFunctionConfig) external {
        ExecutionDetail storage executionDetail = WalletStorageV1Lib.getLayout().executionDetails[selector];
        executionDetail.plugin = executionFunctionConfig.plugin;
        executionDetail.userOpValidationFunction = executionFunctionConfig.userOpValidationFunction;
        executionDetail.runtimeValidationFunction = executionFunctionConfig.runtimeValidationFunction;
    }

    function setPreUserOpValidationHook(bytes4 selector, FunctionReference memory preUserOpValidationHook) external {
        ExecutionDetail storage executionDetail = WalletStorageV1Lib.getLayout().executionDetails[selector];
        executionDetail.preUserOpValidationHooks.append(preUserOpValidationHook);
    }

    function addPlugin(address pluginToAdd) external returns (bool) {
        return WalletStorageV1Lib.getLayout().installedPlugins.append(pluginToAdd);
    }

    function removePlugin(address pluginToRemove) external returns (bool) {
        return WalletStorageV1Lib.getLayout().installedPlugins.remove(pluginToRemove);
    }

    function containsPlugin(address plugin) external view returns (bool) {
        return WalletStorageV1Lib.getLayout().installedPlugins.contains(plugin);
    }

    function sizeOfPlugins() external view returns (uint256) {
        return WalletStorageV1Lib.getLayout().installedPlugins.size();
    }

    function getPluginsPaginated(address start, uint256 limit) external view returns (address[] memory, address) {
        return WalletStorageV1Lib.getLayout().installedPlugins.getPaginated(start, limit);
    }

    function getFirstPlugin() external view returns (address) {
        return WalletStorageV1Lib.getLayout().installedPlugins.getHead();
    }

    function getLastPlugin() external view returns (address) {
        return WalletStorageV1Lib.getLayout().installedPlugins.getTail();
    }

    function addPreUserOpValidationHook(bytes4 selector, FunctionReference memory hookToAdd)
        external
        returns (uint256)
    {
        return WalletStorageV1Lib.getLayout().executionDetails[selector].preUserOpValidationHooks.append(hookToAdd);
    }

    function removePreUserOpValidationHook(bytes4 selector, FunctionReference memory hookToRemove)
        external
        returns (uint256)
    {
        return WalletStorageV1Lib.getLayout().executionDetails[selector].preUserOpValidationHooks.remove(hookToRemove);
    }

    function containsPreUserOpValidationHook(bytes4 selector, FunctionReference memory hook)
        external
        view
        returns (uint256)
    {
        return WalletStorageV1Lib.getLayout().executionDetails[selector].preUserOpValidationHooks.getRepeatedCount(hook);
    }

    function sizeOfPreUserOpValidationHooks(bytes4 selector) external view returns (uint256) {
        return WalletStorageV1Lib.getLayout().executionDetails[selector].preUserOpValidationHooks.getUniqueItems();
    }

    function getPreUserOpValidationHooksPaginated(bytes4 selector, FunctionReference memory start, uint256 limit)
        external
        view
        returns (FunctionReference[] memory, FunctionReference memory)
    {
        return WalletStorageV1Lib.getLayout().executionDetails[selector].preUserOpValidationHooks.getPaginated(
            start, limit
        );
    }

    function getFirstPreUserOpValidationHook(bytes4 selector) external view returns (FunctionReference memory) {
        return WalletStorageV1Lib.getLayout().executionDetails[selector].preUserOpValidationHooks.getHead();
    }

    function getLastPreUserOpValidationHook(bytes4 selector) external view returns (FunctionReference memory) {
        return WalletStorageV1Lib.getLayout().executionDetails[selector].preUserOpValidationHooks.getTail();
    }

    function setImplementation(address newImplementation) external {
        StorageSlot.getAddressSlot(ERC1967Utils.IMPLEMENTATION_SLOT).value = newImplementation;
    }

    function getPluginDetail(address plugin) external view returns (PluginDetailWrapper memory pluginDetailWrapper) {
        PluginDetail storage pluginDetail = WalletStorageV1Lib.getLayout().pluginDetails[plugin];
        pluginDetailWrapper.anyExternalAddressPermitted = pluginDetail.anyExternalAddressPermitted;
        pluginDetailWrapper.canSpendNativeToken = pluginDetail.canSpendNativeToken;
        pluginDetailWrapper.dependentCounter = pluginDetail.dependentCounter;
        pluginDetailWrapper.manifestHash = pluginDetail.manifestHash;
        pluginDetailWrapper.dependencies = pluginDetail.dependencies.getAll();
    }

    function getExecutionDetail(bytes4 selector)
        external
        view
        returns (ExecutionDetailWrapper memory executionDetailWrapper)
    {
        // getExecutionFunctionConfig - plugin, userOpValidationFunction and runtimeValidationFunction
        ExecutionFunctionConfig memory executionFunctionConfig = this.getExecutionFunctionConfig(selector);
        executionDetailWrapper.plugin = executionFunctionConfig.plugin;
        executionDetailWrapper.userOpValidationFunction = executionFunctionConfig.userOpValidationFunction;
        executionDetailWrapper.runtimeValidationFunction = executionFunctionConfig.runtimeValidationFunction;
        // getPreUserOpValidationHooks & getPreRuntimeValidationHooks
        (executionDetailWrapper.preUserOpValidationHooks, executionDetailWrapper.preRuntimeValidationHooks) =
            this.getPreValidationHooks(selector);
        // getExecutionHooks - ExecutionHooks(preExecHook, postExecHook)
        executionDetailWrapper.executionHooks = this.getExecutionHooks(selector);
        return executionDetailWrapper;
    }

    function getPermittedPluginCallSelectorPermitted(address callingPlugin, bytes4 selector)
        external
        view
        returns (bool selectorPermitted)
    {
        return WalletStorageV1Lib.getLayout().permittedPluginCalls[callingPlugin][selector];
    }

    // permission to call external contracts
    function getPermittedExternalCall(address callingPlugin, address targetContract, bytes4 callingSelector)
        external
        view
        returns (bool isPermitted)
    {
        if (WalletStorageV1Lib.getLayout().pluginDetails[callingPlugin].anyExternalAddressPermitted) {
            return true;
        }
        PermittedExternalCall storage permittedExternalCall =
            WalletStorageV1Lib.getLayout().permittedExternalCalls[callingPlugin][targetContract];
        // when plugin is uninstalled
        if (!permittedExternalCall.addressPermitted) {
            return false;
        }
        if (permittedExternalCall.anySelector) {
            return true;
        }
        return permittedExternalCall.selectors[callingSelector];
    }

    function getSupportedInterface(bytes4 selector) external view returns (uint256 interfaceId) {
        return WalletStorageV1Lib.getLayout().supportedInterfaces[selector];
    }
}
