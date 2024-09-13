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
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {WalletStorageLib} from "../../../../src/msca/6900/v0.8/libs/WalletStorageLib.sol";
import {AddressDLLLib} from "../../../../src/msca/6900/shared/libs/AddressDLLLib.sol";
import {Bytes32DLLLib} from "../../../../src/msca/6900/shared/libs/Bytes32DLLLib.sol";
import {ModuleEntityLib} from "../../../../src/msca/6900/v0.8/libs/thirdparty/ModuleEntityLib.sol";
import {UpgradableMSCA} from "../../../../src/msca/6900/v0.8/account/UpgradableMSCA.sol";
import {PluginManager} from "../../../../src/msca/6900/v0.8/managers/PluginManager.sol";
import {Bytes32DLL, ExecutionHook, ExecutionDetail} from "../../../../src/msca/6900/v0.8/common/Structs.sol";
import {AddressDLL, Bytes4DLL, Bytes32DLL} from "../../../../src/msca/6900/shared/common/Structs.sol";
import {Bytes4DLLLib} from "../../../../src/msca/6900/shared/libs/Bytes4DLLLib.sol";
import {ModuleEntity} from "../../../../src/msca/6900/v0.8/common/Types.sol";

// testing contract with some convenience methods
contract TestCircleMSCA is UpgradableMSCA {
    using WalletStorageLib for WalletStorageLib.Layout;
    using AddressDLLLib for AddressDLL;
    using Bytes32DLLLib for Bytes32DLL;
    using ModuleEntityLib for ModuleEntity;
    using Bytes4DLLLib for Bytes4DLL;

    // just for testing
    struct ExecutionDetailWrapper {
        address plugin; // plugin address that implements the execution function, for native functions, the value is set
            // to address(0)
        ExecutionHook[] executionHooks;
        bool skipRuntimeValidation;
        // Whether or not a global validation function may be used to validate this function.
        bool allowGlobalValidation;
    }

    // solhint-disable-next-line func-visibility
    constructor(IEntryPoint _newEntryPoint, PluginManager _newPluginManager)
        UpgradableMSCA(_newEntryPoint, _newPluginManager)
    {}

    function associateSelectorToValidation(bytes4 selector, address plugin, ModuleEntity validationFunction) external {
        ExecutionDetail storage executionDetail = WalletStorageLib.getLayout().executionDetails[selector];
        executionDetail.plugin = plugin;
        WalletStorageLib.getLayout().validationDetails[validationFunction].selectors.append(selector);
    }

    function setPreValidationHook(ModuleEntity validationFunction, ModuleEntity preValidationHook) external {
        WalletStorageLib.getLayout().validationDetails[validationFunction].preValidationHooks.push(preValidationHook);
    }

    function setSkipRuntimeValidation(bytes4 selector, bool skipRuntimeValidation) external {
        ExecutionDetail storage executionDetail = WalletStorageLib.getLayout().executionDetails[selector];
        executionDetail.skipRuntimeValidation = skipRuntimeValidation;
    }

    function addPlugin(address pluginToAdd) external returns (bool) {
        return WalletStorageLib.getLayout().installedPlugins.append(pluginToAdd);
    }

    function removePlugin(address pluginToRemove) external returns (bool) {
        return WalletStorageLib.getLayout().installedPlugins.remove(pluginToRemove);
    }

    function containsPlugin(address plugin) external view returns (bool) {
        return WalletStorageLib.getLayout().installedPlugins.contains(plugin);
    }

    function sizeOfPlugins() external view returns (uint256) {
        return WalletStorageLib.getLayout().installedPlugins.size();
    }

    function getPluginsPaginated(address start, uint256 limit) external view returns (address[] memory, address) {
        return WalletStorageLib.getLayout().installedPlugins.getPaginated(start, limit);
    }

    function getFirstPlugin() external view returns (address) {
        return WalletStorageLib.getLayout().installedPlugins.getHead();
    }

    function getLastPlugin() external view returns (address) {
        return WalletStorageLib.getLayout().installedPlugins.getTail();
    }

    function sizeOfPreValidationHooks(ModuleEntity validationFunction) external view returns (uint256) {
        return WalletStorageLib.getLayout().validationDetails[validationFunction].preValidationHooks.length;
    }

    function setImplementation(address newImplementation) external {
        StorageSlot.getAddressSlot(ERC1967Utils.IMPLEMENTATION_SLOT).value = newImplementation;
    }

    function getExecutionDetail(bytes4 selector)
        external
        view
        returns (ExecutionDetailWrapper memory executionDetailWrapper)
    {
        // getExecutionFunctionConfig - plugin, userOpValidationFunction and runtimeValidationFunction
        executionDetailWrapper.plugin = this.getExecutionData(selector);
        // getExecutionHooks - ExecutionHooks(preExecHook, postExecHook)
        executionDetailWrapper.executionHooks = this.getExecutionHooks(selector);
        executionDetailWrapper.skipRuntimeValidation =
            WalletStorageLib.getLayout().executionDetails[selector].skipRuntimeValidation;
        executionDetailWrapper.allowGlobalValidation =
            WalletStorageLib.getLayout().executionDetails[selector].allowGlobalValidation;
        return executionDetailWrapper;
    }

    function getSupportedInterface(bytes4 selector) external view returns (uint256 interfaceId) {
        return WalletStorageLib.getLayout().supportedInterfaces[selector];
    }
}
