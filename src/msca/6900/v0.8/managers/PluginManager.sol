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

import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import {IPlugin} from "../interfaces/IPlugin.sol";
import {WalletStorageLib} from "../libs/WalletStorageLib.sol";
import {AddressDLLLib} from "../../shared/libs/AddressDLLLib.sol";
import {Bytes32DLLLib} from "../../shared/libs/Bytes32DLLLib.sol";
import {ModuleEntityLib} from "../libs/thirdparty/ModuleEntityLib.sol";
import {SelectorRegistryLib} from "../libs/SelectorRegistryLib.sol";
import {PluginManifest, ManifestValidation, ManifestExecutionFunction} from "../common/PluginManifest.sol";
import {SENTINEL_BYTES32, SENTINEL_BYTES4} from "../../../../common/Constants.sol";
import {AddressDLL} from "../../shared/common/Structs.sol";
import {ExecutionHook, ValidationDetail} from "../common/Structs.sol";
import {Bytes32DLL, Bytes4DLL} from "../../shared/common/Structs.sol";
import {RESERVED_VALIDATION_DATA_INDEX} from "../common/Constants.sol";
import {Bytes4DLLLib} from "../../shared/libs/Bytes4DLLLib.sol";
import {ValidationConfigLib} from "../libs/thirdparty/ValidationConfigLib.sol";
import {ValidationConfig, ModuleEntity} from "../common/Types.sol";
import {ModuleEntityLib} from "../libs/thirdparty/ModuleEntityLib.sol";
import {ExecutionHookLib} from "../libs/ExecutionHookLib.sol";

/**
 * @dev Default implementation of https://eips.ethereum.org/EIPS/eip-6900. MSCAs must implement this interface to
 * support installing and uninstalling plugins.
 */
contract PluginManager {
    using AddressDLLLib for AddressDLL;
    using Bytes32DLLLib for Bytes32DLL;
    using ModuleEntityLib for ModuleEntity;
    using SelectorRegistryLib for bytes4;
    using Bytes4DLLLib for Bytes4DLL;
    using ValidationConfigLib for ValidationConfig;
    using ExecutionHookLib for ExecutionHook;
    using ExecutionHookLib for bytes32;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable state-variable-assignment
    address private immutable __SELF = address(this);

    error PluginNotImplementInterface();
    error ExecutionDetailAlreadySet(address plugin, bytes4 selector);
    error ValidationFunctionAlreadySet(bytes4 selector);
    error FailToCallOnInstall(address plugin, bytes revertReason);
    error OnlyDelegated();
    error InvalidExecutionSelector(address plugin, bytes4 selector);
    error InvalidExecutionHook(address plugin, bytes4 selector);
    error GlobalValidationFunctionAlreadySet(ModuleEntity validationFunction);
    error PreValidationHookLimitExceeded();
    error NullPlugin();

    modifier onlyDelegated() {
        if (address(this) == __SELF) {
            revert OnlyDelegated();
        }
        _;
    }

    /// @dev Refer to IPluginManager
    function installPlugin(address plugin, bytes memory pluginInstallData) external onlyDelegated {
        if (plugin == address(0)) {
            revert NullPlugin();
        }
        // revert if the plugin does not implement ERC-165 or does not support the IPlugin interface
        if (!ERC165Checker.supportsInterface(plugin, type(IPlugin).interfaceId)) {
            revert PluginNotImplementInterface();
        }
        WalletStorageLib.Layout storage storageLayout = WalletStorageLib.getLayout();
        // revert internally if the plugin has already been installed on the modular account
        storageLayout.installedPlugins.append(plugin);
        IPlugin pluginToInstall = IPlugin(plugin);
        // revert if manifestHash does not match the computed Keccak-256 hash of the plugin’s returned manifest
        PluginManifest memory pluginManifest = pluginToInstall.pluginManifest();
        uint256 length = pluginManifest.interfaceIds.length;
        for (uint256 i = 0; i < length; ++i) {
            storageLayout.supportedInterfaces[pluginManifest.interfaceIds[i]] += 1;
        }

        // record execution details
        //////////////////////////////////////////////
        // install execution functions and hooks
        //////////////////////////////////////////////
        length = pluginManifest.executionFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            bytes4 selector = pluginManifest.executionFunctions[i].executionSelector;
            if (storageLayout.executionDetails[selector].plugin != address(0)) {
                revert ExecutionDetailAlreadySet(plugin, selector);
            }
            if (
                selector._isNativeFunctionSelector() || selector._isErc4337FunctionSelector()
                    || selector._isIPluginFunctionSelector()
            ) {
                revert InvalidExecutionSelector(plugin, selector);
            }
            storageLayout.executionDetails[selector].plugin = plugin;
            storageLayout.executionDetails[selector].skipRuntimeValidation =
                pluginManifest.executionFunctions[i].skipRuntimeValidation;
            storageLayout.executionDetails[selector].allowGlobalValidation =
                pluginManifest.executionFunctions[i].allowGlobalValidation;
        }

        // install execution hooks
        length = pluginManifest.executionHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            bytes4 selector = pluginManifest.executionHooks[i].selector;
            if (!pluginManifest.executionHooks[i].isPreHook && !pluginManifest.executionHooks[i].isPostHook) {
                revert InvalidExecutionHook(plugin, selector);
            }
            storageLayout.executionDetails[selector].executionHooks.append(
                ExecutionHook({
                    hookFunction: ModuleEntityLib.pack({addr: plugin, entityId: pluginManifest.executionHooks[i].entityId}),
                    isPreHook: pluginManifest.executionHooks[i].isPreHook,
                    isPostHook: pluginManifest.executionHooks[i].isPostHook
                }).toBytes32()
            );
        }

        //////////////////////////////////////////////
        // install validation functions and hooks
        //////////////////////////////////////////////
        // install selectors per validation
        length = pluginManifest.validationFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestValidation memory manifestValidation = pluginManifest.validationFunctions[i];
            ModuleEntity validationFunction =
                ModuleEntityLib.pack({addr: plugin, entityId: manifestValidation.entityId});
            if (manifestValidation.isGlobal) {
                storageLayout.validationDetails[validationFunction].isGlobal = true;
            }
            if (manifestValidation.isSignatureValidation) {
                storageLayout.validationDetails[validationFunction].isSignatureValidation = true;
            }
            for (uint256 j = 0; j < manifestValidation.selectors.length; ++j) {
                storageLayout.validationDetails[validationFunction].selectors.append(manifestValidation.selectors[j]);
            }
        }

        // call onInstall to initialize plugin data for the modular account
        // solhint-disable-next-line no-empty-blocks
        try IPlugin(plugin).onInstall(pluginInstallData) {}
        catch (bytes memory revertReason) {
            revert FailToCallOnInstall(plugin, revertReason);
        }
    }

    /// @dev Refer to IPluginManager
    function uninstallPlugin(address plugin, bytes memory config, bytes memory pluginUninstallData)
        external
        onlyDelegated
        returns (bool)
    {
        WalletStorageLib.Layout storage storageLayout = WalletStorageLib.getLayout();
        // revert internally if plugin was not installed before
        storageLayout.installedPlugins.remove(plugin);
        PluginManifest memory pluginManifest;
        if (config.length > 0) {
            // the modular account MAY implement the capability for the manifest to be encoded in the config field as a
            // parameter
            pluginManifest = abi.decode(config, (PluginManifest));
        } else {
            pluginManifest = IPlugin(plugin).pluginManifest();
        }
        // uninstall the components in reverse order (by component type) of their installation
        //////////////////////////////////////////////
        // uninstall validation functions and hooks
        //////////////////////////////////////////////
        uint256 length = pluginManifest.validationFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestValidation memory manifestValidation = pluginManifest.validationFunctions[i];
            ModuleEntity validationFunction =
                ModuleEntityLib.pack({addr: plugin, entityId: manifestValidation.entityId});
            storageLayout.validationDetails[validationFunction].isGlobal = false;
            storageLayout.validationDetails[validationFunction].isSignatureValidation = false;
            Bytes4DLL storage selectors = storageLayout.validationDetails[validationFunction].selectors;
            uint256 selectorsLength = selectors.size();
            bytes4 startSelector = SENTINEL_BYTES4;
            for (uint256 j = 0; j < selectorsLength; ++j) {
                (bytes4[] memory selectorsToRemove, bytes4 nextSelector) = selectors.getPaginated(startSelector, 10);
                for (uint256 k = 0; k < selectorsToRemove.length; ++k) {
                    selectors.remove(selectorsToRemove[k]);
                }
                if (nextSelector == SENTINEL_BYTES4) {
                    break;
                }
                startSelector = nextSelector;
            }
        }

        //////////////////////////////////////////////
        // uninstall execution hooks and functions
        //////////////////////////////////////////////
        length = pluginManifest.executionHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            bytes4 selector = pluginManifest.executionHooks[i].selector;
            storageLayout.executionDetails[selector].executionHooks.remove(
                ExecutionHook({
                    hookFunction: ModuleEntityLib.pack({addr: plugin, entityId: pluginManifest.executionHooks[i].entityId}),
                    isPreHook: pluginManifest.executionHooks[i].isPreHook,
                    isPostHook: pluginManifest.executionHooks[i].isPostHook
                }).toBytes32()
            );
        }

        length = pluginManifest.executionFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestExecutionFunction memory manifestExecutionFunction = pluginManifest.executionFunctions[i];
            storageLayout.executionDetails[manifestExecutionFunction.executionSelector].plugin = address(0);
            storageLayout.executionDetails[manifestExecutionFunction.executionSelector].skipRuntimeValidation = false;
            storageLayout.executionDetails[manifestExecutionFunction.executionSelector].allowGlobalValidation = false;
        }

        length = pluginManifest.interfaceIds.length;
        for (uint256 i = 0; i < length; ++i) {
            storageLayout.supportedInterfaces[pluginManifest.interfaceIds[i]] -= 1;
        }
        // call the plugin’s onUninstall callback with the data provided in the uninstallData parameter;
        // This serves to clear the plugin state for the modular account;
        // If onUninstall reverts, execution SHOULD continue to allow the uninstall to complete
        bool onUninstallSucceeded = true;
        // solhint-disable-next-line no-empty-blocks
        try IPlugin(plugin).onUninstall(pluginUninstallData) {}
        catch {
            // leave it up to the caller if we want to revert if the plugin storage isn't cleaned up
            onUninstallSucceeded = false;
        }
        return onUninstallSucceeded;
    }

    /// @dev Refer to IPluginManager
    function installValidation(
        ValidationConfig validationConfig,
        bytes4[] calldata selectors,
        bytes calldata installData,
        bytes calldata hooks,
        bytes calldata permissionHooks
    ) external onlyDelegated {
        ModuleEntity moduleEntity = validationConfig.moduleEntity();
        ValidationDetail storage validationDetail = WalletStorageLib.getLayout().validationDetails[moduleEntity];
        if (hooks.length > 0) {
            (ModuleEntity[] memory hookFunctions, bytes[] memory hookFunctionsInitData) =
                abi.decode(hooks, (ModuleEntity[], bytes[]));
            uint256 hooksLength = hookFunctions.length;
            for (uint256 i = 0; i < hooksLength; ++i) {
                ModuleEntity hookFunction = hookFunctions[i];
                // TODO: dedupe
                validationDetail.preValidationHooks.push(hookFunction);
                if (hookFunctionsInitData[i].length > 0) {
                    address plugin = hookFunction.getAddress();
                    // solhint-disable-next-line no-empty-blocks
                    try IPlugin(plugin).onInstall(hookFunctionsInitData[i]) {}
                    catch (bytes memory revertReason) {
                        revert FailToCallOnInstall(plugin, revertReason);
                    }
                }
                // Avoid collision between reserved index and actual indices
                if (validationDetail.preValidationHooks.length > RESERVED_VALIDATION_DATA_INDEX) {
                    revert PreValidationHookLimitExceeded();
                }
            }
        }

        if (permissionHooks.length > 0) {
            (ExecutionHook[] memory hookFunctions, bytes[] memory hookFunctionsInitData) =
                abi.decode(permissionHooks, (ExecutionHook[], bytes[]));
            uint256 hooksLength = hookFunctions.length;
            for (uint256 i = 0; i < hooksLength; ++i) {
                // revert internally
                validationDetail.permissionHooks.append(hookFunctions[i].toBytes32());
                if (hookFunctionsInitData[i].length > 0) {
                    IPlugin(hookFunctions[i].hookFunction.getAddress()).onInstall(hookFunctionsInitData[i]);
                }
            }
        }

        validationDetail.isGlobal = validationConfig.isGlobal();
        validationDetail.isSignatureValidation = validationConfig.isSignatureValidation();

        uint256 length = selectors.length;
        for (uint256 i = 0; i < length; ++i) {
            // revert internally
            validationDetail.selectors.append(selectors[i]);
        }
        // call onInstall to initialize plugin data for the modular account
        if (installData.length > 0) {
            address plugin = validationConfig.plugin();
            // solhint-disable-next-line no-empty-blocks
            try IPlugin(plugin).onInstall(installData) {}
            catch (bytes memory revertReason) {
                revert FailToCallOnInstall(plugin, revertReason);
            }
        }
    }

    /// @dev Refer to IPluginManager
    function uninstallValidation(
        ModuleEntity validationFunction,
        bytes calldata uninstallData,
        bytes calldata hookUninstallData,
        bytes calldata permissionHookUninstallData
    ) external onlyDelegated returns (bool) {
        ValidationDetail storage validationDetail = WalletStorageLib.getLayout().validationDetails[validationFunction];
        validationDetail.isGlobal = false;
        validationDetail.isSignatureValidation = false;
        bool onUninstallSucceeded = true;

        {
            // uninstall pre validation hooks
            bytes[] memory hookFunctionsUninstallData = abi.decode(hookUninstallData, (bytes[]));
            ModuleEntity[] storage hookFunctions = validationDetail.preValidationHooks;
            uint256 hooksLength = hookFunctions.length;
            uint256 uninstalled = 0;
            for (uint256 i = 0; i < hooksLength; ++i) {
                if (hookFunctionsUninstallData[uninstalled].length > 0) {
                    // solhint-disable-next-line no-empty-blocks
                    try IPlugin(hookFunctions[i].getAddress()).onUninstall(hookFunctionsUninstallData[uninstalled]) {}
                    catch {
                        // leave it up to the caller if we want to revert if the plugin storage isn't cleaned up
                        if (onUninstallSucceeded) {
                            onUninstallSucceeded = false;
                        }
                    }
                }
                uninstalled++;
            }
            delete validationDetail.preValidationHooks;
        }

        {
            // uninstall permission hooks
            bytes[] memory hookFunctionsUninstallData = abi.decode(permissionHookUninstallData, (bytes[]));
            Bytes32DLL storage hookFunctions = validationDetail.permissionHooks;
            uint256 hooksLength = hookFunctions.size();
            uint256 uninstalled = 0;
            bytes32 startHook = SENTINEL_BYTES32;
            for (uint256 i = 0; i < hooksLength; ++i) {
                (bytes32[] memory hooksToRemove, bytes32 nextHook) = hookFunctions.getPaginated(startHook, 10);
                for (uint256 j = 0; j < hooksToRemove.length; ++j) {
                    hookFunctions.remove(hooksToRemove[j]);
                    if (hookFunctionsUninstallData[uninstalled].length > 0) {
                        ModuleEntity hookFunction = hooksToRemove[j].getExecutionHookFunction();
                        // solhint-disable-next-line no-empty-blocks
                        try IPlugin(hookFunction.getAddress()).onUninstall(hookFunctionsUninstallData[uninstalled]) {}
                        catch {
                            // leave it up to the caller if we want to revert if the plugin storage isn't cleaned up
                            if (onUninstallSucceeded) {
                                onUninstallSucceeded = false;
                            }
                        }
                    }
                    uninstalled++;
                }
                if (nextHook == SENTINEL_BYTES32) {
                    break;
                }
                startHook = nextHook;
            }
        }

        {
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
        }

        if (uninstallData.length > 0) {
            // solhint-disable-next-line no-empty-blocks
            try IPlugin(validationFunction.getAddress()).onUninstall(uninstallData) {}
            catch {
                // leave it up to the caller if we want to revert if the plugin storage isn't cleaned up
                if (onUninstallSucceeded) {
                    onUninstallSucceeded = false;
                }
            }
        }
        return onUninstallSucceeded;
    }
}
