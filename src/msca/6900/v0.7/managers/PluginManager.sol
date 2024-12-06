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

import {EMPTY_FUNCTION_REFERENCE} from "../../../../common/Constants.sol";
import {InvalidFunctionReference} from "../../shared/common/Errors.sol";
import {AddressDLL} from "../../shared/common/Structs.sol";
import {AddressDLLLib} from "../../shared/libs/AddressDLLLib.sol";
import {
    PRE_HOOK_ALWAYS_DENY_FUNCTION_REFERENCE,
    RUNTIME_VALIDATION_ALWAYS_ALLOW_FUNCTION_REFERENCE
} from "../common/Constants.sol";
import {
    ManifestAssociatedFunctionType,
    ManifestExecutionHook,
    ManifestExternalCallPermission,
    ManifestFunction,
    PluginManifest
} from "../common/PluginManifest.sol";
import {
    Bytes21DLL,
    FunctionReference,
    HookGroup,
    PermittedExternalCall,
    RepeatableBytes21DLL
} from "../common/Structs.sol";
import {IPlugin} from "../interfaces/IPlugin.sol";
import {FunctionReferenceDLLLib} from "../libs/FunctionReferenceDLLLib.sol";
import {FunctionReferenceLib} from "../libs/FunctionReferenceLib.sol";
import {RepeatableFunctionReferenceDLLLib} from "../libs/RepeatableFunctionReferenceDLLLib.sol";
import {SelectorRegistryLib} from "../libs/SelectorRegistryLib.sol";
import {WalletStorageV1Lib} from "../libs/WalletStorageV1Lib.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";

/**
 * @dev Default implementation of https://eips.ethereum.org/EIPS/eip-6900. MSCAs must implement this interface to
 * support installing and uninstalling plugins.
 */
contract PluginManager {
    using AddressDLLLib for AddressDLL;
    using FunctionReferenceDLLLib for Bytes21DLL;
    using RepeatableFunctionReferenceDLLLib for RepeatableBytes21DLL;
    using FunctionReferenceLib for FunctionReference;
    using FunctionReferenceLib for bytes21;
    using SelectorRegistryLib for bytes4;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable state-variable-assignment
    address private immutable SELF = address(this);

    enum AssociatedFunctionType {
        HOOK,
        VALIDATION_FUNCTION
    }

    error PluginNotImplementInterface();
    error InvalidPluginManifest();
    error InvalidPluginManifestHash();
    error InvalidPluginDependency(address plugin);
    error PluginUsedByOthers(address plugin);
    error ExecutionDetailAlreadySet(address plugin, bytes4 selector);
    error ExecuteFromPluginExternalAlreadySet(address plugin, address externalAddress);
    error ExecuteFromPluginExternalAlreadyUnset(address plugin, address externalAddress);
    error ValidationFunctionAlreadySet(bytes4 selector);
    error FailToCallOnInstall(address plugin, bytes revertReason);
    error OnlyDelegated();
    error HookDependencyNotPermitted();
    error InvalidExecutionSelector(address plugin, bytes4 selector);

    modifier onlyDelegated() {
        if (address(this) == SELF) {
            revert OnlyDelegated();
        }
        _;
    }

    /// @dev Refer to IPluginManager
    function install(
        address plugin,
        bytes32 manifestHash,
        bytes memory pluginInstallData,
        FunctionReference[] memory dependencies,
        address msca
    ) external onlyDelegated {
        // revert if the plugin does not implement ERC-165 or does not support the IPlugin interface
        if (!ERC165Checker.supportsInterface(plugin, type(IPlugin).interfaceId)) {
            revert PluginNotImplementInterface();
        }
        WalletStorageV1Lib.Layout storage storageLayout = WalletStorageV1Lib.getLayout();
        // revert internally if the plugin has already been installed on the modular account
        storageLayout.installedPlugins.append(plugin);
        IPlugin pluginToInstall = IPlugin(plugin);
        // revert if manifestHash does not match the computed Keccak-256 hash of the plugin’s returned manifest
        PluginManifest memory pluginManifest = pluginToInstall.pluginManifest();
        if (manifestHash != keccak256(abi.encode(pluginManifest))) {
            revert InvalidPluginManifestHash();
        }
        // store the plugin manifest hash
        storageLayout.pluginDetails[plugin].manifestHash = manifestHash;
        uint256 length = pluginManifest.interfaceIds.length;
        for (uint256 i = 0; i < length; ++i) {
            storageLayout.supportedInterfaces[pluginManifest.interfaceIds[i]] += 1;
        }
        // revert if any address in dependencies does not support the interface at its matching index in the manifest’s
        // dependencyInterfaceIds,
        // or if the two array lengths do not match,
        // or if any of the dependencies are not already installed on the modular account
        length = dependencies.length;
        if (length != pluginManifest.dependencyInterfaceIds.length) {
            revert InvalidPluginDependency(plugin);
        }
        for (uint256 i = 0; i < length; ++i) {
            address dependencyPluginAddr = dependencies[i].plugin;
            // if dependencyPluginAddr is msca address, then we don't actually introduce any new plugin dependency
            // other than native dependency, so we do not need to perform any plugin dependency related logic
            if (dependencyPluginAddr == msca) {
                continue;
            }
            if (!ERC165Checker.supportsInterface(dependencyPluginAddr, pluginManifest.dependencyInterfaceIds[i])) {
                revert InvalidPluginDependency(dependencyPluginAddr);
            }
            // the dependency plugin needs to be installed first
            if (!storageLayout.installedPlugins.contains(dependencyPluginAddr)) {
                revert InvalidPluginDependency(dependencyPluginAddr);
            }
            // each dependency’s record MUST also be updated to reflect that it has a new dependent
            // record the plugin dependency, will revert if it's already installed
            storageLayout.pluginDetails[plugin].dependencies.append(dependencies[i]);
            // increment the dependency's dependentCounter since the current plugin is dependent on dependencyPlugin
            storageLayout.pluginDetails[dependencyPluginAddr].dependentCounter += 1;
        }

        // record if this plugin is allowed to spend native token
        if (pluginManifest.canSpendNativeToken) {
            storageLayout.pluginDetails[plugin].canSpendNativeToken = true;
        }

        // record execution details
        //////////////////////////////////////////////
        // install execution functions and hooks
        //////////////////////////////////////////////
        length = pluginManifest.executionFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            bytes4 selector = pluginManifest.executionFunctions[i];
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
        }

        // install pre and post execution hooks
        length = pluginManifest.executionHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            bytes4 selector = pluginManifest.executionHooks[i].selector;
            FunctionReference memory preExecHook = _resolveManifestFunction(
                pluginManifest.executionHooks[i].preExecHook,
                plugin,
                dependencies,
                ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY,
                AssociatedFunctionType.HOOK
            );
            FunctionReference memory postExecHook = _resolveManifestFunction(
                pluginManifest.executionHooks[i].postExecHook,
                plugin,
                dependencies,
                ManifestAssociatedFunctionType.NONE,
                AssociatedFunctionType.HOOK
            );
            _addHookGroup(storageLayout.executionDetails[selector].executionHooks, preExecHook, postExecHook);
        }

        //////////////////////////////////////////////
        // install validation functions and hooks
        //////////////////////////////////////////////
        // install userOpValidationFunctions
        length = pluginManifest.userOpValidationFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            bytes4 selector = pluginManifest.userOpValidationFunctions[i].executionSelector;
            if (storageLayout.executionDetails[selector].userOpValidationFunction.pack() != EMPTY_FUNCTION_REFERENCE) {
                revert ValidationFunctionAlreadySet(selector);
            }
            storageLayout.executionDetails[selector].userOpValidationFunction = _resolveManifestFunction(
                pluginManifest.userOpValidationFunctions[i].associatedFunction,
                plugin,
                dependencies,
                ManifestAssociatedFunctionType.NONE,
                AssociatedFunctionType.VALIDATION_FUNCTION
            );
        }
        // install runtimeValidationFunctions
        length = pluginManifest.runtimeValidationFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            bytes4 selector = pluginManifest.runtimeValidationFunctions[i].executionSelector;
            if (storageLayout.executionDetails[selector].runtimeValidationFunction.pack() != EMPTY_FUNCTION_REFERENCE) {
                revert ValidationFunctionAlreadySet(selector);
            }
            storageLayout.executionDetails[selector].runtimeValidationFunction = _resolveManifestFunction(
                pluginManifest.runtimeValidationFunctions[i].associatedFunction,
                plugin,
                dependencies,
                ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW, // risk burning gas from the account
                AssociatedFunctionType.VALIDATION_FUNCTION
            );
        }
        // install preUserOpValidationHooks
        length = pluginManifest.preUserOpValidationHooks.length;
        // force override to be safe
        FunctionReference[] memory emptyDependencies = new FunctionReference[](0);
        for (uint256 i = 0; i < length; ++i) {
            bytes4 selector = pluginManifest.preUserOpValidationHooks[i].executionSelector;
            // revert internally
            storageLayout.executionDetails[selector].preUserOpValidationHooks.append(
                _resolveManifestFunction(
                    pluginManifest.preUserOpValidationHooks[i].associatedFunction,
                    plugin,
                    emptyDependencies,
                    ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY,
                    AssociatedFunctionType.HOOK
                )
            );
        }
        // install preRuntimeValidationHooks
        length = pluginManifest.preRuntimeValidationHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            // revert internally
            storageLayout.executionDetails[pluginManifest.preRuntimeValidationHooks[i].executionSelector]
                .preRuntimeValidationHooks
                .append(
                _resolveManifestFunction(
                    pluginManifest.preRuntimeValidationHooks[i].associatedFunction,
                    plugin,
                    emptyDependencies,
                    ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY,
                    AssociatedFunctionType.HOOK
                )
            );
        }

        // store the plugin’s permitted function selectors and external contract calls to be able to validate calls
        // to executeFromPlugin and executeFromPluginExternal
        //////////////////////////////////////////////
        // permissions for executeFromPlugin
        //////////////////////////////////////////////
        // native functions or execution functions already installed on the MSCA that this plugin will be able to call
        length = pluginManifest.permittedExecutionSelectors.length;
        for (uint256 i = 0; i < length; ++i) {
            // enable PermittedPluginCall
            storageLayout.permittedPluginCalls[plugin][pluginManifest.permittedExecutionSelectors[i]] = true;
        }

        //////////////////////////////////////////////
        // permissions for executeFromPluginExternal
        //////////////////////////////////////////////
        // is the plugin permitted to call any external contracts and selectors
        if (pluginManifest.permitAnyExternalAddress) {
            storageLayout.pluginDetails[plugin].anyExternalAddressPermitted = true;
        } else {
            // more limited access - record external contract calls that this plugin will be able to make
            length = pluginManifest.permittedExternalCalls.length;
            for (uint256 i = 0; i < length; ++i) {
                ManifestExternalCallPermission memory externalCallPermission = pluginManifest.permittedExternalCalls[i];
                PermittedExternalCall storage permittedExternalCall =
                    storageLayout.permittedExternalCalls[plugin][externalCallPermission.externalAddress];
                if (permittedExternalCall.addressPermitted) {
                    revert ExecuteFromPluginExternalAlreadySet(plugin, externalCallPermission.externalAddress);
                }
                permittedExternalCall.addressPermitted = true;
                if (externalCallPermission.permitAnySelector) {
                    permittedExternalCall.anySelector = true;
                } else {
                    uint256 permittedExternalCallSelectorsLength = externalCallPermission.selectors.length;
                    for (uint256 j = 0; j < permittedExternalCallSelectorsLength; ++j) {
                        permittedExternalCall.selectors[externalCallPermission.selectors[j]] = true;
                    }
                }
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
    function uninstall(address plugin, bytes memory config, bytes memory pluginUninstallData)
        external
        onlyDelegated
        returns (bool)
    {
        WalletStorageV1Lib.Layout storage storageLayout = WalletStorageV1Lib.getLayout();
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
        // revert if the hash of the manifest used at install time does not match the computed Keccak-256 hash of the
        // plugin’s current manifest
        if (storageLayout.pluginDetails[plugin].manifestHash != keccak256(abi.encode(pluginManifest))) {
            revert InvalidPluginManifestHash();
        }
        // revert if there is at least 1 other installed plugin that depends on validation functions or hooks added by
        // this plugin;
        // plugins used as dependencies must not be uninstalled while dependent plugins exist
        if (storageLayout.pluginDetails[plugin].dependentCounter != 0) {
            revert PluginUsedByOthers(plugin);
        }
        // each dependency’s record SHOULD be updated to reflect that it has no longer has this plugin as a dependent
        _removeDependencies(plugin, storageLayout);
        // remove records for the plugin’s dependencies, injected permitted call hooks, permitted function selectors,
        // and permitted external contract calls
        // uninstall the components in reverse order (by component type) of their installation
        //////////////////////////////////////////////
        // permissions for executeFromPluginExternal
        //////////////////////////////////////////////
        if (pluginManifest.permitAnyExternalAddress) {
            storageLayout.pluginDetails[plugin].anyExternalAddressPermitted = false;
        }
        uint256 length;
        if (!pluginManifest.permitAnyExternalAddress) {
            length = pluginManifest.permittedExternalCalls.length;
            for (uint256 i = 0; i < length; ++i) {
                ManifestExternalCallPermission memory externalCallPermission = pluginManifest.permittedExternalCalls[i];
                PermittedExternalCall storage permittedExternalCall =
                    storageLayout.permittedExternalCalls[plugin][externalCallPermission.externalAddress];
                if (!permittedExternalCall.addressPermitted) {
                    revert ExecuteFromPluginExternalAlreadyUnset(plugin, externalCallPermission.externalAddress);
                }
                permittedExternalCall.addressPermitted = false;
                if (externalCallPermission.permitAnySelector) {
                    permittedExternalCall.anySelector = false;
                } else {
                    uint256 permittedExternalCallSelectorsLength = externalCallPermission.selectors.length;
                    for (uint256 j = 0; j < permittedExternalCallSelectorsLength; ++j) {
                        permittedExternalCall.selectors[externalCallPermission.selectors[j]] = false;
                    }
                }
            }
        }

        length = pluginManifest.permittedExecutionSelectors.length;
        for (uint256 i = 0; i < length; ++i) {
            // disable PermittedPluginCall
            storageLayout.permittedPluginCalls[plugin][pluginManifest.permittedExecutionSelectors[i]] = false;
        }

        //////////////////////////////////////////////
        // uninstall validation functions and hooks
        //////////////////////////////////////////////
        // uninstall preRuntimeValidationHooks
        FunctionReference[] memory emptyDependencies = new FunctionReference[](0);
        length = pluginManifest.preRuntimeValidationHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            // revert internally
            storageLayout.executionDetails[pluginManifest.preRuntimeValidationHooks[i].executionSelector]
                .preRuntimeValidationHooks
                .remove(
                _resolveManifestFunction(
                    pluginManifest.preRuntimeValidationHooks[i].associatedFunction,
                    plugin,
                    emptyDependencies,
                    ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY,
                    AssociatedFunctionType.HOOK
                )
            );
        }
        // uninstall preUserOpValidationHooks
        length = pluginManifest.preUserOpValidationHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            // revert internally
            storageLayout.executionDetails[pluginManifest.preUserOpValidationHooks[i].executionSelector]
                .preUserOpValidationHooks
                .remove(
                _resolveManifestFunction(
                    pluginManifest.preUserOpValidationHooks[i].associatedFunction,
                    plugin,
                    emptyDependencies,
                    ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY,
                    AssociatedFunctionType.HOOK
                )
            );
        }
        // uninstall runtimeValidationFunctions
        FunctionReference memory emptyFunctionReference = EMPTY_FUNCTION_REFERENCE.unpack();
        length = pluginManifest.runtimeValidationFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            storageLayout.executionDetails[pluginManifest.runtimeValidationFunctions[i].executionSelector]
                .runtimeValidationFunction = emptyFunctionReference;
        }
        // uninstall userOpValidationFunctions
        length = pluginManifest.userOpValidationFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            storageLayout.executionDetails[pluginManifest.userOpValidationFunctions[i].executionSelector]
                .userOpValidationFunction = emptyFunctionReference;
        }

        //////////////////////////////////////////////
        // uninstall execution functions and hooks
        //////////////////////////////////////////////
        _removeExecutionHooks(plugin, pluginManifest.executionHooks, storageLayout);
        length = pluginManifest.executionFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            storageLayout.executionDetails[pluginManifest.executionFunctions[i]].plugin = address(0);
        }

        length = pluginManifest.interfaceIds.length;
        for (uint256 i = 0; i < length; ++i) {
            storageLayout.supportedInterfaces[pluginManifest.interfaceIds[i]] -= 1;
        }
        // reset all members that are not mappings and also recurse into the members unless they're mappings
        delete storageLayout.pluginDetails[plugin];
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

    /**
     * @dev Resolve manifest function.
     *      For functions of type `ManifestAssociatedFunctionType.DEPENDENCY`, the MSCA MUST find the plugin address
     *      of the function at `dependencies[dependencyIndex]` during the call to `installPlugin(config)`.
     *      A plugin can no longer use hooks from other plugins to be added on Execution and/or Validation function
     * selectors
     *      in its own manifest. We'll revert if hook is provided as dependency from an external plugin.
     * @param allowedMagicValue which magic value (if any) is permissible for the function type to resolve.
     * @param associatedFunctionType the type of associated function, either a validation function or a hook, as opposed
     * to execution functions
     */
    function _resolveManifestFunction(
        ManifestFunction memory manifestFunction,
        address plugin,
        FunctionReference[] memory dependencies,
        ManifestAssociatedFunctionType allowedMagicValue,
        AssociatedFunctionType associatedFunctionType
    ) internal pure returns (FunctionReference memory) {
        // revert if it's hook and provided as dependency
        if (
            associatedFunctionType == AssociatedFunctionType.HOOK
                && manifestFunction.functionType == ManifestAssociatedFunctionType.DEPENDENCY
        ) {
            revert HookDependencyNotPermitted();
        }
        if (manifestFunction.functionType == ManifestAssociatedFunctionType.SELF) {
            return FunctionReference(plugin, manifestFunction.functionId);
        } else if (manifestFunction.functionType == ManifestAssociatedFunctionType.DEPENDENCY) {
            // out of boundary
            if (manifestFunction.dependencyIndex >= dependencies.length) {
                revert InvalidPluginManifest();
            }
            return dependencies[manifestFunction.dependencyIndex];
        } else if (manifestFunction.functionType == ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW) {
            if (allowedMagicValue == ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW) {
                return RUNTIME_VALIDATION_ALWAYS_ALLOW_FUNCTION_REFERENCE.unpack();
            } else {
                revert InvalidPluginManifest();
            }
        } else if (manifestFunction.functionType == ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY) {
            if (allowedMagicValue == ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY) {
                return PRE_HOOK_ALWAYS_DENY_FUNCTION_REFERENCE.unpack();
            } else {
                revert InvalidPluginManifest();
            }
        } else {
            return EMPTY_FUNCTION_REFERENCE.unpack();
        }
    }

    function _addHookGroup(
        HookGroup storage hookGroup,
        FunctionReference memory preExecHook,
        FunctionReference memory postExecHook
    ) internal {
        bytes21 packedPreExecHook = preExecHook.pack();
        if (packedPreExecHook == EMPTY_FUNCTION_REFERENCE) {
            if (postExecHook.pack() == EMPTY_FUNCTION_REFERENCE) {
                // pre and post hooks cannot be null at the same time
                revert InvalidFunctionReference();
            }
            hookGroup.postOnlyHooks.append(postExecHook);
        } else {
            hookGroup.preHooks.append(preExecHook);
            if (postExecHook.pack() != EMPTY_FUNCTION_REFERENCE) {
                hookGroup.preToPostHooks[packedPreExecHook].append(postExecHook);
            }
        }
    }

    function _removeHookGroup(
        HookGroup storage hookGroup,
        FunctionReference memory preExecHook,
        FunctionReference memory postExecHook
    ) internal {
        bytes21 packedPreExecHook = preExecHook.pack();
        if (packedPreExecHook == EMPTY_FUNCTION_REFERENCE) {
            // pre and post hooks cannot be null at the same time
            hookGroup.postOnlyHooks.remove(postExecHook);
        } else {
            hookGroup.preHooks.remove(preExecHook);
            // remove postExecHook if any
            if (postExecHook.pack() != EMPTY_FUNCTION_REFERENCE) {
                hookGroup.preToPostHooks[packedPreExecHook].remove(postExecHook);
            }
        }
    }

    function _removeDependencies(address plugin, WalletStorageV1Lib.Layout storage storageLayout) internal {
        Bytes21DLL storage pluginDependencies = storageLayout.pluginDetails[plugin].dependencies;
        uint256 length = pluginDependencies.size();
        FunctionReference memory startFR = EMPTY_FUNCTION_REFERENCE.unpack();
        FunctionReference[] memory dependencies;
        for (uint256 i = 0; i < length; ++i) {
            (dependencies, startFR) = pluginDependencies.getPaginated(startFR, 100);
            for (uint256 j = 0; j < dependencies.length; ++j) {
                storageLayout.pluginDetails[dependencies[j].plugin].dependentCounter -= 1;
                storageLayout.pluginDetails[plugin].dependencies.remove(dependencies[j]);
            }
            if (startFR.pack() == EMPTY_FUNCTION_REFERENCE) {
                break;
            }
        }
    }

    function _removeExecutionHooks(
        address plugin,
        ManifestExecutionHook[] memory executionHooks,
        WalletStorageV1Lib.Layout storage storageLayout
    ) internal {
        uint256 length = executionHooks.length;
        FunctionReference[] memory dependencies = new FunctionReference[](0);
        for (uint256 i = 0; i < length; ++i) {
            bytes4 selector = executionHooks[i].selector;
            FunctionReference memory preExecHook = _resolveManifestFunction(
                executionHooks[i].preExecHook,
                plugin,
                dependencies,
                ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY,
                AssociatedFunctionType.HOOK
            );
            FunctionReference memory postExecHookToRemove = _resolveManifestFunction(
                executionHooks[i].postExecHook,
                plugin,
                dependencies,
                ManifestAssociatedFunctionType.NONE,
                AssociatedFunctionType.HOOK
            );
            _removeHookGroup(storageLayout.executionDetails[selector].executionHooks, preExecHook, postExecHookToRemove);
        }
    }
}
