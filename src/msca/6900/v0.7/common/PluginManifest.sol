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

// Plugin Manifest
enum ManifestAssociatedFunctionType {
    // Function is not defined.
    NONE,
    // Function belongs to this plugin.
    SELF,
    // Function belongs to an external plugin provided as a dependency during plugin installation.
    DEPENDENCY,
    // Resolves to a magic value to always bypass runtime validation for a given function.
    // This is only assignable on runtime validation functions. If it were to be used on a user op validation function,
    // it would risk burning gas from the account. When used as a hook in any hook location, it is equivalent to not
    // setting a hook and is therefore disallowed.
    RUNTIME_VALIDATION_ALWAYS_ALLOW,
    // Resolves to a magic value to always fail in a hook for a given function.
    // This is only assignable to pre hooks (pre validation and pre execution). It should not be used on
    // validation functions themselves, because this is equivalent to leaving the validation functions unset.
    // It should not be used in post-exec hooks, because if it is known to always revert, that should happen
    // as early as possible to save gas.
    PRE_HOOK_ALWAYS_DENY
}

/// @dev For functions of type `ManifestAssociatedFunctionType.DEPENDENCY`, the MSCA MUST find the plugin address
/// of the function at `dependencies[dependencyIndex]` during the call to `installPlugin(config)`.
struct ManifestFunction {
    ManifestAssociatedFunctionType functionType;
    uint8 functionId;
    uint256 dependencyIndex;
}

struct ManifestAssociatedFunction {
    bytes4 executionSelector;
    ManifestFunction associatedFunction;
}

struct ManifestExecutionHook {
    bytes4 selector;
    ManifestFunction preExecHook;
    ManifestFunction postExecHook;
}

struct ManifestExternalCallPermission {
    address externalAddress;
    bool permitAnySelector;
    bytes4[] selectors;
}

struct SelectorPermission {
    bytes4 functionSelector;
    string permissionDescription;
}

/// @dev A struct holding fields to describe the plugin in a purely view context. Intended for front end clients.
struct PluginMetadata {
    // A human-readable name of the plugin.
    string name;
    // The version of the plugin, following the semantic versioning scheme.
    string version;
    // The author field SHOULD be a username representing the identity of the user or organization
    // that created this plugin.
    string author;
    // String descriptions of the relative sensitivity of specific functions. The selectors MUST be selectors for
    // functions implemented by this plugin.
    SelectorPermission[] permissionDescriptors;
}

/// @dev A struct describing how the plugin should be installed on a modular account.
struct PluginManifest {
    // List of ERC-165 interface IDs to add to account to support introspection checks. This MUST NOT include
    // IPlugin's interface ID.
    bytes4[] interfaceIds;
    // If this plugin depends on other plugins' validation functions, the interface IDs of those plugins MUST be
    // provided here, with its position in the array matching the `dependencyIndex` members of `ManifestFunction`
    bytes4[] dependencyInterfaceIds;
    // Execution functions defined in this plugin to be installed on the MSCA.
    bytes4[] executionFunctions;
    // Plugin execution functions already installed on the MSCA that this plugin will be able to call.
    bytes4[] permittedExecutionSelectors;
    // Boolean to indicate whether the plugin can call any external address.
    bool permitAnyExternalAddress;
    // Boolean to indicate whether the plugin needs access to spend native tokens of the account. If false, the
    // plugin MUST still be able to spend up to the balance that it sends to the account in the same call.
    bool canSpendNativeToken;
    // More granular control
    ManifestExternalCallPermission[] permittedExternalCalls;
    ManifestAssociatedFunction[] userOpValidationFunctions;
    ManifestAssociatedFunction[] runtimeValidationFunctions;
    ManifestAssociatedFunction[] preUserOpValidationHooks;
    ManifestAssociatedFunction[] preRuntimeValidationHooks;
    // for executionFunctions
    ManifestExecutionHook[] executionHooks;
}
