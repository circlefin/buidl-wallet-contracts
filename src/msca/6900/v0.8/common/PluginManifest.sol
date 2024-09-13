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

struct ManifestExecutionFunction {
    bytes4 executionSelector;
    // If true, the function will not need runtime validation and can be called by anyone
    bool skipRuntimeValidation;
    // If true, the function can be validated by a global validation function
    bool allowGlobalValidation;
}

struct ManifestValidation {
    uint32 entityId;
    bool isGlobal;
    bool isSignatureValidation;
    bytes4[] selectors;
}

struct ManifestExecutionHook {
    bytes4 selector;
    uint32 entityId;
    bool isPreHook;
    bool isPostHook;
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
    // A list of all ERC-7715 permission strings that the plugin could possibly use.
    string[] permissionRequest;
}

/// @dev A struct describing how the plugin should be installed on a modular account.
struct PluginManifest {
    // List of ERC-165 interface IDs to add to account to support introspection checks. This MUST NOT include
    // IPlugin's interface ID.
    bytes4[] interfaceIds;
    // Execution functions defined in this plugin to be installed on the MSCA.
    ManifestExecutionFunction[] executionFunctions;
    ManifestValidation[] validationFunctions;
    // for executionFunctions
    ManifestExecutionHook[] executionHooks;
}
