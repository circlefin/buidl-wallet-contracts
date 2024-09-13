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

// Standard executor
struct Call {
    // The target address for the account to call.
    address target;
    // The value to send with the call.
    uint256 value;
    // The calldata for the call.
    bytes data;
}

struct FunctionReference {
    address plugin;
    uint8 functionId;
}

// Account loupe
// @notice Config for an execution function, given a selector
struct ExecutionFunctionConfig {
    address plugin;
    FunctionReference userOpValidationFunction;
    FunctionReference runtimeValidationFunction;
}

/// @notice Pre and post hooks for a given selector
/// @dev It's possible for one of either `preExecHook` or `postExecHook` to be empty
struct ExecutionHooks {
    FunctionReference preExecHook;
    FunctionReference postExecHook;
}

// internal data structure
struct Bytes21DLL {
    mapping(bytes21 => bytes21) next;
    mapping(bytes21 => bytes21) prev;
    uint256 count;
}

struct RepeatableBytes21DLL {
    mapping(bytes21 => bytes21) next;
    mapping(bytes21 => bytes21) prev;
    mapping(bytes21 => uint256) counter;
    // unique items
    uint256 uniqueItems;
    // total items with repeatable ones
    uint256 totalItems;
}

// Represents a set of pre and post hooks. Used to store execution hooks.
struct HookGroup {
    RepeatableBytes21DLL preHooks;
    // key = preExecHook.pack()
    mapping(bytes21 => RepeatableBytes21DLL) preToPostHooks;
    RepeatableBytes21DLL postOnlyHooks;
}

// plugin's permission to call external (to the account and its plugins) contracts and addresses
// through `executeFromPluginExternal`
struct PermittedExternalCall {
    bool addressPermitted;
    // either anySelector or selectors permitted
    bool anySelector;
    mapping(bytes4 => bool) selectors;
}

struct PostExecHookToRun {
    bytes preExecHookReturnData;
    FunctionReference postExecHook;
}

// plugin detail stored in wallet storage
struct PluginDetail {
    // permitted to call any external contracts and selectors
    bool anyExternalAddressPermitted;
    // boolean to indicate if the plugin can spend native tokens, if any of the execution function can spend
    // native tokens, a plugin is considered to be able to spend native tokens of the accounts
    bool canSpendNativeToken;
    // tracks the count this plugin has been used as a dependency function
    uint256 dependentCounter;
    bytes32 manifestHash;
    Bytes21DLL dependencies;
}

// execution detail associated with selector
struct ExecutionDetail {
    address plugin; // plugin address that implements the execution function, for native functions, the value should be
        // address(0)
    FunctionReference userOpValidationFunction;
    RepeatableBytes21DLL preUserOpValidationHooks;
    FunctionReference runtimeValidationFunction;
    RepeatableBytes21DLL preRuntimeValidationHooks;
    HookGroup executionHooks;
}
