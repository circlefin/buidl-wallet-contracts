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

import {Bytes32DLL, Bytes4DLL} from "../../shared/common/Structs.sol";
import {ModuleEntity} from "./Types.sol";

// Standard executor
struct Call {
    // The target address for the account to call.
    address target;
    // The value to send with the call.
    uint256 value;
    // The calldata for the call.
    bytes data;
}

// Account loupe
// @notice Config for an execution function, given a selector
struct ExecutionFunctionConfig {
    address plugin;
    ModuleEntity validationFunction;
}

/// @notice Pre and post hooks for a given selector.
/// @dev It's possible for one of either `preExecHook` or `postExecHook` to be empty.
struct ExecutionHook {
    ModuleEntity hookFunction;
    bool isPreHook;
    bool isPostHook;
}

struct PostExecHookToRun {
    bytes preExecHookReturnData;
    ModuleEntity postExecHook;
}

struct ValidationDetail {
    // Whether or not this validation can be used as a global validation function.
    bool isGlobal;
    // Whether or not this validation is a signature validator.
    bool isSignatureValidation;
    // The pre validation hooks associated with this validation function.
    ModuleEntity[] preValidationHooks;
    // Permission hooks for this validation function.
    Bytes32DLL permissionHooks;
    // The set of selectors that may be validated by this validation function.
    Bytes4DLL selectors;
}

// execution detail associated with selector
struct ExecutionDetail {
    address plugin; // plugin address that implements the execution function, for native functions, the value should be
        // address(0)
    // Whether or not the function needs runtime validation, or can be called by anyone.
    // Note that even if this is set to true, user op validation will still be required, otherwise anyone could
    // drain the account of native tokens by wasting gas.
    bool skipRuntimeValidation;
    // Whether or not a global validation function may be used to validate this function.
    bool allowGlobalValidation;
    Bytes32DLL executionHooks;
}
