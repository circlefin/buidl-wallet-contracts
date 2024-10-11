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
import {HookConfig, ModuleEntity} from "./Types.sol";

// Standard executor
struct Call {
    // The target address for the account to call.
    address target;
    // The value to send with the call.
    uint256 value;
    // The calldata for the call.
    bytes data;
}

struct PostExecHookToRun {
    bytes preExecHookReturnData;
    ModuleEntity postExecHook;
}

struct ValidationDetail {
    // Whether or not this validation can be used as a global validation function.
    bool isGlobal;
    // Whether or not this validation is allowed to validate ERC-1271 signatures.
    bool isSignatureValidation;
    // Whether or not this validation is allowed to validate ERC-4337 user operations.
    bool isUserOpValidation;
    // The validation hooks for this validation function.
    HookConfig[] validationHooks;
    // Execution hooks to run with this validation function.
    Bytes32DLL executionHooks;
    // The set of selectors that may be validated by this validation function.
    Bytes4DLL selectors;
}

// execution detail associated with selector
struct ExecutionDetail {
    address module; // module address that implements the execution function, for native functions, the value should be
        // address(0)
    // Whether or not the function needs runtime validation, or can be called by anyone.
    // Note that even if this is set to true, user op validation will still be required, otherwise anyone could
    // drain the account of native tokens by wasting gas.
    bool skipRuntimeValidation;
    // Whether or not a global validation function may be used to validate this function.
    bool allowGlobalValidation;
    Bytes32DLL executionHooks;
}

// Represents data associated with a specific function selector.
struct ExecutionDataView {
    // The module that implements this execution function.
    // If this is a native function, the address must remain address(0).
    address module;
    // Whether or not the function needs runtime validation, or can be called by anyone. The function can still be
    // state changing if this flag is set to true.
    // Note that even if this is set to true, user op validation will still be required, otherwise anyone could
    // drain the account of native tokens by wasting gas.
    bool skipRuntimeValidation;
    // Whether or not a global validation function may be used to validate this function.
    bool allowGlobalValidation;
    // The execution hooks for this function selector.
    HookConfig[] executionHooks;
}

// Represents data associated with a specific validation function.
struct ValidationDataView {
    // Whether or not this validation can be used as a global validation function.
    bool isGlobal;
    // Whether or not this validation is a ERC-1271 signature validation function.
    bool isSignatureValidation;
    // Whether or not this validation function is a user operation validation function.
    bool isUserOpValidation;
    // The validation hooks for this validation function.
    HookConfig[] validationHooks;
    // Execution hooks to run with this validation function.
    HookConfig[] executionHooks;
    // The set of selectors that may be validated by this validation function.
    bytes4[] selectors;
}
