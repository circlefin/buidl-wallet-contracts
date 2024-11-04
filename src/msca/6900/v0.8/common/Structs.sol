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
import {ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

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

/// @notice Represents stored data associated with a specific validation function.
struct ValidationStorage {
    // Whether or not this validation can be used as a global validation function.
    bool isGlobal;
    // Whether or not this validation is allowed to validate ERC-1271 signatures.
    bool isSignatureValidation;
    // Whether or not this validation is allowed to validate ERC-4337 user operations.
    bool isUserOpValidation;
    // The validation hooks for this validation function.
    Bytes32DLL validationHooks;
    // Execution hooks to run with this validation function.
    Bytes32DLL executionHooks;
    // The set of selectors that may be validated by this validation function.
    Bytes4DLL selectors;
}

/// @notice Represents stored data associated with a specific function selector.
struct ExecutionStorage {
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
