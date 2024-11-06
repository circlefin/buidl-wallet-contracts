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

import {BaseModule} from "../../../../../src/msca/6900/v0.8/modules/BaseModule.sol";
import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";
import {
    ExecutionManifest,
    IExecutionModule,
    ManifestExecutionFunction,
    ManifestExecutionHook
} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {Test} from "forge-std/src/Test.sol";

/// @notice Inspired by Alchemy's implementation with modifications.
// Used within MSCACallFlowTest, see that file for details on usage.
contract MSCACallFlowModule is
    IValidationModule,
    IValidationHookModule,
    IExecutionModule,
    IExecutionHookModule,
    BaseModule,
    Test
{
    // Stored as a uint256 to make it easier to do the VM staticcall storage writes
    uint256[] public recordedFunctionCalls;

    error VMStaticCallFailed();

    function validateUserOp(uint32 entityId, PackedUserOperation calldata, bytes32) external returns (uint256) {
        recordedFunctionCalls.push(uint256(entityId));
        return 0;
    }

    function validateRuntime(address, uint32 entityId, address, uint256, bytes calldata, bytes calldata) external {
        recordedFunctionCalls.push(uint256(entityId));
    }

    function validateSignature(address, uint32 entityId, address, bytes32, bytes calldata)
        external
        view
        returns (bytes4)
    {
        recordCallInView(entityId);
        return IERC1271.isValidSignature.selector;
    }

    function preUserOpValidationHook(uint32 entityId, PackedUserOperation calldata, bytes32)
        external
        returns (uint256)
    {
        recordedFunctionCalls.push(uint256(entityId));
        return 0;
    }

    function preRuntimeValidationHook(uint32 entityId, address, uint256, bytes calldata, bytes calldata) external {
        recordedFunctionCalls.push(uint256(entityId));
    }

    function preSignatureValidationHook(uint32 entityId, address, bytes32, bytes calldata) external view {
        recordCallInView(entityId);
    }

    function preExecutionHook(uint32 entityId, address, uint256, bytes calldata) external returns (bytes memory) {
        recordedFunctionCalls.push(uint256(entityId));
        return "";
    }

    function postExecutionHook(uint32 entityId, bytes calldata) external {
        recordedFunctionCalls.push(uint256(entityId));
    }

    // solhint-disable-next-line no-empty-blocks
    function onInstall(bytes calldata) external override {}

    // solhint-disable-next-line no-empty-blocks
    function onUninstall(bytes calldata) external override {}

    function foo(uint32 index) external {
        recordedFunctionCalls.push(index);
    }

    function getRecordedFunctionCalls() external view returns (uint256[] memory) {
        return recordedFunctionCalls;
    }

    function moduleId() external pure returns (string memory) {
        return "circle.msca-call-flow-module.2.0.0";
    }

    // Does not return any execution hooks, the caller should add any requested execution hooks prior to calling
    // `installExecution` with the desired entity IDs.
    function executionManifest() external pure returns (ExecutionManifest memory) {
        ManifestExecutionFunction[] memory executionFunctions = new ManifestExecutionFunction[](1);
        executionFunctions[0] = ManifestExecutionFunction({
            executionSelector: this.foo.selector,
            skipRuntimeValidation: false,
            allowGlobalValidation: false
        });

        return ExecutionManifest({
            executionFunctions: executionFunctions,
            executionHooks: new ManifestExecutionHook[](0),
            interfaceIds: new bytes4[](0)
        });
    }

    // Normally we can't write to storage within a staticcall, so the signature validation and signature validation
    // hooks would be unable to record their access order. However, we can use the VM cheat code to write to
    // storage even in a view context, so we can record the order of function calls.
    function recordCallInView(uint32 entityId) private view {
        uint256 slotU;
        bytes32 slot;
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            slotU := recordedFunctionCalls.slot
            mstore(0x0, slotU)
            slot := mload(0x0)
        }
        // CommonBase.VM_ADDRESS
        (bool success, bytes memory returnData) = VM_ADDRESS.staticcall(abi.encodeCall(vm.load, (address(this), slot)));
        if (!success) revert VMStaticCallFailed();

        uint256 length = uint256(bytes32(returnData));
        (success,) = VM_ADDRESS.staticcall(abi.encodeCall(vm.store, (address(this), slot, bytes32(length + 1))));
        if (!success) revert VMStaticCallFailed();

        bytes32 dataSlot = keccak256(abi.encode(slot));
        (success,) = VM_ADDRESS.staticcall(
            abi.encodeCall(vm.store, (address(this), bytes32(uint256(dataSlot) + length), bytes32(uint256(entityId))))
        );
        if (!success) revert VMStaticCallFailed();
    }
}
