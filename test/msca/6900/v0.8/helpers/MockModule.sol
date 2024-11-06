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

import {EIP1271_INVALID_SIGNATURE, EIP1271_VALID_SIGNATURE} from "../../../../../src/common/Constants.sol";

import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";
import {ExecutionManifest} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";

import {BaseModule} from "../../../../../src/msca/6900/v0.8/modules/BaseModule.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";

/// @author Inspired by 6900 reference implementation of MockModule.
contract MockModule is BaseModule, IExecutionHookModule, IValidationModule, IValidationHookModule {
    // It's super inefficient to hold the entire abi-encoded manifest in storage, but this is fine since it's
    // just a mock. Note that the reason we do this is to allow copying the entire contents of the manifest
    // into storage in a single line, since solidity fails to compile with memory -> storage copying of nested
    // dynamic types when compiling without `via-ir` in the lite profile.
    // See the error code below:
    // Error: Unimplemented feature (/solidity/libsolidity/codegen/ArrayUtils.cpp:228):Copying of type
    // struct ManifestAssociatedFunction memory[] memory to storage not yet supported.
    bytes internal _executionManifest;
    uint256 internal _validateUserOpRetValue;
    bool internal _validateRuntimePass;
    bool internal _validateSignaturePass;
    bytes internal _preExecutionHookRetValue;
    bool internal _postExecutionHookPass;
    uint256 internal _preUserOpValidationHookRetValue;
    bool internal _preRuntimeValidationHookPass;
    uint8 internal constant FLAG_TO_PASS = uint8(0);

    event ReceivedCall(bytes msgData);
    event Installed(bytes data);
    event Uninstalled(bytes data);

    error RuntimeValidationFailed();
    error PreRuntimeValidationHookFailed();
    error PostExecutionHookFailed();
    error PreSignatureValidationHookFailed();

    constructor(
        ExecutionManifest memory execManifest,
        uint256 validateUserOpRetValue,
        bool validateRuntimePass,
        bool validateSignaturePass,
        bytes memory preExecutionHookRetValue,
        bool postExecutionHookPass,
        uint256 preUserOpValidationHookRetValue,
        bool preRuntimeValidationHookPass
    ) {
        _executionManifest = abi.encode(execManifest);
        _validateUserOpRetValue = validateUserOpRetValue;
        _validateRuntimePass = validateRuntimePass;
        _validateSignaturePass = validateSignaturePass;
        _preExecutionHookRetValue = preExecutionHookRetValue;
        _postExecutionHookPass = postExecutionHookPass;
        _preUserOpValidationHookRetValue = preUserOpValidationHookRetValue;
        _preRuntimeValidationHookPass = preRuntimeValidationHookPass;
    }

    function testFoo() external {
        // This function is used to test the module's ability to receive calls.
        emit ReceivedCall(msg.data);
    }

    function onInstall(bytes calldata data) external {
        emit Installed(data);
    }

    function onUninstall(bytes calldata data) external {
        emit Uninstalled(data);
    }

    function preUserOpValidationHook(uint32, PackedUserOperation calldata, bytes32) external returns (uint256) {
        emit ReceivedCall(msg.data);
        return _preUserOpValidationHookRetValue;
    }

    function preRuntimeValidationHook(uint32, address, uint256, bytes calldata, bytes calldata) external {
        emit ReceivedCall(msg.data);
        if (_preRuntimeValidationHookPass) {
            return;
        }
        revert PreRuntimeValidationHookFailed();
    }

    function validateUserOp(uint32, PackedUserOperation calldata, bytes32) external returns (uint256) {
        emit ReceivedCall(msg.data);
        return _validateUserOpRetValue;
    }

    function validateRuntime(address, uint32, address, uint256, bytes calldata, bytes calldata) external {
        emit ReceivedCall(msg.data);
        if (_validateRuntimePass) {
            return;
        }
        revert RuntimeValidationFailed();
    }

    function validateSignature(address, uint32, address, bytes32, bytes calldata) external view returns (bytes4) {
        if (_validateSignaturePass) {
            return EIP1271_VALID_SIGNATURE;
        }
        return EIP1271_INVALID_SIGNATURE;
    }

    function preExecutionHook(uint32, address, uint256, bytes calldata) external returns (bytes memory) {
        emit ReceivedCall(msg.data);
        return _preExecutionHookRetValue;
    }

    function postExecutionHook(uint32, bytes calldata) external {
        emit ReceivedCall(msg.data);
        if (!_postExecutionHookPass) {
            revert PostExecutionHookFailed();
        }
    }

    function preSignatureValidationHook(uint32 entityId, address sender, bytes32 hash, bytes calldata signature)
        external
        pure
        override
    {
        (entityId, sender, hash);
        if (signature.length == 0) {
            return;
        }
        uint8 flag = abi.decode(signature, (uint8));
        if (flag == FLAG_TO_PASS) {
            return;
        }
        revert PreSignatureValidationHookFailed();
    }

    function executionManifest() external pure returns (ExecutionManifest memory) {
        return _castToPure(_getManifest)();
    }

    function moduleId() external pure returns (string memory) {
        return "circle.mock-test-module.2.0.0";
    }

    function _getManifest() internal view returns (ExecutionManifest memory) {
        return abi.decode(_executionManifest, (ExecutionManifest));
    }

    function _castToPure(function() internal view returns (ExecutionManifest memory) fnIn)
        internal
        pure
        returns (function() internal pure returns (ExecutionManifest memory) fnOut)
    {
        /* solhint-disable no-inline-assembly */
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }
}
