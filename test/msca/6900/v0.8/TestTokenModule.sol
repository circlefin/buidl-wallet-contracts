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

import {SIG_VALIDATION_SUCCEEDED} from "../../../../src/common/Constants.sol";

import {NotImplementedFunction} from "../../../../src/msca/6900/shared/common/Errors.sol";
import {
    ExecutionManifest,
    ManifestExecutionFunction,
    ManifestExecutionHook
} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";

import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";

import {BaseModule} from "../../../../src/msca/6900/v0.8/modules/BaseModule.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IExecutionModule} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";
import {console} from "forge-std/src/console.sol";

/**
 * @dev Module for tests only. This module implements everything in manifest.
 */
contract TestTokenModule is
    IValidationHookModule,
    IValidationModule,
    IExecutionHookModule,
    IExecutionModule,
    BaseModule
{
    event PreExecutionHookCalled(uint32 indexed entityId, address sender, uint256 value, bytes data);
    event PostExecutionHookCalled(uint32 indexed entityId, bytes preExecHookData);

    error InvalidSender(address addr);
    error InvalidReceiver(address addr);
    error InsufficientBalance(address addr, uint256 bal, uint256 value);

    enum EntityId {
        PRE_VALIDATION_HOOK_PASS1, // 0
        PRE_VALIDATION_HOOK_PASS2, // 1
        VALIDATION, // 2
        PRE_AND_POST_EXECUTION_HOOK, // 3
        PRE_PERMITTED_CALL_EXECUTION_HOOK, // 4
        POST_PERMITTED_CALL_EXECUTION_HOOK // 5

    }

    string public constant NAME = "Test Token Module";
    string public constant NOT_FROZEN_PERM = "NOT_FROZEN_PERM"; // msg.sender should be able to

    mapping(address => uint256) internal _balances;

    function transferToken(address to, uint256 value) external {
        _transferToken(to, value);
    }

    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }

    /// @inheritdoc IModule
    function onInstall(bytes calldata data) external override {
        // airdrop token
        _balances[msg.sender] = abi.decode(data, (uint256));
    }

    /// @inheritdoc IModule
    function onUninstall(bytes calldata data) external override {
        // reclaim token
        (address destination, uint256 value) = abi.decode(data, (address, uint256));
        _transferToken(destination, value);
        // destroy the remaining balance
        delete _balances[msg.sender];
    }

    /// @inheritdoc IValidationHookModule
    function preUserOpValidationHook(uint32 entityId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        pure
        override
        returns (uint256 validationData)
    {
        (userOp, userOpHash);
        if (entityId == uint32(EntityId.PRE_VALIDATION_HOOK_PASS1)) {
            return SIG_VALIDATION_SUCCEEDED;
        } else if (entityId == uint32(EntityId.PRE_VALIDATION_HOOK_PASS2)) {
            return SIG_VALIDATION_SUCCEEDED;
        }
        revert NotImplementedFunction(msg.sig, entityId);
    }

    /// @inheritdoc IValidationModule
    function validateUserOp(uint32 entityId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        pure
        override
        returns (uint256 validationData)
    {
        (userOp, userOpHash);
        if (entityId == uint32(EntityId.VALIDATION)) {
            return SIG_VALIDATION_SUCCEEDED;
        }
        revert NotImplementedFunction(msg.sig, entityId);
    }

    /// @inheritdoc IValidationHookModule
    function preRuntimeValidationHook(
        uint32 entityId,
        address sender,
        uint256 value,
        bytes calldata data,
        bytes calldata authorization
    ) external pure override {
        (authorization);
        (sender, value, data);
        if (entityId == uint32(EntityId.PRE_VALIDATION_HOOK_PASS1)) {
            return;
        } else if (entityId == uint32(EntityId.PRE_VALIDATION_HOOK_PASS2)) {
            return;
        }
        revert NotImplementedFunction(msg.sig, entityId);
    }

    /// @inheritdoc IValidationModule
    function validateRuntime(
        address account,
        uint32 entityId,
        address sender,
        uint256 value,
        bytes calldata data,
        bytes calldata authorization
    ) external pure override {
        (account, sender, value, data, authorization);
        if (entityId == uint8(EntityId.VALIDATION)) {
            return;
        }
        revert NotImplementedFunction(msg.sig, entityId);
    }

    /// @inheritdoc IValidationModule
    function validateSignature(address account, uint32 entityId, address, bytes32, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        (account);
        revert NotImplementedFunction(msg.sig, entityId);
    }

    /// @inheritdoc IExecutionHookModule
    function preExecutionHook(uint32 entityId, address sender, uint256 value, bytes calldata data)
        external
        override
        returns (bytes memory context)
    {
        console.logString("TestTokenModule.preExecutionHook data:");
        console.logBytes(data);
        emit PreExecutionHookCalled(entityId, sender, value, data);
        if (entityId == uint32(EntityId.PRE_AND_POST_EXECUTION_HOOK)) {
            return abi.encode(sender);
        } else if (entityId == uint32(EntityId.PRE_PERMITTED_CALL_EXECUTION_HOOK)) {
            return abi.encode(sender);
        }
        revert NotImplementedFunction(msg.sig, entityId);
    }

    /// @inheritdoc IExecutionHookModule
    function postExecutionHook(uint32 entityId, bytes calldata preExecHookData) external override {
        address sender = abi.decode(preExecHookData, (address));
        // do something about sender, we just log it here
        console.logString("TestTokenModule.postExecutionHook sender passed from preHook is: ");
        console.logAddress(sender);
        console.logString("entityId is: ");
        console.logUint(entityId);
        emit PostExecutionHookCalled(entityId, preExecHookData);
        if (entityId == uint32(EntityId.PRE_AND_POST_EXECUTION_HOOK)) {
            return;
        } else if (entityId == uint32(EntityId.POST_PERMITTED_CALL_EXECUTION_HOOK)) {
            return;
        }
        revert NotImplementedFunction(msg.sig, entityId);
    }

    function preSignatureValidationHook(uint32 entityId, address sender, bytes32 hash, bytes calldata signature)
        external
        pure
        override
    {
        (entityId, sender, hash, signature);
    }

    /// @inheritdoc IExecutionModule
    function executionManifest() external pure override returns (ExecutionManifest memory) {
        ExecutionManifest memory manifest;
        /// executionFunctions
        manifest.executionFunctions = new ManifestExecutionFunction[](2);
        // Execution functions defined in this module to be installed on the MSCA.
        manifest.executionFunctions[0] = ManifestExecutionFunction({
            executionSelector: this.transferToken.selector,
            skipRuntimeValidation: false,
            allowGlobalValidation: true
        });
        manifest.executionFunctions[1] = ManifestExecutionFunction({
            executionSelector: this.balanceOf.selector,
            skipRuntimeValidation: true,
            allowGlobalValidation: true
        });

        bytes4[] memory selectors = new bytes4[](manifest.executionFunctions.length);
        for (uint256 i = 0; i < manifest.executionFunctions.length; ++i) {
            selectors[i] = manifest.executionFunctions[i].executionSelector;
        }

        /// executionHooks
        manifest.executionHooks = new ManifestExecutionHook[](1);
        manifest.executionHooks[0] = ManifestExecutionHook({
            executionSelector: this.transferToken.selector,
            entityId: uint32(EntityId.PRE_AND_POST_EXECUTION_HOOK),
            isPreHook: true,
            isPostHook: true
        });
        return manifest;
    }

    function moduleId() external pure returns (string memory) {
        return "circle.token-test-module.2.0.0";
    }

    function _transferToken(address to, uint256 value) internal {
        // TODO: pass the from address the function param
        address from = msg.sender;
        if (from == address(0)) {
            revert InvalidSender(address(0));
        }
        if (to == address(0)) {
            revert InvalidReceiver(address(0));
        }
        uint256 fromBalance = _balances[from];
        if (fromBalance < value) {
            revert InsufficientBalance(from, fromBalance, value);
        }
        _balances[from] = fromBalance - value;
        _balances[to] += value;
    }
}
