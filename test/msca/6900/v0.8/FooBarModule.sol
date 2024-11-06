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
    ManifestExecutionFunction
} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";

import {BaseModule} from "../../../../src/msca/6900/v0.8/modules/BaseModule.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IExecutionModule} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";

contract FooBarModule is IValidationModule, IExecutionModule, BaseModule {
    string public constant NAME = "Your Favourite Fruit Bar Module";

    enum EntityId {
        VALIDATION
    }

    // solhint-disable-next-line no-empty-blocks
    function onInstall(bytes calldata) external override {}

    // solhint-disable-next-line no-empty-blocks
    function onUninstall(bytes calldata) external override {}

    function foo() external pure returns (bytes32) {
        return keccak256("foo");
    }

    function bar() external pure returns (bytes32) {
        return keccak256("bar");
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

    function executionManifest() external pure override returns (ExecutionManifest memory) {
        ExecutionManifest memory manifest;
        manifest.executionFunctions = new ManifestExecutionFunction[](2);
        manifest.executionFunctions[0] = ManifestExecutionFunction({
            executionSelector: this.foo.selector,
            skipRuntimeValidation: true,
            allowGlobalValidation: false
        });
        manifest.executionFunctions[1] = ManifestExecutionFunction({
            executionSelector: this.bar.selector,
            skipRuntimeValidation: false,
            allowGlobalValidation: false
        });
        return manifest;
    }

    function moduleId() external pure returns (string memory) {
        return "circle.foo-bar-test-module.2.0.0";
    }
}
