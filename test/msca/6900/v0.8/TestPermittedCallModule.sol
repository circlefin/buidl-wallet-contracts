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

import {
    ExecutionManifest,
    ManifestExecutionFunction
} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";

import {BaseModule} from "../../../../src/msca/6900/v0.8/modules/BaseModule.sol";
import {FooBarModule} from "./FooBarModule.sol";
import {IExecutionModule} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";

/**
 * @dev Module for tests only. This module demos permitted call.
 */
contract TestPermittedCallModule is IExecutionModule, BaseModule {
    string public constant NAME = "Test Permitted Call Module";

    // solhint-disable-next-line no-empty-blocks
    function onInstall(bytes calldata) external override {}

    // solhint-disable-next-line no-empty-blocks
    function onUninstall(bytes calldata) external override {}

    // "foo" can skip runtime validation
    function permittedCallAllowed() external view returns (bytes memory) {
        return abi.encode(FooBarModule(msg.sender).foo());
    }

    // "bar" cannot skip runtime validation, so this should revert.
    function permittedCallNotAllowed() external view returns (bytes memory) {
        return abi.encode(FooBarModule(msg.sender).bar());
    }

    /// @inheritdoc IExecutionModule
    function executionManifest() external pure override returns (ExecutionManifest memory) {
        ExecutionManifest memory manifest;
        manifest.executionFunctions = new ManifestExecutionFunction[](2);
        manifest.executionFunctions[0].executionSelector = this.permittedCallAllowed.selector;
        manifest.executionFunctions[1].executionSelector = this.permittedCallNotAllowed.selector;

        for (uint256 i = 0; i < manifest.executionFunctions.length; i++) {
            manifest.executionFunctions[i].skipRuntimeValidation = true;
        }
        return manifest;
    }

    function moduleId() external pure returns (string memory) {
        return "circle.permitted-call-test-module.2.0.0";
    }
}
