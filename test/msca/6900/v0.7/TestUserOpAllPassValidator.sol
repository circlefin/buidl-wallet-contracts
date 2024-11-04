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

import {ValidationData} from "../../../../src/msca/6900/shared/common/Structs.sol";
import {PluginManifest} from "../../../../src/msca/6900/v0.7/common/PluginManifest.sol";
import {BasePlugin} from "../../../../src/msca/6900/v0.7/plugins/BasePlugin.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract TestUserOpAllPassValidator is BasePlugin {
    ValidationData expectedValidationData;

    constructor() {
        ValidationData memory expectToPass = ValidationData(0, 0xFFFFFFFFFFFF, address(0));
        expectedValidationData = expectToPass;
    }

    function onInstall(bytes calldata data) external pure override {
        (data);
    }

    function onUninstall(bytes calldata data) external pure override {
        (data);
    }

    /// @inheritdoc BasePlugin
    function userOpValidationFunction(uint8 functionId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256 validationData)
    {
        (functionId, userOp, userOpHash);
        return _packValidationData(expectedValidationData);
    }

    /// @inheritdoc BasePlugin
    function runtimeValidationFunction(uint8 functionId, address sender, uint256 value, bytes calldata data)
        external
        pure
        override
    {
        (functionId, sender, value, data);
        return;
    }

    function pluginManifest() external pure override returns (PluginManifest memory) {}

    /**
     * @dev Pack into the serialized format as validAfter | validUntil | authorizer.
     */
    function _packValidationData(ValidationData memory data) internal pure returns (uint256) {
        return uint160(data.authorizer) | (uint256(data.validUntil) << 160) | (uint256(data.validAfter) << (160 + 48));
    }
}
