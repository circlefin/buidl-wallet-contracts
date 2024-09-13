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

import {NotImplementedFunction} from "../../../../src/msca/6900/shared/common/Errors.sol";
import {ValidationData} from "../../../../src/msca/6900/shared/common/Structs.sol";

import {PluginManifest, PluginMetadata} from "../../../../src/msca/6900/v0.8/common/PluginManifest.sol";
import {IPlugin} from "../../../../src/msca/6900/v0.8/interfaces/IPlugin.sol";
import {IValidation} from "../../../../src/msca/6900/v0.8/interfaces/IValidation.sol";
import {BasePlugin} from "../../../../src/msca/6900/v0.8/plugins/BasePlugin.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract TestUserOpValidator is IValidation, BasePlugin {
    ValidationData private expectedValidationData;

    // solhint-disable-next-line func-visibility
    constructor(ValidationData memory _expectedValidationData) {
        expectedValidationData = _expectedValidationData;
    }

    /// @inheritdoc IPlugin
    function onInstall(bytes calldata data) external pure override {
        (data);
    }

    /// @inheritdoc IPlugin
    function onUninstall(bytes calldata data) external pure override {
        (data);
    }

    /// @inheritdoc IPlugin
    function pluginManifest() external pure returns (PluginManifest memory) {
        revert NotImplementedFunction(msg.sig, 0);
    }

    /// @inheritdoc IPlugin
    function pluginMetadata() external pure returns (PluginMetadata memory) {
        revert NotImplementedFunction(msg.sig, 0);
    }

    /// @inheritdoc IValidation
    function validateUserOp(uint32 entityId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256 validationData)
    {
        (entityId, userOp, userOpHash);
        return _packValidationData(expectedValidationData);
    }

    /// @inheritdoc IValidation
    function validateRuntime(
        address account,
        uint32 entityId,
        address sender,
        uint256 value,
        bytes calldata data,
        bytes calldata authorization
    ) external pure override {
        (sender, value, data, authorization);
        revert NotImplementedFunction(msg.sig, entityId);
    }

    /// @inheritdoc IValidation
    function validateSignature(address account, uint32 entityId, address, bytes32, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        revert NotImplementedFunction(msg.sig, entityId);
    }

    /**
     * @dev Pack into the serialized format as validAfter | validUntil | authorizer.
     */
    function _packValidationData(ValidationData memory data) internal pure returns (uint256) {
        return uint160(data.authorizer) | (uint256(data.validUntil) << 160) | (uint256(data.validAfter) << (160 + 48));
    }
}
