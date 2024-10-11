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
import {BasePlugin} from "../../../../src/msca/6900/v0.7/plugins/BasePlugin.sol";
import {UserOperation} from "@account-abstraction/contracts/interfaces/UserOperation.sol";

contract TestUserOpValidator is BasePlugin {
    ValidationData private expectedValidationData;

    // solhint-disable-next-line func-visibility
    constructor(ValidationData memory _expectedValidationData) {
        expectedValidationData = _expectedValidationData;
    }

    /// @inheritdoc BasePlugin
    function userOpValidationFunction(uint8 functionId, UserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256 validationData)
    {
        (functionId, userOp, userOpHash);
        return _packValidationData(expectedValidationData);
    }

    /**
     * @dev Pack into the serialized format as validAfter | validUntil | authorizer.
     */
    function _packValidationData(ValidationData memory data) internal pure returns (uint256) {
        return uint160(data.authorizer) | (uint256(data.validUntil) << 160) | (uint256(data.validAfter) << (160 + 48));
    }
}
