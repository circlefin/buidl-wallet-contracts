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

import {ValidationData} from "../common/Structs.sol";

library ValidationDataLib {
    error WrongTimeBounds();

    /**
     * @dev Intercept the time bounds [validAfter, validUntil], as well as signature validation result (favoring the
     * failure).
     */
    function _intersectValidationData(ValidationData memory a, uint256 uintb)
        internal
        pure
        returns (ValidationData memory validationData)
    {
        ValidationData memory b = _unpackValidationData(uintb);
        if (a.validAfter > a.validUntil) {
            revert WrongTimeBounds();
        }
        if (b.validAfter > b.validUntil) {
            revert WrongTimeBounds();
        }
        // 0 is successful validation
        if (a.authorizer == address(0)) {
            validationData.authorizer = b.authorizer;
        } else {
            validationData.authorizer = a.authorizer;
        }
        if (a.validAfter > b.validAfter) {
            validationData.validAfter = a.validAfter;
        } else {
            validationData.validAfter = b.validAfter;
        }
        if (a.validUntil < b.validUntil) {
            validationData.validUntil = a.validUntil;
        } else {
            validationData.validUntil = b.validUntil;
        }
        // make sure the caller (e.g. entryPoint) reverts
        if (validationData.validAfter >= validationData.validUntil) {
            validationData.authorizer = address(1);
        }
        return validationData;
    }

    /**
     * @dev Unpack into the deserialized packed format from validAfter | validUntil | authorizer.
     */
    function _unpackValidationData(uint256 validationDataInt)
        internal
        pure
        returns (ValidationData memory validationData)
    {
        address authorizer = address(uint160(validationDataInt));
        uint48 validUntil = uint48(validationDataInt >> 160);
        if (validUntil == 0) {
            validUntil = type(uint48).max;
        }
        uint48 validAfter = uint48(validationDataInt >> (48 + 160));
        return ValidationData(validAfter, validUntil, authorizer);
    }

    function _packValidationData(ValidationData memory data) internal pure returns (uint256) {
        return uint160(data.authorizer) | (uint256(data.validUntil) << 160) | (uint256(data.validAfter) << (160 + 48));
    }
}
