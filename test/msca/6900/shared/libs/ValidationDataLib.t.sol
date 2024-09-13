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

import {TestUtils} from "../../../../util/TestUtils.sol";
import {ValidationDataLib} from "../../../../../src/msca/6900/shared/libs/ValidationDataLib.sol";
import {ValidationData} from "../../../../../src/msca/6900/shared/common/Structs.sol";

contract ValidationDataLibTest is TestUtils {
    using ValidationDataLib for ValidationData;
    using ValidationDataLib for uint256;

    error WrongTimeBounds();

    function testIntersectWrongTimeBounds_a() public {
        ValidationData memory a = ValidationData({validAfter: 2, validUntil: 1, authorizer: address(0)});
        ValidationData memory b = ValidationData({validAfter: 1, validUntil: 2, authorizer: address(0)});
        uint256 bUint = b._packValidationData();
        vm.expectRevert(WrongTimeBounds.selector);
        a._intersectValidationData(bUint);
    }

    function testIntersectWrongTimeBounds_b() public {
        ValidationData memory a = ValidationData({validAfter: 1, validUntil: 2, authorizer: address(0)});
        ValidationData memory b = ValidationData({validAfter: 2, validUntil: 1, authorizer: address(0)});
        uint256 bUint = b._packValidationData();
        vm.expectRevert(WrongTimeBounds.selector);
        a._intersectValidationData(bUint);
    }

    // address(0) is good
    function testIntersectBadAuthorizer_a() public pure {
        ValidationData memory a = ValidationData({validAfter: 1, validUntil: 2, authorizer: address(1)});
        ValidationData memory b = ValidationData({validAfter: 1, validUntil: 2, authorizer: address(0)});
        uint256 bUint = b._packValidationData();
        ValidationData memory result = a._intersectValidationData(bUint);
        assertEq(result.validAfter, 1);
        assertEq(result.validUntil, 2);
        assertEq(result.authorizer, address(1));
    }

    function testIntersectBadAuthorizer_b() public pure {
        ValidationData memory a = ValidationData({validAfter: 1, validUntil: 2, authorizer: address(0)});
        ValidationData memory b = ValidationData({validAfter: 1, validUntil: 2, authorizer: address(1)});
        uint256 bUint = b._packValidationData();
        ValidationData memory result = a._intersectValidationData(bUint);
        assertEq(result.validAfter, 1);
        assertEq(result.validUntil, 2);
        assertEq(result.authorizer, address(1));
    }

    function testIntersect_equal() public pure {
        ValidationData memory a = ValidationData({validAfter: 1, validUntil: 3, authorizer: address(0)});
        ValidationData memory b = ValidationData({validAfter: 3, validUntil: 5, authorizer: address(0)});
        uint256 bUint = b._packValidationData();
        ValidationData memory result = a._intersectValidationData(bUint);
        assertEq(result.validAfter, 3);
        assertEq(result.validUntil, 3);
        assertEq(result.authorizer, address(1));
    }

    function testIntersect_noOverlap() public pure {
        ValidationData memory a = ValidationData({validAfter: 1, validUntil: 2, authorizer: address(0)});
        ValidationData memory b = ValidationData({validAfter: 3, validUntil: 4, authorizer: address(0)});
        uint256 bUint = b._packValidationData();
        ValidationData memory result = a._intersectValidationData(bUint);
        assertEq(result.validAfter, 3);
        assertEq(result.validUntil, 2);
        assertEq(result.authorizer, address(1));
    }
}
