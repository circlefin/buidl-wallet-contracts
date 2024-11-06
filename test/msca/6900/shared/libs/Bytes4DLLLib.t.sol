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

/* solhint-disable one-contract-per-file */

import {SENTINEL_BYTES4} from "../../../../../src/common/Constants.sol";
import {Bytes4DLL} from "../../../../../src/msca/6900/shared/common/Structs.sol";
import {Bytes4DLLLib} from "../../../../../src/msca/6900/shared/libs/Bytes4DLLLib.sol";
import {TestUtils} from "../../../../util/TestUtils.sol";

contract TestDLL {
    using Bytes4DLLLib for Bytes4DLL;

    Bytes4DLL private bytes4DLL;

    function append(bytes4 valueToAdd) external returns (bool) {
        return bytes4DLL.append(valueToAdd);
    }

    function remove(bytes4 valueToRemove) external returns (bool) {
        return bytes4DLL.remove(valueToRemove);
    }

    function size() external view returns (uint256) {
        return bytes4DLL.size();
    }

    function contains(bytes4 value) external view returns (bool) {
        return bytes4DLL.contains(value);
    }

    function getAll() external view returns (bytes4[] memory results) {
        return bytes4DLL.getAll();
    }

    function getPaginated(bytes4 start, uint256 limit) external view returns (bytes4[] memory results, bytes4 next) {
        return bytes4DLL.getPaginated(start, limit);
    }

    function getHead() external view returns (bytes4) {
        return bytes4DLL.getHead();
    }

    function getTail() external view returns (bytes4) {
        return bytes4DLL.getTail();
    }
}

contract Bytes4DLLLibTest is TestUtils {
    using Bytes4DLLLib for Bytes4DLL;

    function testAddRemoveGetBytes4Values() public {
        TestDLL values = new TestDLL();
        // sentinel value is initialized
        assertEq(values.size(), 0);
        // try to remove sentinel stupidly
        bytes4 errorSelector = bytes4(keccak256("InvalidBytes4()"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector));
        values.remove(SENTINEL_BYTES4);
        assertEq(values.getHead(), SENTINEL_BYTES4);
        assertEq(values.getTail(), SENTINEL_BYTES4);
        // sentinel doesn't count
        assertEq(values.size(), 0);
        bytes4 value1 = 0x11111111;
        bytes4 value2 = 0x22222222;
        bytes4 value3 = 0x33333333;
        bytes4 value4 = 0x44444444;
        assertTrue(values.append(value1));
        assertTrue(values.contains(value1));
        assertEq(values.getHead(), value1);
        assertEq(values.getTail(), value1);
        // remove it
        assertTrue(values.remove(value1));
        assertEq(values.size(), 0);
        assertEq(values.getHead(), SENTINEL_BYTES4);
        assertEq(values.getTail(), SENTINEL_BYTES4);
        assertFalse(values.contains(value1));
        // add value1 and value2
        assertTrue(values.append(value1));
        assertTrue(values.append(value2));
        assertEq(values.size(), 2);
        assertEq(values.getHead(), value1);
        assertEq(values.getTail(), value2);
        // now remove value2
        assertTrue(values.remove(value2));
        assertEq(values.getHead(), value1);
        assertEq(values.getTail(), value1);
        // now add back value2 with three more values
        assertTrue(values.append(value2));
        assertTrue(values.append(value3));
        assertTrue(values.append(value4));
        assertEq(values.size(), 4);
        assertEq(values.getHead(), value1);
        assertEq(values.getTail(), value4);
        bytes4[] memory results = values.getAll();
        assertEq(results[0], value1);
        assertEq(results[1], value2);
        assertEq(results[2], value3);
        assertEq(results[3], value4);
        // now remove value1
        assertTrue(values.remove(value1));
        assertEq(values.size(), 3);
        assertEq(values.getHead(), value2);
        assertEq(values.getTail(), value4);
        // now remove value4
        assertTrue(values.remove(value4));
        assertEq(values.size(), 2);
        assertEq(values.getHead(), value2);
        assertEq(values.getTail(), value3);
        // now remove value3
        assertTrue(values.remove(value3));
        assertEq(values.size(), 1);
        assertEq(values.getHead(), value2);
        assertEq(values.getTail(), value2);
        // now remove value2
        assertTrue(values.remove(value2));
        assertEq(values.size(), 0);
        assertEq(values.getHead(), SENTINEL_BYTES4);
        assertEq(values.getTail(), SENTINEL_BYTES4);
        // now remove value2 again, should revert
        errorSelector = bytes4(keccak256("ItemDoesNotExist()"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector));
        values.remove(value2);
        // get zero value every time
        errorSelector = bytes4(keccak256("InvalidLimit()"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector));
        values.getPaginated(SENTINEL_BYTES4, 0);
    }

    function testFuzz_bulkGetValues(uint8 limit, uint8 totalValues) public {
        // try out different limits, even bigger than totalValues
        bound(limit, 1, 30);
        bound(totalValues, 3, 30);
        TestDLL dll = new TestDLL();
        for (uint32 i = 1; i <= totalValues; i++) {
            dll.append(bytes4(i));
        }
        bulkGetAndVerifyValues(dll, totalValues, limit);
    }

    function bulkGetAndVerifyValues(TestDLL dll, uint256 totalValues, uint256 limit) private view {
        bytes4[] memory results = new bytes4[](totalValues);
        bytes4 start = SENTINEL_BYTES4;
        uint32 count = 0;
        uint256 j = 0;
        bytes4[] memory values;
        bytes4 next;
        while (count < totalValues && limit != 0) {
            (values, next) = dll.getPaginated(start, limit);
            for (uint256 i = 0; i < values.length; ++i) {
                results[count] = values[i];
                // starts from bytes4(1)
                assertEq(results[j], bytes4(count + 1));
                count++;
                j++;
            }
            if (next == SENTINEL_BYTES4) {
                break;
            }
            start = next;
        }
    }
}
