/*
 * Copyright 2025 Circle Internet Group, Inc. All rights reserved.

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

import {AddressDLL} from "../../../../../src/msca/6900/shared/common/Structs.sol";
import {AddressDLLLib} from "../../../../../src/msca/6900/shared/libs/AddressDLLLib.sol";
import {TestUtils} from "../../../../util/TestUtils.sol";
import {TestAddressDLL} from "./TestAddressDLL.sol";

contract AddressDLLLibTest is TestUtils {
    address internal constant SENTINEL_ADDRESS = address(0x0);

    using AddressDLLLib for AddressDLL;

    function testSentinelAddress() public {
        TestAddressDLL dll = new TestAddressDLL();
        assertEq(dll.getHead(), SENTINEL_ADDRESS);
        assertEq(dll.getTail(), SENTINEL_ADDRESS);
        // sentinel should not considered as the value of the list
        assertFalse(dll.contains(SENTINEL_ADDRESS));
        // add one item
        assertTrue(dll.append(address(1)));
        // sentinel should not considered as the value of the list
        assertFalse(dll.contains(SENTINEL_ADDRESS));
    }

    function testAddRemoveGetAddressValues() public {
        TestAddressDLL values = new TestAddressDLL();
        assertEq(values.size(), 0);
        assertEq(values.getAll().length, 0);
        // try to remove sentinel stupidly
        bytes4 errorSelector = bytes4(keccak256("InvalidAddress()"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector));
        values.remove(SENTINEL_ADDRESS);
        assertEq(values.getHead(), SENTINEL_ADDRESS);
        assertEq(values.getTail(), SENTINEL_ADDRESS);
        // sentinel doesn't count
        assertEq(values.size(), 0);
        address value1 = address(1);
        address value2 = address(2);
        address value3 = address(3);
        address value4 = address(4);
        assertTrue(values.append(value1));
        assertTrue(values.contains(value1));
        assertEq(values.getHead(), value1);
        assertEq(values.getTail(), value1);
        // remove it
        assertTrue(values.remove(value1));
        assertEq(values.size(), 0);
        assertEq(values.getHead(), SENTINEL_ADDRESS);
        assertEq(values.getTail(), SENTINEL_ADDRESS);
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
        address[] memory results = values.getAll();
        assertEq(results.length, 4);
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
        assertEq(values.getHead(), SENTINEL_ADDRESS);
        assertEq(values.getTail(), SENTINEL_ADDRESS);
        // now remove value2 again, should revert
        errorSelector = bytes4(keccak256("ItemDoesNotExist()"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector));
        values.remove(value2);
        // get zero value every time
        errorSelector = bytes4(keccak256("InvalidLimit()"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector));
        values.getPaginated(SENTINEL_ADDRESS, 0);
    }

    function testFuzz_bulkGetAddresses(uint8 limit, uint8 totalValues) public {
        // try out different limits, even bigger than totalValues
        bound(limit, 1, 30);
        bound(totalValues, 3, 30);
        TestAddressDLL dll = new TestAddressDLL();
        for (uint32 i = 1; i <= totalValues; i++) {
            dll.append(address(uint160(i)));
        }
        bulkGetAndVerifyAddresses(dll, totalValues, limit);
    }

    function bulkGetAndVerifyAddresses(TestAddressDLL dll, uint256 totalValues, uint256 limit) private view {
        address[] memory results = new address[](totalValues);
        address start = SENTINEL_ADDRESS;
        uint32 count = 0;
        uint256 j = 0;
        address[] memory values;
        address next;
        while (count < totalValues && limit != 0) {
            (values, next) = dll.getPaginated(start, limit);
            for (uint256 i = 0; i < values.length; ++i) {
                results[count] = values[i];
                // starts from address(1)
                assertEq(results[j], address(uint160(count + 1)));
                count++;
                j++;
            }
            if (next == SENTINEL_ADDRESS) {
                break;
            }
            start = next;
        }
    }
}
