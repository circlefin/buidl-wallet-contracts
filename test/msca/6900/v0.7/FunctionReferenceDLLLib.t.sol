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

import {SENTINEL_BYTES21} from "../../../../src/common/Constants.sol";

import {FunctionReference} from "../../../../src/msca/6900/v0.7/common/Structs.sol";
import {FunctionReferenceLib} from "../../../../src/msca/6900/v0.7/libs/FunctionReferenceLib.sol";
import {TestUtils} from "../../../util/TestUtils.sol";
import {TestFunctionReferenceDLL} from "./TestFunctionReferenceDLL.sol";

contract FunctionReferenceDLLibTest is TestUtils {
    using FunctionReferenceLib for bytes21;
    using FunctionReferenceLib for FunctionReference;

    function testSentinelFunctionReference() public {
        TestFunctionReferenceDLL dll = new TestFunctionReferenceDLL();
        assertEq(dll.getFirst().pack(), SENTINEL_BYTES21);
        assertEq(dll.getLast().pack(), SENTINEL_BYTES21);
        // sentinel should not considered as the value of the list
        assertFalse(dll.contains(SENTINEL_BYTES21.unpack()));
        // add one item
        assertTrue(dll.append(FunctionReference(address(0x123), 0)));
        // sentinel should not considered as the value of the list
        assertFalse(dll.contains(SENTINEL_BYTES21.unpack()));
    }

    function testAddRemoveGetFunctionReferences() public {
        TestFunctionReferenceDLL dll = new TestFunctionReferenceDLL();
        assertEq(dll.getAll().length, 0);
        // try to remove sentinel stupidly
        bytes4 errorSelector = bytes4(keccak256("InvalidFunctionReference()"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector));
        dll.remove(SENTINEL_BYTES21.unpack());
        assertEq(dll.getFirst().pack(), SENTINEL_BYTES21);
        assertEq(dll.getLast().pack(), SENTINEL_BYTES21);
        // sentinel doesn't count
        assertEq(dll.getSize(), 0);
        FunctionReference memory fr123 = FunctionReference(address(0x123), 0);
        FunctionReference memory fr456 = FunctionReference(address(0x456), 0);
        FunctionReference memory fr789 = FunctionReference(address(0x789), 0);
        FunctionReference memory frabc = FunctionReference(address(0xabc), 0);
        assertTrue(dll.append(fr123));
        assertEq(dll.getFirst().pack(), fr123.pack());
        assertEq(dll.getLast().pack(), fr123.pack());
        // try to add the same function reference again, should revert
        errorSelector = bytes4(keccak256("ItemAlreadyExists()"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector));
        dll.append(fr123);
        // now remove it
        assertTrue(dll.remove(fr123));
        // remove it again, should revert
        errorSelector = bytes4(keccak256("ItemDoesNotExist()"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector));
        dll.remove(fr123);
        // add fr123 back with one more fr
        assertTrue(dll.append(fr123));
        assertTrue(dll.append(fr456));
        assertEq(dll.getSize(), 2);
        assertEq(dll.getFirst().pack(), fr123.pack());
        assertEq(dll.getLast().pack(), fr456.pack());
        // now remove fr456
        assertTrue(dll.remove(fr456));
        assertEq(dll.getFirst().pack(), fr123.pack());
        assertEq(dll.getLast().pack(), fr123.pack());
        // now add back fr456 with three more frs
        assertTrue(dll.append(fr456));
        assertTrue(dll.append(fr789));
        assertTrue(dll.append(frabc));
        assertEq(dll.getSize(), 4);
        assertEq(dll.getFirst().pack(), fr123.pack());
        assertEq(dll.getLast().pack(), frabc.pack());
        FunctionReference[] memory results = dll.getAll();
        assertEq(results.length, 4);
        assertEq(results[0].pack(), fr123.pack());
        assertEq(results[1].pack(), fr456.pack());
        assertEq(results[2].pack(), fr789.pack());
        assertEq(results[3].pack(), frabc.pack());
        // now remove frabc
        assertTrue(dll.remove(frabc));
        assertEq(dll.getSize(), 3);
        assertEq(dll.getFirst().pack(), fr123.pack());
        assertEq(dll.getLast().pack(), fr789.pack());
        // now remove fr789
        assertTrue(dll.remove(fr789));
        assertEq(dll.getSize(), 2);
        assertEq(dll.getFirst().pack(), fr123.pack());
        assertEq(dll.getLast().pack(), fr456.pack());
        // now remove fr456
        assertTrue(dll.remove(fr456));
        assertEq(dll.getSize(), 1);
        assertEq(dll.getFirst().pack(), fr123.pack());
        assertEq(dll.getLast().pack(), fr123.pack());
        // now remove fr123
        assertTrue(dll.remove(fr123));
        assertEq(dll.getSize(), 0);
        assertEq(dll.getFirst().pack(), SENTINEL_BYTES21);
        assertEq(dll.getLast().pack(), SENTINEL_BYTES21);
        // now remove fr456 again, should revert
        errorSelector = bytes4(keccak256("ItemDoesNotExist()"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector));
        dll.remove(fr456);
        // get zero fr every time
        errorSelector = bytes4(keccak256("InvalidLimit()"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector));
        dll.getPaginated(SENTINEL_BYTES21.unpack(), 0);
    }

    function testBulkGetFunctionReferences() public {
        // try out different limits, even bigger than totalFRs
        for (uint256 limit = 1; limit <= 10; limit++) {
            // 4 plugins
            bulkAddAndFunctionReferences(new TestFunctionReferenceDLL(), 4, limit);
        }
        for (uint256 limit = 1; limit <= 25; limit++) {
            bulkAddAndFunctionReferences(new TestFunctionReferenceDLL(), 20, limit);
        }
        for (uint256 limit = 1; limit <= 26; limit++) {
            bulkAddAndFunctionReferences(new TestFunctionReferenceDLL(), 20, limit);
        }
    }

    function bulkAddAndFunctionReferences(TestFunctionReferenceDLL dll, uint256 totalFRs, uint256 limit) private {
        for (uint256 i = 2; i <= totalFRs; i++) {
            assertTrue(dll.append(FunctionReference(vm.addr(i), 0)));
        }
        bulkGetFunctionReferences(dll, totalFRs, limit);
    }

    function bulkGetFunctionReferences(TestFunctionReferenceDLL dll, uint256 totalFRs, uint256 limit) private view {
        FunctionReference[] memory results = new FunctionReference[](totalFRs);
        FunctionReference memory start = SENTINEL_BYTES21.unpack();
        uint256 count = 0;
        uint256 j = 0;
        FunctionReference[] memory frs;
        FunctionReference memory next;
        while (count < totalFRs) {
            (frs, next) = dll.getPaginated(start, limit);
            for (uint256 i = 0; i < frs.length; i++) {
                results[count] = frs[i];
                // vm.addr starts from 2
                assertEq(results[j].plugin, vm.addr(count + 2));
                count++;
                j++;
            }
            if (next.pack() == SENTINEL_BYTES21) {
                break;
            }
            start = next;
        }
    }
}
