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

import "../../../../src/msca/6900/v0.7/common/Structs.sol";
import "../../../util/TestUtils.sol";
import "./TestRepeatableFunctionReferenceDLL.sol";
import "forge-std/src/console.sol";

contract RepeatableFunctionReferenceDLLibTest is TestUtils {
    using FunctionReferenceLib for bytes21;
    using FunctionReferenceLib for FunctionReference;

    function testAddRemoveGetPreValidationHooks() public {
        TestRepeatableFunctionReferenceDLL dll = new TestRepeatableFunctionReferenceDLL();
        // sentinel hook is initialized
        assertEq(dll.getRepeatedCountOfPreValidationHook(SENTINEL_BYTES21.unpack()), 1);
        // try to remove sentinel stupidly
        bytes4 errorSelector = bytes4(keccak256("InvalidFunctionReference()"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector));
        dll.removePreValidationHook(SENTINEL_BYTES21.unpack());
        assertEq(dll.getFirstPreValidationHook().pack(), SENTINEL_BYTES21);
        assertEq(dll.getLastPreValidationHook().pack(), SENTINEL_BYTES21);
        // sentinel doesn't count
        assertEq(dll.getTotalItemsOfPreValidationHooks(), 0);
        FunctionReference memory hook123 = FunctionReference(address(0x123), 0);
        FunctionReference memory hook456 = FunctionReference(address(0x456), 0);
        FunctionReference memory hook789 = FunctionReference(address(0x789), 0);
        FunctionReference memory hookabc = FunctionReference(address(0xabc), 0);
        assertEq(dll.appendPreValidationHook(hook123), 1);
        assertEq(dll.getFirstPreValidationHook().pack(), hook123.pack());
        assertEq(dll.getLastPreValidationHook().pack(), hook123.pack());
        // try to add the same function reference again, should increase the counter
        assertEq(dll.appendPreValidationHook(hook123), 2);
        assertEq(dll.getTotalItemsOfPreValidationHooks(), 2);
        assertEq(dll.getUniqueItemsOfPreValidationHooks(), 1);
        // now remove it
        assertEq(dll.removePreValidationHook(hook123), 1);
        assertEq(dll.getTotalItemsOfPreValidationHooks(), 1);
        assertEq(dll.getUniqueItemsOfPreValidationHooks(), 1);
        // remove it again
        assertEq(dll.removePreValidationHook(hook123), 0);
        assertEq(dll.getTotalItemsOfPreValidationHooks(), 0);
        assertEq(dll.getUniqueItemsOfPreValidationHooks(), 0);
        assertEq(dll.getFirstPreValidationHook().pack(), SENTINEL_BYTES21);
        assertEq(dll.getLastPreValidationHook().pack(), SENTINEL_BYTES21);
        // add hook123 back with one more hook
        assertEq(dll.appendPreValidationHook(hook123), 1);
        assertEq(dll.appendPreValidationHook(hook456), 1);
        assertEq(dll.getRepeatedCountOfPreValidationHook(hook123), 1);
        assertEq(dll.getRepeatedCountOfPreValidationHook(hook456), 1);
        assertEq(dll.getTotalItemsOfPreValidationHooks(), 2);
        assertEq(dll.getUniqueItemsOfPreValidationHooks(), 2);
        assertEq(dll.getFirstPreValidationHook().pack(), hook123.pack());
        assertEq(dll.getLastPreValidationHook().pack(), hook456.pack());
        // now remove hook456
        assertEq(dll.removePreValidationHook(hook456), 0);
        assertEq(dll.getRepeatedCountOfPreValidationHook(hook456), 0);
        assertEq(dll.getFirstPreValidationHook().pack(), hook123.pack());
        assertEq(dll.getLastPreValidationHook().pack(), hook123.pack());
        // now add back hook456 with three more hooks
        assertEq(dll.appendPreValidationHook(hook456), 1);
        assertEq(dll.appendPreValidationHook(hook123), 2);
        assertEq(dll.appendPreValidationHook(hook789), 1);
        assertEq(dll.appendPreValidationHook(hookabc), 1);
        assertEq(dll.getTotalItemsOfPreValidationHooks(), 5);
        assertEq(dll.getUniqueItemsOfPreValidationHooks(), 4);
        assertEq(dll.getFirstPreValidationHook().pack(), hook123.pack());
        assertEq(dll.getLastPreValidationHook().pack(), hookabc.pack());
        FunctionReference[] memory results = dll.getAllPreValidationHooks();
        assertEq(results.length, 4);
        assertEq(results[0].pack(), hook123.pack());
        assertEq(results[1].pack(), hook456.pack());
        assertEq(results[2].pack(), hook789.pack());
        assertEq(results[3].pack(), hookabc.pack());
        // now remove 2 instances of hook123
        assertTrue(dll.removeAllRepeatedPreValidationHooks(hook123));
        assertEq(dll.getRepeatedCountOfPreValidationHook(hook123), 0);
        assertEq(dll.getTotalItemsOfPreValidationHooks(), 3);
        assertEq(dll.getUniqueItemsOfPreValidationHooks(), 3);
        assertEq(dll.getFirstPreValidationHook().pack(), hook456.pack());
        assertEq(dll.getLastPreValidationHook().pack(), hookabc.pack());
        // now remove hookabc
        assertEq(dll.removePreValidationHook(hookabc), 0);
        assertEq(dll.getTotalItemsOfPreValidationHooks(), 2);
        assertEq(dll.getUniqueItemsOfPreValidationHooks(), 2);
        assertEq(dll.getFirstPreValidationHook().pack(), hook456.pack());
        assertEq(dll.getLastPreValidationHook().pack(), hook789.pack());
        // now remove hook789
        assertEq(dll.removePreValidationHook(hook789), 0);
        assertEq(dll.getTotalItemsOfPreValidationHooks(), 1);
        assertEq(dll.getUniqueItemsOfPreValidationHooks(), 1);
        assertEq(dll.getFirstPreValidationHook().pack(), hook456.pack());
        assertEq(dll.getLastPreValidationHook().pack(), hook456.pack());
        // now remove hook456
        assertEq(dll.removePreValidationHook(hook456), 0);
        assertEq(dll.getTotalItemsOfPreValidationHooks(), 0);
        assertEq(dll.getUniqueItemsOfPreValidationHooks(), 0);
        assertEq(dll.getFirstPreValidationHook().pack(), SENTINEL_BYTES21);
        assertEq(dll.getLastPreValidationHook().pack(), SENTINEL_BYTES21);
        // now remove hook456 again, should revert
        errorSelector = bytes4(keccak256("ItemDoesNotExist()"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector));
        dll.removePreValidationHook(hook456);
        // get zero hook every time
        errorSelector = bytes4(keccak256("InvalidLimit()"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector));
        dll.getPreValidationHooksPaginated(SENTINEL_BYTES21.unpack(), 0);
    }

    function testBulkGetPreValidationHooks() public {
        // try out different limits, even bigger than totalHooks
        for (uint256 limit = 1; limit <= 10; limit++) {
            // 4 plugins
            bulkAddAndGetPreValidationHooks(new TestRepeatableFunctionReferenceDLL(), 4, limit);
        }
        for (uint256 limit = 1; limit <= 55; limit++) {
            bulkAddAndGetPreValidationHooks(new TestRepeatableFunctionReferenceDLL(), 50, limit);
        }
        for (uint256 limit = 1; limit <= 56; limit++) {
            bulkAddAndGetPreValidationHooks(new TestRepeatableFunctionReferenceDLL(), 50, limit);
        }
    }

    function bulkAddAndGetPreValidationHooks(TestRepeatableFunctionReferenceDLL dll, uint256 totalHooks, uint256 limit)
        private
    {
        for (uint256 i = 2; i <= totalHooks; i++) {
            assertEq(dll.appendPreValidationHook(FunctionReference(vm.addr(i), 0)), 1);
        }
        bulkGetPreValidationHooks(dll, totalHooks, limit);
    }

    function bulkGetPreValidationHooks(TestRepeatableFunctionReferenceDLL dll, uint256 totalHooks, uint256 limit)
        private
        view
    {
        FunctionReference[] memory results = new FunctionReference[](totalHooks);
        FunctionReference memory start = SENTINEL_BYTES21.unpack();
        uint256 count = 0;
        uint256 j = 0;
        FunctionReference[] memory hooks;
        FunctionReference memory next;
        while (count < totalHooks) {
            (hooks, next) = dll.getPreValidationHooksPaginated(start, limit);
            for (uint256 i = 0; i < hooks.length; i++) {
                results[count] = hooks[i];
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
