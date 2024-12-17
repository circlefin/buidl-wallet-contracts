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
import {FunctionReference, RepeatableBytes21DLL} from "../../../../src/msca/6900/v0.7/common/Structs.sol";
import {FunctionReferenceLib} from "../../../../src/msca/6900/v0.7/libs/FunctionReferenceLib.sol";
import {RepeatableFunctionReferenceDLLLib} from
    "../../../../src/msca/6900/v0.7/libs/RepeatableFunctionReferenceDLLLib.sol";

import {TestUtils} from "../../../util/TestUtils.sol";
import {TestCircleMSCA} from "./TestCircleMSCA.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PluginManager} from "src/msca/6900/v0.7/managers/PluginManager.sol";

contract WalletStorageV1LibTest is TestUtils {
    using RepeatableFunctionReferenceDLLLib for RepeatableBytes21DLL;
    using FunctionReferenceLib for bytes21;
    using FunctionReferenceLib for FunctionReference;

    address private constant SENTINEL_ADDRESS = address(0x0);
    IEntryPoint private entryPoint = new EntryPoint();
    PluginManager private pluginManager = new PluginManager();
    uint256 internal eoaPrivateKey;
    address private ownerAddr;
    address payable private beneficiary; // e.g. bundler

    function setUp() public {
        beneficiary = payable(address(makeAddr("bundler")));
    }

    function testWalletStorageSlot() public pure {
        bytes32 hash = keccak256(abi.encode(uint256(keccak256("circle.msca.v1.storage")) - 1));
        bytes32 alignedHash = hash & ~bytes32(uint256(0xff));
        assertEq(alignedHash, 0x1f5beaddce7d7c52c0db456127db41c33d65f252d3a09b925e817276761a6a00);
    }

    // this test is very similar to AddressDLLLibTest, but under the context of plugin and wallet
    function testAddRemoveGetPlugins() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testAddRemoveGetPlugins");
        TestCircleMSCA msca = new TestCircleMSCA(entryPoint, pluginManager);
        // sentinel address is not considered as the value of the list
        assertFalse(msca.containsPlugin(SENTINEL_ADDRESS));
        // try to remove sentinel stupidly
        bytes4 selector = bytes4(keccak256("InvalidAddress()"));
        vm.expectRevert(abi.encodeWithSelector(selector));
        msca.removePlugin(SENTINEL_ADDRESS);
        assertEq(msca.getFirstPlugin(), SENTINEL_ADDRESS);
        assertEq(msca.getLastPlugin(), SENTINEL_ADDRESS);
        // sentinel doesn't count
        assertEq(msca.sizeOfPlugins(), 0);
        assertFalse(msca.containsPlugin(address(0x123)));
        assertTrue(msca.addPlugin(address(0x123)));
        assertEq(msca.getFirstPlugin(), address(0x123));
        assertEq(msca.getLastPlugin(), address(0x123));
        // try to add the same plugin again, should revert
        selector = bytes4(keccak256("ItemAlreadyExists()"));
        vm.expectRevert(abi.encodeWithSelector(selector));
        msca.addPlugin(address(0x123));
        // check the size of plugins
        assertEq(msca.sizeOfPlugins(), 1);
        assertTrue(msca.containsPlugin(address(0x123)));
        // now remove it
        assertTrue(msca.removePlugin(address(0x123)));
        assertEq(msca.sizeOfPlugins(), 0);
        assertEq(msca.getFirstPlugin(), SENTINEL_ADDRESS);
        assertEq(msca.getLastPlugin(), SENTINEL_ADDRESS);
        // now remove the same item again
        selector = bytes4(keccak256("ItemDoesNotExist()"));
        vm.expectRevert(abi.encodeWithSelector(selector));
        msca.removePlugin(address(0x123));
        // now remove an item never added before
        selector = bytes4(keccak256("ItemDoesNotExist()"));
        vm.expectRevert(abi.encodeWithSelector(selector));
        msca.removePlugin(address(0xdef));
        // add address(123) back with one more address
        assertTrue(msca.addPlugin(address(0x123)));
        assertTrue(msca.addPlugin(address(0x456)));
        assertTrue(msca.containsPlugin(address(0x123)));
        assertTrue(msca.containsPlugin(address(0x456)));
        assertEq(msca.getFirstPlugin(), address(0x123));
        assertEq(msca.getLastPlugin(), address(0x456));
        // now remove address(456) using the correct method
        assertTrue(msca.removePlugin(address(0x456)));
        assertFalse(msca.containsPlugin(address(0x456)));
        assertEq(msca.getFirstPlugin(), address(0x123));
        assertEq(msca.getLastPlugin(), address(0x123));
        // now add back address(456) with two more plugins
        assertTrue(msca.addPlugin(address(0x456)));
        assertTrue(msca.addPlugin(address(0x789)));
        assertTrue(msca.addPlugin(address(0xabc)));
        assertEq(msca.getFirstPlugin(), address(0x123));
        assertEq(msca.getLastPlugin(), address(0xabc));
        assertEq(msca.sizeOfPlugins(), 4);
        // get zero plugin every time
        selector = bytes4(keccak256("InvalidLimit()"));
        vm.expectRevert(abi.encodeWithSelector(selector));
        msca.getPluginsPaginated(address(0x0), 0);
    }

    function testAddRemoveGetPreUserOpValidationHooks() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testAddRemoveGetPreUserOpValidationHooks");
        TestCircleMSCA msca = new TestCircleMSCA(entryPoint, pluginManager);
        // sentinel hook is not part of the list
        bytes4 selector = bytes4(0xb61d27f6);
        assertEq(msca.containsPreUserOpValidationHook(selector, SENTINEL_BYTES21.unpack()), 0);
        // try to remove sentinel stupidly
        bytes4 errorSelector = bytes4(keccak256("InvalidFunctionReference()"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector));
        msca.removePreUserOpValidationHook(selector, SENTINEL_BYTES21.unpack());
        assertEq(msca.getFirstPreUserOpValidationHook(selector).pack(), SENTINEL_BYTES21);
        assertEq(msca.getLastPreUserOpValidationHook(selector).pack(), SENTINEL_BYTES21);
        // sentinel doesn't count
        assertEq(msca.sizeOfPreUserOpValidationHooks(selector), 0);
        FunctionReference memory hook123 = FunctionReference(address(0x123), 0);
        FunctionReference memory hook456 = FunctionReference(address(0x456), 0);
        FunctionReference memory hook789 = FunctionReference(address(0x789), 0);
        FunctionReference memory hookabc = FunctionReference(address(0xabc), 0);
        assertEq(msca.containsPreUserOpValidationHook(selector, hook123), 0);
        assertEq(msca.addPreUserOpValidationHook(selector, hook123), 1);
        assertEq(msca.getFirstPreUserOpValidationHook(selector).pack(), hook123.pack());
        assertEq(msca.getLastPreUserOpValidationHook(selector).pack(), hook123.pack());
        // now remove it
        assertEq(msca.removePreUserOpValidationHook(selector, hook123), 0);
        assertEq(msca.sizeOfPreUserOpValidationHooks(selector), 0);
        assertEq(msca.getFirstPreUserOpValidationHook(selector).pack(), SENTINEL_BYTES21);
        assertEq(msca.getLastPreUserOpValidationHook(selector).pack(), SENTINEL_BYTES21);
        // add hook123 back with one more hook
        assertEq(msca.addPreUserOpValidationHook(selector, hook123), 1);
        assertEq(msca.addPreUserOpValidationHook(selector, hook456), 1);
        assertEq(msca.containsPreUserOpValidationHook(selector, hook123), 1);
        assertEq(msca.containsPreUserOpValidationHook(selector, hook456), 1);
        assertEq(msca.getFirstPreUserOpValidationHook(selector).pack(), hook123.pack());
        assertEq(msca.getLastPreUserOpValidationHook(selector).pack(), hook456.pack());
        // now remove hook456
        assertEq(msca.removePreUserOpValidationHook(selector, hook456), 0);
        assertEq(msca.containsPreUserOpValidationHook(selector, hook456), 0);
        assertEq(msca.getFirstPreUserOpValidationHook(selector).pack(), hook123.pack());
        assertEq(msca.getLastPreUserOpValidationHook(selector).pack(), hook123.pack());
        // now add back hook456 with two more hooks
        assertEq(msca.addPreUserOpValidationHook(selector, hook456), 1);
        assertEq(msca.addPreUserOpValidationHook(selector, hook789), 1);
        assertEq(msca.addPreUserOpValidationHook(selector, hookabc), 1);
        assertEq(msca.getFirstPreUserOpValidationHook(selector).pack(), hook123.pack());
        assertEq(msca.getLastPreUserOpValidationHook(selector).pack(), hookabc.pack());
        assertEq(msca.sizeOfPreUserOpValidationHooks(selector), 4);
        // now remove hook123
        assertEq(msca.removePreUserOpValidationHook(selector, hook123), 0);
        assertEq(msca.getFirstPreUserOpValidationHook(selector).pack(), hook456.pack());
        assertEq(msca.getLastPreUserOpValidationHook(selector).pack(), hookabc.pack());
        // now remove hookabc
        assertEq(msca.removePreUserOpValidationHook(selector, hookabc), 0);
        assertEq(msca.getFirstPreUserOpValidationHook(selector).pack(), hook456.pack());
        assertEq(msca.getLastPreUserOpValidationHook(selector).pack(), hook789.pack());
        // now remove hook789
        assertEq(msca.removePreUserOpValidationHook(selector, hook789), 0);
        assertEq(msca.getFirstPreUserOpValidationHook(selector).pack(), hook456.pack());
        assertEq(msca.getLastPreUserOpValidationHook(selector).pack(), hook456.pack());
        // now remove hook456
        assertEq(msca.removePreUserOpValidationHook(selector, hook456), 0);
        assertEq(msca.getFirstPreUserOpValidationHook(selector).pack(), SENTINEL_BYTES21);
        assertEq(msca.getLastPreUserOpValidationHook(selector).pack(), SENTINEL_BYTES21);
        // now remove hook456 again, should revert
        errorSelector = bytes4(keccak256("ItemDoesNotExist()"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector));
        msca.removePreUserOpValidationHook(selector, hook456);
        // still sentinel
        assertEq(msca.getFirstPreUserOpValidationHook(selector).pack(), SENTINEL_BYTES21);
        assertEq(msca.getLastPreUserOpValidationHook(selector).pack(), SENTINEL_BYTES21);
        // get zero hook every time
        errorSelector = bytes4(keccak256("InvalidLimit()"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector));
        msca.getPreUserOpValidationHooksPaginated(selector, SENTINEL_BYTES21.unpack(), 0);
    }

    function testBulkGetPlugins() public {
        // try out different limits, even bigger than totalPlugins
        for (uint256 limit = 1; limit <= 10; limit++) {
            // 4 plugins
            bulkAddAndGetPlugins(new TestCircleMSCA(entryPoint, pluginManager), 4, limit);
        }
        for (uint256 limit = 1; limit <= 55; limit++) {
            bulkAddAndGetPlugins(new TestCircleMSCA(entryPoint, pluginManager), 50, limit);
        }
        for (uint256 limit = 1; limit <= 56; limit++) {
            bulkAddAndGetPlugins(new TestCircleMSCA(entryPoint, pluginManager), 50, limit);
        }
    }

    function testBulkGetPreUserOpValidationHooks() public {
        // try out different limits, even bigger than totalHooks
        for (uint256 limit = 1; limit <= 10; limit++) {
            // 4 plugins
            bulkAddAndGetPreUserOpValidationHooks(new TestCircleMSCA(entryPoint, pluginManager), 4, limit);
        }
        for (uint256 limit = 1; limit <= 55; limit++) {
            bulkAddAndGetPreUserOpValidationHooks(new TestCircleMSCA(entryPoint, pluginManager), 50, limit);
        }
        for (uint256 limit = 1; limit <= 56; limit++) {
            bulkAddAndGetPreUserOpValidationHooks(new TestCircleMSCA(entryPoint, pluginManager), 50, limit);
        }
    }

    function bulkAddAndGetPlugins(TestCircleMSCA msca, uint256 totalPlugins, uint256 limit) private {
        for (uint256 i = 2; i <= totalPlugins; i++) {
            assertTrue(msca.addPlugin(vm.addr(i)));
        }
        bulkGetPlugins(msca, totalPlugins, limit);
    }

    function bulkGetPlugins(TestCircleMSCA msca, uint256 totalPlugins, uint256 limit) private view {
        address[] memory results = new address[](totalPlugins);
        address start = address(0x0);
        uint256 count = 0;
        uint256 j = 0;
        address[] memory plugins;
        address next;
        while (count < totalPlugins) {
            (plugins, next) = msca.getPluginsPaginated(start, limit);
            for (uint256 i = 0; i < plugins.length; i++) {
                results[count] = plugins[i];
                // vm.addr starts from 2
                assertEq(results[j], vm.addr(count + 2));
                count++;
                j++;
            }
            if (next == address(0x0)) {
                break;
            }
            start = next;
        }
    }

    function bulkAddAndGetPreUserOpValidationHooks(TestCircleMSCA msca, uint256 totalHooks, uint256 limit) private {
        bytes4 selector = bytes4(0xb61d27f6);
        for (uint256 i = 2; i <= totalHooks; i++) {
            assertEq(msca.addPreUserOpValidationHook(selector, FunctionReference(vm.addr(i), 0)), 1);
        }
        bulkGetPreUserOpValidationHooks(msca, selector, totalHooks, limit);
    }

    function bulkGetPreUserOpValidationHooks(TestCircleMSCA msca, bytes4 selector, uint256 totalHooks, uint256 limit)
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
            (hooks, next) = msca.getPreUserOpValidationHooksPaginated(selector, start, limit);
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
