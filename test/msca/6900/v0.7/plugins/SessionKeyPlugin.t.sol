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

/**
 * modular account library needs to be updated before tests can pass
 * import {TestUtils} from "../../../../util/TestUtils.sol";
 * import {console} from "forge-std/src/console.sol";
 * import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
 * import {UserOperation} from "@account-abstraction/contracts/interfaces/UserOperation.sol";
 * import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
 * import {ISessionKeyPlugin} from "@modular-account/plugins/session/ISessionKeyPlugin.sol";
 * import {ISessionKeyPermissionsUpdates} from
 *     "@modular-account/plugins/session/permissions/ISessionKeyPermissionsUpdates.sol";
 * import {SessionKeyPlugin} from "@modular-account/plugins/session/SessionKeyPlugin.sol";
 * import {Call} from "@modular-account/interfaces/IStandardExecutor.sol";
 * import {PluginManager} from "../../../../../src/msca/6900/v0.7/managers/PluginManager.sol";
 * import {SingleOwnerMSCAFactory} from "../../../../../src/msca/6900/v0.7/factories/semi/SingleOwnerMSCAFactory.sol";
 * import {SingleOwnerMSCA} from "../../../../../src/msca/6900/v0.7/account/semi/SingleOwnerMSCA.sol";
 * import {TestLiquidityPool} from "../../../../util/TestLiquidityPool.sol";
 * import {FunctionReference} from "../../../../../src/msca/6900/v0.7/common/Structs.sol";
 * import {SingleOwnerPlugin} from "../../../../../src/msca/6900/v0.7/plugins/v1_0_0/acl/SingleOwnerPlugin.sol";
 * import {ISingleOwnerPlugin} from "../../../../../src/msca/6900/v0.7/plugins/v1_0_0/acl/ISingleOwnerPlugin.sol";
 *
 * contract SessionKeyPluginTest is TestUtils {
 *     // 4337
 *     event UserOperationEvent(
 *         bytes32 indexed userOpHash,
 *         address indexed sender,
 *         address indexed paymaster,
 *         uint256 nonce,
 *         bool success,
 *         uint256 actualGasCost,
 *         uint256 actualGasUsed
 *     );
 *
 *     IEntryPoint private entryPoint = new EntryPoint();
 *     PluginManager private pluginManager = new PluginManager();
 *     address payable beneficiary; // e.g. bundler
 *     SessionKeyPlugin sessionKeyPlugin = new SessionKeyPlugin();
 *     SingleOwnerMSCAFactory private factory;
 *     TestLiquidityPool private testUSDC;
 *     SingleOwnerPlugin private singleOwnerPlugin;
 *
 *     function setUp() public {
 *         beneficiary = payable(address(makeAddr("bundler")));
 *         factory = new SingleOwnerMSCAFactory(address(entryPoint), address(pluginManager));
 *         testUSDC = new TestLiquidityPool("usdc", "usdc");
 *         sessionKeyPlugin = new SessionKeyPlugin();
 *         singleOwnerPlugin = new SingleOwnerPlugin();
 *     }
 *
 *     /// @notice This test validates the possibility of recurring pull payments that occurs between a customer who
 *     /// subscribes to
 *     //          a service provider.
 *     //          In the test setup, we deploy a session key enabled MSCA for the customer.
 *     //          We then enable a session key for the streaming service provider's based on agreed terms. The service
 *     // provider is holding
 *     //          the private key of session key pair.
 *     //          When the date reaches to the recurring billing cycles, the streaming service provider is able to
 *     //          pull the USDC from the customer MSCA.
 *     //          Note: I'm manually scheduling the recurring charges in this test. But in real life,
 *     //          the scheduling service could be something like a smart contract (ethereum alarm clock/chainlink
 *     // keepers),
 *     //          or a plugin that implements EAC (need to validate), or an offchain service.
 *     function testPullPayments() public {
 *         /// ////////////////
 *         /// msca set up
 *         /// ////////////////
 *         // create a modular account first
 *         address ownerAddr = makeAddr("testPullPayments");
 *         SingleOwnerMSCA msca = factory.createAccount(
 *             ownerAddr, 0x0000000000000000000000000000000000000000000000000000000000000000, abi.encode(ownerAddr)
 *         );
 *         console.log("mscaAddr:", address(msca));
 *
 *         // extra steps for single owner msca because the native owner is the default validation method for all
 * function
 *         // selectors;
 *         // we don't need the follow steps for full msca
 *         // install single owner plugin first
 *         FunctionReference[] memory dependencies = new FunctionReference[](0);
 *         vm.deal(address(msca), 1 ether);
 *         vm.startPrank(ownerAddr);
 *         msca.installPlugin(
 *             address(singleOwnerPlugin),
 *             keccak256(abi.encode(singleOwnerPlugin.pluginManifest())),
 *             abi.encode(ownerAddr),
 *             dependencies
 *         );
 *         // renounce native ownership
 *         msca.renounceNativeOwnership();
 *         vm.stopPrank();
 *
 *         /// ////////////////////
 *         /// issue session key
 *         /// ////////////////////
 *         // install the session key plugin
 *         dependencies = new FunctionReference[](2);
 *         dependencies[0] = FunctionReference(
 *             address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
 *         );
 *         dependencies[1] =
 *             FunctionReference(address(singleOwnerPlugin),
 * uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
 *         vm.deal(address(msca), 1 ether);
 *         // mint USDC
 *         testUSDC.mint(address(msca), 1000);
 *         vm.startPrank(ownerAddr);
 *         msca.installPlugin(
 *             address(sessionKeyPlugin),
 *             keccak256(abi.encode(sessionKeyPlugin.pluginManifest())),
 *             abi.encode(new address[](0), new bytes32[](0), new bytes[][](0)),
 *             dependencies
 *         );
 *         vm.stopPrank();
 *
 *         // create and add a session key
 *         (address sessionKey, uint256 sessionKeyPrivate) = makeAddrAndKey("testPullPayments_sessionKey");
 *         vm.startPrank(ownerAddr);
 *         SessionKeyPlugin(address(msca)).addSessionKey(sessionKey, bytes32(0), new bytes[](0));
 *         vm.stopPrank();
 *         // check that the session key is registered
 *         assertTrue(sessionKeyPlugin.isSessionKeyOf(address(msca), sessionKey));
 *         // assert that the limit is not set
 *         ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo =
 *             sessionKeyPlugin.getERC20SpendLimitInfo(address(msca), sessionKey, address(testUSDC));
 *         assertFalse(spendLimitInfo.hasLimit);
 *         assertEq(spendLimitInfo.limit, 0);
 *         assertEq(spendLimitInfo.refreshInterval, 0);
 *         assertEq(spendLimitInfo.limitUsed, 0);
 *
 *         // grant the session key of 10 USDC spending limit that's refreshed every 4 weeks
 *         uint256 startTime = 1711466989;
 *         vm.warp(startTime);
 *         bytes[] memory updates = new bytes[](2);
 *         // allow the session key to interact with USDC token
 *         updates[0] =
 *             abi.encodeCall(ISessionKeyPermissionsUpdates.updateAccessListAddressEntry, (address(testUSDC), true,
 * false));
 *         // set spending limits
 *         updates[1] = abi.encodeCall(ISessionKeyPermissionsUpdates.setERC20SpendLimit, (address(testUSDC), 10, 4
 * weeks));
 *         vm.prank(ownerAddr);
 *         SessionKeyPlugin(address(msca)).updateKeyPermissions(sessionKey, updates);
 *         vm.stopPrank();
 *
 *         // assert that the limit is updated now
 *         spendLimitInfo = sessionKeyPlugin.getERC20SpendLimitInfo(address(msca), sessionKey, address(testUSDC));
 *         assertTrue(spendLimitInfo.hasLimit);
 *         assertEq(spendLimitInfo.limit, 10);
 *         assertEq(spendLimitInfo.refreshInterval, 4 weeks);
 *         assertEq(spendLimitInfo.limitUsed, 0);
 *         assertEq(spendLimitInfo.lastUsedTime, startTime);
 *
 *         /// ////////////////////////////////////////
 *         /// bill the customer with session key
 *         /// ////////////////////////////////////////
 *         // spend 11 USDC, should fail due to ERC20SpendLimitExceeded
 *         address streamingServiceProvider = makeAddr("streaming_service");
 *         Call memory spend11USDC = Call({
 *             target: address(testUSDC),
 *             data: abi.encodeCall(testUSDC.transfer, (streamingServiceProvider, 11)),
 *             value: 0
 *         });
 *         Call[] memory calls = new Call[](1);
 *         calls[0] = spend11USDC;
 *         vm.expectCall(address(testUSDC), 0 wei, calls[0].data, 0);
 *         _executeSessionKeyViaUserOp(calls, address(msca), sessionKeyPrivate, "");
 *         // assert that the limit is NOT updated
 *         spendLimitInfo = sessionKeyPlugin.getERC20SpendLimitInfo(address(msca), sessionKey, address(testUSDC));
 *         assertTrue(spendLimitInfo.hasLimit);
 *         assertEq(spendLimitInfo.limit, 10);
 *         assertEq(spendLimitInfo.refreshInterval, 4 weeks);
 *         assertEq(spendLimitInfo.limitUsed, 0);
 *         assertEq(spendLimitInfo.lastUsedTime, startTime);
 *
 *         // spend 10 USDC, should work
 *         calls = new Call[](1);
 *         Call memory spend10USDC = Call({
 *             target: address(testUSDC),
 *             data: abi.encodeCall(testUSDC.transfer, (streamingServiceProvider, 10)),
 *             value: 0
 *         });
 *         calls[0] = spend10USDC;
 *         _executeSessionKeyViaUserOp(calls, address(msca), sessionKeyPrivate, "");
 *         spendLimitInfo = sessionKeyPlugin.getERC20SpendLimitInfo(address(msca), sessionKey, address(testUSDC));
 *         assertTrue(spendLimitInfo.hasLimit);
 *         assertEq(spendLimitInfo.limit, 10);
 *         assertEq(spendLimitInfo.refreshInterval, 4 weeks);
 *         assertEq(spendLimitInfo.limitUsed, 10);
 *         assertEq(spendLimitInfo.lastUsedTime, startTime);
 *         // now verify the merchants' USDC balance
 *         assertEq(testUSDC.balanceOf(streamingServiceProvider), 10);
 *
 *         // the merchant tries to charge 1 day prior to next billing date, should fail
 *         uint256 oneDayPriorToNextBillingCycle = startTime + 4 weeks - 1 days;
 *         vm.warp(oneDayPriorToNextBillingCycle);
 *         calls = new Call[](1);
 *         calls[0] = spend10USDC;
 *         _executeSessionKeyViaUserOp(calls, address(msca), sessionKeyPrivate, "");
 *         spendLimitInfo = sessionKeyPlugin.getERC20SpendLimitInfo(address(msca), sessionKey, address(testUSDC));
 *         assertTrue(spendLimitInfo.hasLimit);
 *         assertEq(spendLimitInfo.limit, 10);
 *         assertEq(spendLimitInfo.refreshInterval, 4 weeks);
 *         assertEq(spendLimitInfo.limitUsed, 10);
 *         assertEq(spendLimitInfo.lastUsedTime, startTime);
 *         // the merchants' USDC balance hasn't changed
 *         assertEq(testUSDC.balanceOf(streamingServiceProvider), 10);
 *
 *         // the merchant tries to charge on next billing date, should work
 *         uint256 nextBillingCycle = startTime + 4 weeks;
 *         vm.warp(nextBillingCycle);
 *         calls = new Call[](1);
 *         calls[0] = spend10USDC;
 *         _executeSessionKeyViaUserOp(calls, address(msca), sessionKeyPrivate, "");
 *         spendLimitInfo = sessionKeyPlugin.getERC20SpendLimitInfo(address(msca), sessionKey, address(testUSDC));
 *         assertTrue(spendLimitInfo.hasLimit);
 *         assertEq(spendLimitInfo.limit, 10);
 *         assertEq(spendLimitInfo.refreshInterval, 4 weeks);
 *         assertEq(spendLimitInfo.limitUsed, 10);
 *         assertEq(spendLimitInfo.lastUsedTime, nextBillingCycle);
 *         // 10 from last billing cycle, 10 from this billing cycle
 *         assertEq(testUSDC.balanceOf(streamingServiceProvider), 20);
 *
 *         // the merchant tries to charge 1 day after next 2 billing date, should work
 *         uint256 nextTwoBillingCycle = startTime + 4 weeks + 4 weeks;
 *         vm.warp(nextTwoBillingCycle);
 *         calls = new Call[](1);
 *         calls[0] = spend10USDC;
 *         _executeSessionKeyViaUserOp(calls, address(msca), sessionKeyPrivate, "");
 *         spendLimitInfo = sessionKeyPlugin.getERC20SpendLimitInfo(address(msca), sessionKey, address(testUSDC));
 *         assertTrue(spendLimitInfo.hasLimit);
 *         assertEq(spendLimitInfo.limit, 10);
 *         assertEq(spendLimitInfo.refreshInterval, 4 weeks);
 *         assertEq(spendLimitInfo.limitUsed, 10);
 *         assertEq(spendLimitInfo.lastUsedTime, nextTwoBillingCycle);
 *         // 20 from last two billing cycle, 10 from this billing cycle
 *         assertEq(testUSDC.balanceOf(streamingServiceProvider), 30);
 *     }
 *
 *     function _executeSessionKeyViaUserOp(
 *         Call[] memory calls,
 *         address senderAddr,
 *         uint256 sessionKeyPrivate,
 *         bytes memory expectedError
 *     ) internal {
 *         UserOperation memory userOp = buildPartialUserOp(
 *             senderAddr,
 *             entryPoint.getNonce(senderAddr, 0),
 *             "0x",
 *             vm.toString(abi.encodeCall(ISessionKeyPlugin.executeWithSessionKey, (calls,
 * vm.addr(sessionKeyPrivate)))),
 *             100000,
 *             1000000,
 *             0,
 *             2,
 *             1,
 *             "0x"
 *         );
 *
 *         // sign with session key
 *         userOp.signature = signUserOpHash(entryPoint, vm, sessionKeyPrivate, userOp);
 *         UserOperation[] memory ops = new UserOperation[](1);
 *         ops[0] = userOp;
 *         if (expectedError.length > 0) {
 *             vm.expectRevert(expectedError);
 *         }
 *         vm.startPrank(address(entryPoint));
 *         entryPoint.handleOps(ops, beneficiary);
 *         vm.stopPrank();
 *     }
 * }
 */
