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

import "../../../../src/msca/6900/v0.7/factories/semi/SingleOwnerMSCAFactory.sol";
import "../../../../src/msca/6900/v0.7/interfaces/IStandardExecutor.sol";
import {PluginManager} from "../../../../src/msca/6900/v0.7/managers/PluginManager.sol";
import "../../../util/TestLiquidityPool.sol";
import "../../../util/TestUtils.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "forge-std/src/console.sol";

contract SingleOwnerMSCAFactoryTest is TestUtils {
    event AccountCreated(address indexed proxy, address sender, bytes32 salt);
    event SingleOwnerMSCAInitialized(address indexed account, address indexed entryPointAddress, address owner);
    event PluginInstalled(address indexed plugin, bytes32 manifestHash, FunctionReference[] dependencies);
    event OwnershipTransferred(address indexed account, address indexed previousOwner, address indexed newOwner);
    event UserOperationEvent(
        bytes32 indexed userOpHash,
        address indexed sender,
        address indexed paymaster,
        uint256 nonce,
        bool success,
        uint256 actualGasCost,
        uint256 actualGasUsed
    );

    IEntryPoint private entryPoint = new EntryPoint();
    PluginManager private pluginManager = new PluginManager();
    uint256 internal eoaPrivateKey;
    address private ownerAddr;
    SingleOwnerMSCAFactory private factory;
    TestLiquidityPool private testLiquidityPool;
    address payable beneficiary; // e.g. bundler

    function setUp() public {
        factory = new SingleOwnerMSCAFactory(address(entryPoint), address(pluginManager));
        testLiquidityPool = new TestLiquidityPool("getrich", "$$$");
        beneficiary = payable(address(makeAddr("bundler")));
    }

    function testGetAddressAndCreateSingleOwnerMSCA() public {
        // calculate counterfactual address first
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testGetAddressAndCreateSingleOwnerMSCA");
        vm.startPrank(ownerAddr);
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        bytes memory initializingData = abi.encode(ownerAddr);
        (address counterfactualAddr,) = factory.getAddress(ownerAddr, salt, initializingData);
        // emit OwnershipTransferred
        vm.expectEmit(true, true, true, false);
        emit OwnershipTransferred(counterfactualAddr, address(0), ownerAddr);
        // emit SingleOwnerMSCAInitialized
        vm.expectEmit(true, true, false, false);
        emit SingleOwnerMSCAInitialized(counterfactualAddr, address(entryPoint), ownerAddr);
        // emit AccountCreated
        vm.expectEmit(true, true, false, false);
        emit AccountCreated(counterfactualAddr, ownerAddr, salt);
        SingleOwnerMSCA accountCreated = factory.createAccount(ownerAddr, salt, initializingData);
        assertEq(address(accountCreated.entryPoint()), address(entryPoint));
        assertEq(accountCreated.getNativeOwner(), ownerAddr);
        // verify the address does not change
        assertEq(address(accountCreated), counterfactualAddr);
        // deploy again
        SingleOwnerMSCA accountCreatedAgain = factory.createAccount(ownerAddr, salt, initializingData);
        // verify the address does not change
        assertEq(address(accountCreatedAgain), counterfactualAddr);
        vm.stopPrank();
    }

    function testDeploySingleOwnerMSCAWith1stOutboundUserOp() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testDeploySingleOwnerMSCAWith1stOutboundUserOp");
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        bytes memory initializingData = abi.encode(ownerAddr);
        (address sender,) = factory.getAddress(ownerAddr, salt, initializingData);
        assertTrue(sender.code.length == 0);
        uint256 acctNonce = entryPoint.getNonce(sender, 0);
        // start with balance
        vm.deal(sender, 1 ether);
        testLiquidityPool.mint(sender, 2000000);
        address recipient = address(0x9005Be081B8EC2A31258878409E88675Cd791376);
        // execute ERC20 token contract
        address liquidityPoolSpenderAddr = address(testLiquidityPool);
        bytes memory tokenTransferCallData = abi.encodeCall(testLiquidityPool.transfer, (recipient, 1000000));
        bytes memory executeCallData =
            abi.encodeCall(IStandardExecutor.execute, (liquidityPoolSpenderAddr, 0, tokenTransferCallData));
        bytes memory createAccountCall =
            abi.encodeCall(SingleOwnerMSCAFactory.createAccount, (ownerAddr, salt, initializingData));
        address factoryAddr = address(factory);
        bytes memory initCode = abi.encodePacked(factoryAddr, createAccountCall);
        PackedUserOperation memory userOp = buildPartialUserOp(
            sender,
            acctNonce,
            vm.toString(initCode),
            vm.toString(executeCallData),
            83353,
            1028650,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        // no paymaster
        emit UserOperationEvent(userOpHash, sender, address(0), acctNonce, true, 287692350000000, 254595);
        entryPoint.handleOps(ops, beneficiary);
        // verify the account has been deployed
        assertTrue(sender.code.length > 0);
        // verify the outbound ERC20 token transfer is successful by checking the balance
        assertEq(testLiquidityPool.balanceOf(recipient), 1000000);
        assertEq(testLiquidityPool.balanceOf(sender), 1000000);
        vm.stopPrank();
    }

    function testGetAddressAndCreateUsingAddressZero() public {
        // calculate counterfactual address first
        ownerAddr = address(0);
        vm.startPrank(ownerAddr);
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        bytes memory initializingData = abi.encode(ownerAddr);
        vm.expectRevert(InvalidInitializationInput.selector);
        factory.getAddress(ownerAddr, salt, initializingData);
        vm.expectRevert(InvalidInitializationInput.selector);
        factory.createAccount(ownerAddr, salt, initializingData);
        vm.stopPrank();
    }
}
