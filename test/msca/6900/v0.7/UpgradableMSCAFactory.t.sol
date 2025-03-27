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

import {InvalidInitializationInput} from "../../../../src/msca/6900/shared/common/Errors.sol";
import {UpgradableMSCA} from "../../../../src/msca/6900/v0.7/account/UpgradableMSCA.sol";

import {FunctionReference} from "../../../../src/msca/6900/v0.7/common/Structs.sol";
import {UpgradableMSCAFactory} from "../../../../src/msca/6900/v0.7/factories/UpgradableMSCAFactory.sol";

import {IStandardExecutor} from "../../../../src/msca/6900/v0.7/interfaces/IStandardExecutor.sol";
import {PluginManager} from "../../../../src/msca/6900/v0.7/managers/PluginManager.sol";
import {SingleOwnerPlugin} from "../../../../src/msca/6900/v0.7/plugins/v1_0_0/acl/SingleOwnerPlugin.sol";
import {ExecutionUtils} from "../../../../src/utils/ExecutionUtils.sol";
import {TestLiquidityPool} from "../../../util/TestLiquidityPool.sol";
import {TestUtils} from "../../../util/TestUtils.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";

import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {UserOperation} from "@account-abstraction/contracts/interfaces/UserOperation.sol";

contract UpgradableMSCAFactoryTest is TestUtils {
    event AccountCreated(address indexed proxy, bytes32 sender, bytes32 salt);
    event UpgradableMSCAInitialized(address indexed account, address indexed entryPointAddress);
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
    UpgradableMSCAFactory private factory;
    SingleOwnerPlugin private singleOwnerPlugin;
    TestLiquidityPool private testLiquidityPool;
    address payable private beneficiary; // e.g. bundler
    address private factoryOwner;

    function setUp() public {
        factoryOwner = makeAddr("factoryOwner");
        factory = new UpgradableMSCAFactory(factoryOwner, address(entryPoint), address(pluginManager));
        beneficiary = payable(address(makeAddr("bundler")));
        testLiquidityPool = new TestLiquidityPool("getrich", "$$$");
        singleOwnerPlugin = new SingleOwnerPlugin();
        address[] memory _plugins = new address[](1);
        _plugins[0] = address(singleOwnerPlugin);
        bool[] memory _permissions = new bool[](1);
        _permissions[0] = true;
        vm.startPrank(factoryOwner);
        factory.setPlugins(_plugins, _permissions);
        vm.stopPrank();
    }

    function testInstallDisabledPlugin() public {
        SingleOwnerPlugin maliciousPlugin = new SingleOwnerPlugin();
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        address[] memory plugins = new address[](1);
        bytes32[] memory manifestHashes = new bytes32[](1);
        bytes[] memory pluginInstallData = new bytes[](1);
        plugins[0] = address(maliciousPlugin);
        manifestHashes[0] = keccak256(abi.encode(maliciousPlugin.pluginManifest()));
        pluginInstallData[0] = "";
        bytes memory initializingData = abi.encode(plugins, manifestHashes, pluginInstallData);
        bytes4 errorSelector = bytes4(keccak256("PluginIsNotAllowed(address)"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector, plugins[0]));
        factory.createAccount(addressToBytes32(ownerAddr), salt, initializingData);
    }

    function testGetAddressAndCreateMSCA() public {
        // calculate counterfactual address first
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testGetAddressAndCreateMSCA");
        vm.startPrank(ownerAddr);
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        address[] memory plugins = new address[](1);
        bytes32[] memory manifestHashes = new bytes32[](1);
        bytes[] memory pluginInstallData = new bytes[](1);
        plugins[0] = address(singleOwnerPlugin);
        manifestHashes[0] = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
        pluginInstallData[0] = abi.encode(ownerAddr);
        bytes memory initializingData = abi.encode(plugins, manifestHashes, pluginInstallData);
        (address counterfactualAddr,) = factory.getAddress(addressToBytes32(ownerAddr), salt, initializingData);
        FunctionReference[] memory dependencies = new FunctionReference[](0);
        // emit OwnershipTransferred
        vm.expectEmit(true, true, true, false);
        emit OwnershipTransferred(counterfactualAddr, address(0), ownerAddr);
        // emit PluginInstalled first
        vm.expectEmit(true, false, false, true);
        emit PluginInstalled(address(singleOwnerPlugin), manifestHashes[0], dependencies);
        // emit UpgradableMSCAInitialized
        vm.expectEmit(true, true, false, false);
        emit UpgradableMSCAInitialized(counterfactualAddr, address(entryPoint));
        // emit AccountCreated
        vm.expectEmit(true, true, false, false);
        emit AccountCreated(counterfactualAddr, addressToBytes32(ownerAddr), salt);
        UpgradableMSCA accountCreated = factory.createAccount(addressToBytes32(ownerAddr), salt, initializingData);
        assertEq(address(accountCreated.ENTRY_POINT()), address(entryPoint));
        assertEq(singleOwnerPlugin.getOwnerOf(address(accountCreated)), ownerAddr);
        // verify the address does not change
        assertEq(address(accountCreated), counterfactualAddr);
        // deploy again
        UpgradableMSCA accountCreatedAgain = factory.createAccount(addressToBytes32(ownerAddr), salt, initializingData);
        // verify the address does not change
        assertEq(address(accountCreatedAgain), counterfactualAddr);
        address[] memory installedPlugins = accountCreated.getInstalledPlugins();
        assertEq(installedPlugins[0], address(singleOwnerPlugin));
        vm.stopPrank();
    }

    // standard execution
    function testDeployMSCAWith1stOutboundUserOp() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testDeployMSCAWith1stOutboundUserOp");
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        // only get address w/o deployment
        address[] memory plugins = new address[](1);
        bytes32[] memory manifestHashes = new bytes32[](1);
        bytes[] memory pluginInstallData = new bytes[](1);
        plugins[0] = address(singleOwnerPlugin);
        manifestHashes[0] = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
        pluginInstallData[0] = abi.encode(ownerAddr);
        bytes memory initializingData = abi.encode(plugins, manifestHashes, pluginInstallData);
        (address sender,) = factory.getAddress(addressToBytes32(ownerAddr), salt, initializingData);
        assertTrue(sender.code.length == 0);
        // nonce key is 0
        uint256 acctNonce = entryPoint.getNonce(sender, 0);
        // start with balance
        vm.deal(sender, 10 ether);
        testLiquidityPool.mint(sender, 2000000);
        address recipient = address(0x9005Be081B8EC2A31258878409E88675Cd791376);
        // execute ERC20 token contract
        address liquidityPoolSpenderAddr = address(testLiquidityPool);
        bytes memory tokenTransferCallData = abi.encodeCall(testLiquidityPool.transfer, (recipient, 1000000));
        bytes memory executeCallData =
            abi.encodeCall(IStandardExecutor.execute, (liquidityPoolSpenderAddr, 0, tokenTransferCallData));
        bytes memory createAccountCall =
            abi.encodeCall(UpgradableMSCAFactory.createAccount, (addressToBytes32(ownerAddr), salt, initializingData));
        address factoryAddr = address(factory);
        bytes memory initCode = abi.encodePacked(factoryAddr, createAccountCall);
        UserOperation memory userOp = buildPartialUserOp(
            sender,
            acctNonce,
            vm.toString(initCode),
            vm.toString(executeCallData),
            83353,
            10028650,
            45484,
            516219199704,
            1130000000,
            "0x"
        ); // no paymaster

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        UserOperation[] memory ops = new UserOperation[](1);
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

    function testStakeAndUnstakeWithEP() public {
        vm.deal(factoryOwner, 1 ether);
        address payable stakeWithdrawalAddr = payable(vm.addr(1));
        vm.startPrank(factoryOwner);
        factory.addStake{value: 123}(1);
        factory.unlockStake();
        // skip forward block.timestamp
        skip(10);
        factory.withdrawStake(stakeWithdrawalAddr);
        vm.stopPrank();
        assertEq(stakeWithdrawalAddr.balance, 123);

        address randomAddr = makeAddr("randomAddr");
        vm.startPrank(randomAddr);
        vm.expectRevert(bytes("Ownable: caller is not the owner"));
        factory.withdrawStake(stakeWithdrawalAddr);

        vm.deal(randomAddr, 1 ether);
        vm.expectRevert(bytes("Ownable: caller is not the owner"));
        factory.addStake{value: 123}(1);

        vm.expectRevert(bytes("Ownable: caller is not the owner"));
        factory.unlockStake();

        vm.expectRevert(bytes("Ownable: caller is not the owner"));
        factory.transferOwnership(address(0x1));

        vm.expectRevert(bytes("Ownable: caller is not the owner"));
        address[] memory _plugins = new address[](1);
        _plugins[0] = address(singleOwnerPlugin);
        bool[] memory _permissions = new bool[](1);
        _permissions[0] = true;
        factory.setPlugins(_plugins, _permissions);
        vm.stopPrank();

        // transfer owner to address(1)
        address pendingOwner = vm.addr(1);
        vm.startPrank(factoryOwner);
        factory.transferOwnership(pendingOwner);
        vm.stopPrank();
        assertEq(factory.pendingOwner(), pendingOwner);
        // call from pendingOwner
        vm.startPrank(pendingOwner);
        factory.acceptOwnership();
        assertEq(factory.owner(), pendingOwner);
        vm.stopPrank();
    }

    function testEncodeAndDecodeFactoryWithValidPaddedInput() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testEncodeAndDecodeFactoryWithValidPaddedInput");
        address[] memory plugins = new address[](1);
        bytes32[] memory manifestHashes = new bytes32[](1);
        bytes[] memory pluginInstallData = new bytes[](1);
        plugins[0] = address(singleOwnerPlugin);
        manifestHashes[0] = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
        pluginInstallData[0] = abi.encode(ownerAddr);
        bytes memory result = abi.encode(plugins, manifestHashes, pluginInstallData);
        address[] memory expectedPlugins = new address[](1);
        bytes32[] memory expectedManifestHashes = new bytes32[](1);
        bytes[] memory expectedPluginInstallData = new bytes[](1);
        (expectedPlugins, expectedManifestHashes, expectedPluginInstallData) =
            abi.decode(result, (address[], bytes32[], bytes[]));
        assertEq(plugins, expectedPlugins);
        for (uint256 i = 0; i < manifestHashes.length; i++) {
            assertEq(manifestHashes[i], expectedManifestHashes[i]);
        }
        for (uint256 i = 0; i < pluginInstallData.length; i++) {
            assertEq(pluginInstallData[i], expectedPluginInstallData[i]);
        }
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testEncodeAndDecodeFactoryWithInvalidPaddedInput() public {
        bytes memory result = hex"7109709ECfa91a80626fF3989D68f67F5b1DD12D";
        vm.expectRevert();
        abi.decode(result, (address[], bytes32[], bytes[]));
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testEncodeAndDecodeFactoryWithMaliciousBytes() public {
        // valid input with extra malicious bytes "12" in the beginning
        bytes memory result =
            hex"12000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000c7183455a4c133ae270771860664b6b7ec320bb1000000000000000000000000a0cb889707d426a7a386870a03bc70d1b069759800000000000000000000000000000000000000000000000000000000000000021fb17bac7936d72e95b49501e9c8757384ffae4690113008f5bd3ecf2de5750ed892482cc7e665eca1d358d318d38aa3a63c10247d473d04fc3538f4069ce4ae00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000200000000000000000000000001924ea847b70baedb7e066e092912d89ca8c654a0000000000000000000000000000000000000000000000000000000000000000";
        vm.expectRevert();
        abi.decode(result, (address[], bytes32[], bytes[]));
    }

    function testGetAddressAndCreateMSCAWithInvalidInput() public {
        // calculate counterfactual address first
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testGetAddressAndCreateMSCAWithInvalidInput");
        vm.startPrank(ownerAddr);
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        address[] memory plugins = new address[](1);
        // zero manifestHashes provided
        bytes32[] memory manifestHashes = new bytes32[](0);
        bytes[] memory pluginInstallData = new bytes[](1);
        plugins[0] = address(singleOwnerPlugin);
        pluginInstallData[0] = abi.encode(ownerAddr);
        bytes memory initializingData = abi.encode(plugins, manifestHashes, pluginInstallData);
        vm.expectRevert(InvalidInitializationInput.selector);
        factory.getAddress(addressToBytes32(ownerAddr), salt, initializingData);
        vm.expectRevert(InvalidInitializationInput.selector);
        factory.createAccount(addressToBytes32(ownerAddr), salt, initializingData);
        vm.stopPrank();
    }

    function testSendNativeTokenToFactory() public {
        address sender = vm.addr(123);
        vm.deal(sender, 1 ether);
        vm.expectRevert();
        ExecutionUtils.callWithReturnDataOrRevert(address(factory), 1, "");
    }
}
