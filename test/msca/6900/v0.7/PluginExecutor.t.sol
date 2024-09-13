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

import "../../../util/TestUtils.sol";
import "forge-std/src/console.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import "./TestCircleMSCA.sol";
import "../../../../src/msca/6900/v0.7/common/Structs.sol";
import "./TestUserOpValidator.sol";
import "./TestUserOpValidatorHook.sol";
import "../../../util/TestLiquidityPool.sol";
import "../../../../src/msca/6900/v0.7/plugins/v1_0_0/acl/SingleOwnerPlugin.sol";
import "./TestTokenPlugin.sol";
import "./TestCircleMSCAFactory.sol";
import "./TestPermitAnyExternalAddressPlugin.sol";
import "./TestTokenWithPostHookOnlyPlugin.sol";
import "./TestPermitAnyExternalAddressWithPostHookOnlyPlugin.sol";
import "./TestTokenWithPreHookOnlyPlugin.sol";
import "./TestPermitAnyExternalAddressWithPreHookOnlyPlugin.sol";

contract PluginExecutorTest is TestUtils {
    using FunctionReferenceLib for bytes21;
    using FunctionReferenceLib for FunctionReference;
    // upgrade

    event Upgraded(address indexed newImplementation);
    // 4337
    event UserOperationEvent(
        bytes32 indexed userOpHash,
        address indexed sender,
        address indexed paymaster,
        uint256 nonce,
        bool success,
        uint256 actualGasCost,
        uint256 actualGasUsed
    );
    event UserOperationRevertReason(
        bytes32 indexed userOpHash, address indexed sender, uint256 nonce, bytes revertReason
    );

    // hook events
    event PreExecutionHookCalled(uint8 indexed functionId, address sender, uint256 value, bytes data);
    event PostExecutionHookCalled(uint8 indexed functionId, bytes preExecHookData);

    IEntryPoint private entryPoint = new EntryPoint();
    PluginManager private pluginManager = new PluginManager();
    uint256 internal ownerPrivateKey;
    address private ownerAddr;
    address payable beneficiary; // e.g. bundler
    TestCircleMSCAFactory private factory;
    SingleOwnerPlugin private singleOwnerPlugin;
    TestCircleMSCA private msca;
    TestTokenPlugin private testTokenPlugin;
    TestPermitAnyExternalAddressPlugin private testPermitAnyExternalAddressPlugin;
    TestTokenWithPostHookOnlyPlugin private testTokenWithPostHookOnlyPlugin;
    TestTokenWithPreHookOnlyPlugin private testTokenWithPreHookOnlyPlugin;
    TestPermitAnyExternalAddressWithPostHookOnlyPlugin private testPermitAnyExternalAddressWithPostHookOnlyPlugin;
    TestPermitAnyExternalAddressWithPreHookOnlyPlugin private testPermitAnyExternalAddressWithPreHookOnlyPlugin;
    address private mscaAddr;
    TestLiquidityPool private longLiquidityPool;
    TestLiquidityPool private shortLiquidityPool;
    address private longLiquidityPoolAddr;
    address private shortLiquidityPoolAddr;
    address private factoryOwner;

    function setUp() public {
        factoryOwner = makeAddr("factoryOwner");
        beneficiary = payable(address(makeAddr("bundler")));
        factory = new TestCircleMSCAFactory(factoryOwner, entryPoint, pluginManager);
        singleOwnerPlugin = new SingleOwnerPlugin();

        address[] memory _plugins = new address[](1);
        _plugins[0] = address(singleOwnerPlugin);
        bool[] memory _permissions = new bool[](1);
        _permissions[0] = true;
        vm.startPrank(factoryOwner);
        factory.setPlugins(_plugins, _permissions);
        vm.stopPrank();

        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("PluginExecutor");
        vm.startPrank(ownerAddr);
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        address[] memory plugins = new address[](1);
        bytes32[] memory manifestHashes = new bytes32[](1);
        bytes[] memory pluginInstallData = new bytes[](1);
        plugins[0] = address(singleOwnerPlugin);
        manifestHashes[0] = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
        pluginInstallData[0] = abi.encode(ownerAddr);
        bytes memory initializingData = abi.encode(plugins, manifestHashes, pluginInstallData);
        msca = factory.createAccount(ownerAddr, salt, initializingData);
        console.logString("msca address:");
        console.logAddress(address(msca));
        console.logString("single owner plugin address:");
        console.logAddress(address(singleOwnerPlugin));
        console.logString("owner address:");
        console.logAddress(ownerAddr);
        mscaAddr = address(msca);
        testTokenPlugin = new TestTokenPlugin();
        PluginMetadata memory pluginMetadata = testTokenPlugin.pluginMetadata();
        assertEq(pluginMetadata.name, "Test Token Plugin");
        assertEq(pluginMetadata.version, PLUGIN_VERSION_1);
        assertEq(pluginMetadata.author, PLUGIN_AUTHOR);
        console.logString("test token plugin address:");
        console.logAddress(address(testTokenPlugin));
        testPermitAnyExternalAddressPlugin = new TestPermitAnyExternalAddressPlugin();
        pluginMetadata = testPermitAnyExternalAddressPlugin.pluginMetadata();
        assertEq(pluginMetadata.name, "Test Permit Any External Contract Plugin");
        assertEq(pluginMetadata.version, PLUGIN_VERSION_1);
        assertEq(pluginMetadata.author, PLUGIN_AUTHOR);
        console.logString("test permit any external contract plugin address:");
        console.logAddress(address(testPermitAnyExternalAddressPlugin));
        longLiquidityPool = new TestLiquidityPool("Token plugin long liquidity pool", "+$$$");
        shortLiquidityPool = new TestLiquidityPool("Token plugin short liquidity pool", "+$$$");
        longLiquidityPoolAddr = address(longLiquidityPool);
        shortLiquidityPoolAddr = address(shortLiquidityPool);
        console.logString("longLiquidityPool address:");
        console.logAddress(longLiquidityPoolAddr);
        console.logString("shortLiquidityPool address:");
        console.logAddress(shortLiquidityPoolAddr);
        testTokenWithPostHookOnlyPlugin = new TestTokenWithPostHookOnlyPlugin();
        testPermitAnyExternalAddressWithPostHookOnlyPlugin = new TestPermitAnyExternalAddressWithPostHookOnlyPlugin();
        testTokenWithPreHookOnlyPlugin = new TestTokenWithPreHookOnlyPlugin();
        testPermitAnyExternalAddressWithPreHookOnlyPlugin = new TestPermitAnyExternalAddressWithPreHookOnlyPlugin();
        vm.stopPrank();
    }

    /// https://eips.ethereum.org/assets/eip-6900/Plugin_Execution_Flow.svg
    function testExecuteFromPluginWithPermission() public {
        // deployment was done in setUp
        assertTrue(address(msca).code.length != 0);
        // nonce key is 0
        // start with balance
        vm.deal(address(msca), 10 ether);
        bytes32 manifestHash = keccak256(abi.encode(testTokenPlugin.pluginManifest()));
        // airdrop 1000 tokens
        bytes memory pluginInstallData = abi.encode(1000);
        FunctionReference[] memory dependencies = new FunctionReference[](1);
        // import SingleOwnerPlugin as dependency
        dependencies[0] =
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        bytes memory installPluginCallData = abi.encodeCall(
            IPluginManager.installPlugin, (address(testTokenPlugin), manifestHash, pluginInstallData, dependencies)
        );
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca),
            0,
            "0x",
            vm.toString(installPluginCallData),
            10053353,
            103353,
            45484,
            516219199704,
            1130000000,
            "0x"
        ); // no paymaster

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        // signed by singleOwnerPlugin
        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        emit UserOperationEvent(userOpHash, address(msca), address(0), 0, true, 2649665810000000, 2344837);
        entryPoint.handleOps(ops, beneficiary);
        // verify the plugin has been installed
        assertEq(msca.sizeOfPlugins(), 2);
        address[] memory installedPlugins = msca.getInstalledPlugins();
        assertEq(installedPlugins[0], address(singleOwnerPlugin));
        assertEq(installedPlugins[1], address(testTokenPlugin));
        // verify pluginDetail
        TestCircleMSCA.PluginDetailWrapper memory pluginDetail = msca.getPluginDetail(address(testTokenPlugin));
        assertFalse(pluginDetail.anyExternalAddressPermitted);
        assertEq(pluginDetail.dependentCounter, 0);
        assertEq(pluginDetail.manifestHash, manifestHash);
        assertEq(pluginDetail.dependencies.length, 1);
        TestCircleMSCA.PluginDetailWrapper memory singleOwnerPluginDetailWrapper =
            msca.getPluginDetail(address(singleOwnerPlugin));
        // now SingleOwnerPlugin has one dependent
        assertEq(singleOwnerPluginDetailWrapper.dependentCounter, 1);
        // verify airdrop amount initiated during installation
        assertEq(testTokenPlugin.balanceOf(mscaAddr), 1000);
        bool selectorPermitted = msca.getPermittedPluginCallSelectorPermitted(
            address(testTokenPlugin), ISingleOwnerPlugin.getOwnerOf.selector
        );
        assertTrue(selectorPermitted);
        vm.stopPrank();

        // call airdropToken via another userOp
        bytes memory executeFromPluginAllowedCallData = abi.encodeCall(testTokenPlugin.airdropToken, (234));
        userOp = buildPartialUserOp(
            address(msca),
            1,
            "0x",
            vm.toString(executeFromPluginAllowedCallData),
            10053353,
            103353,
            45484,
            516219199704,
            1130000000,
            "0x"
        ); // no paymaster

        userOpHash = entryPoint.getUserOpHash(userOp);
        // eoaPrivateKey from singleOwnerPlugin
        signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;
        ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));

        // pre execution hook event
        vm.expectEmit(true, true, true, true);
        emit PreExecutionHookCalled(
            uint8(TestTokenPlugin.FunctionId.PRE_EXECUTION_HOOK),
            address(testTokenPlugin),
            0,
            abi.encodeCall(ISingleOwnerPlugin.getOwnerOf, (address(msca)))
        );

        // post execution hook event
        vm.expectEmit(true, true, true, true);
        emit PostExecutionHookCalled(uint8(TestTokenPlugin.FunctionId.POST_EXECUTION_HOOK), abi.encode(testTokenPlugin));

        // user op event
        vm.expectEmit(true, true, true, false);
        // no paymaster
        emit UserOperationEvent(userOpHash, address(msca), address(0), 1, true, 154546710000000, 136767);
        entryPoint.handleOps(ops, beneficiary);
        // verify the amount has been increased by airdrop
        assertEq(testTokenPlugin.balanceOf(ownerAddr), 234);
        vm.stopPrank();
    }

    /// https://eips.ethereum.org/assets/eip-6900/Plugin_Execution_Flow.svg
    function testExecuteFromPluginWithoutPermission() public {
        // deployment was done in setUp
        assertTrue(address(msca).code.length != 0);
        // nonce key is 0
        // start with balance
        vm.deal(address(msca), 10 ether);
        bytes32 manifestHash = keccak256(abi.encode(testTokenPlugin.pluginManifest()));
        // airdrop 1000 tokens
        FunctionReference[] memory dependencies = new FunctionReference[](1);
        // import SingleOwnerPlugin as dependency
        dependencies[0] =
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        bytes memory installPluginCallData = abi.encodeCall(
            IPluginManager.installPlugin, (address(testTokenPlugin), manifestHash, abi.encode(1000), dependencies)
        );
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca),
            0,
            "0x",
            vm.toString(installPluginCallData),
            10053353,
            103353,
            45484,
            516219199704,
            1130000000,
            "0x"
        ); // no paymaster

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        // signed by singleOwnerPlugin
        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        emit UserOperationEvent(userOpHash, address(msca), address(0), 0, true, 2082518810000000, 1842937);
        entryPoint.handleOps(ops, beneficiary);
        // verify the plugin has been installed
        assertEq(msca.sizeOfPlugins(), 2);
        address[] memory installedPlugins = msca.getInstalledPlugins();
        assertEq(installedPlugins[0], address(singleOwnerPlugin));
        assertEq(installedPlugins[1], address(testTokenPlugin));
        // verify pluginDetail
        TestCircleMSCA.PluginDetailWrapper memory pluginDetail = msca.getPluginDetail(address(testTokenPlugin));
        assertFalse(pluginDetail.anyExternalAddressPermitted);
        assertEq(pluginDetail.dependentCounter, 0);
        assertEq(pluginDetail.manifestHash, manifestHash);
        assertEq(pluginDetail.dependencies.length, 1);
        TestCircleMSCA.PluginDetailWrapper memory singleOwnerPluginDetailWrapper =
            msca.getPluginDetail(address(singleOwnerPlugin));
        // now SingleOwnerPlugin has one dependent
        assertEq(singleOwnerPluginDetailWrapper.dependentCounter, 1);
        // verify airdrop amount initiated during installation
        assertEq(testTokenPlugin.balanceOf(mscaAddr), 1000);
        bool selectorPermitted = msca.getPermittedPluginCallSelectorPermitted(
            address(testTokenPlugin), ISingleOwnerPlugin.getOwnerOf.selector
        );
        assertTrue(selectorPermitted);
        selectorPermitted = msca.getPermittedPluginCallSelectorPermitted(
            address(testTokenPlugin), ISingleOwnerPlugin.transferOwnership.selector
        );
        assertFalse(selectorPermitted);
        vm.stopPrank();

        // call airdropTokenBad via another userOp
        userOp = buildPartialUserOp(
            address(msca),
            1,
            "0x",
            vm.toString(abi.encodeCall(testTokenPlugin.airdropTokenBad, (234))),
            10053353,
            103353,
            45484,
            516219199704,
            1130000000,
            "0x"
        ); // no paymaster

        userOpHash = entryPoint.getUserOpHash(userOp);
        // eoaPrivateKey from singleOwnerPlugin
        signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;
        ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, true);
        emit UserOperationRevertReason(
            userOpHash,
            address(msca),
            1,
            abi.encodeWithSelector(
                bytes4(keccak256("ExecFromPluginToSelectorNotPermitted(address,bytes4)")),
                address(testTokenPlugin),
                bytes4(keccak256("transferOwnership(address)"))
            )
        );
        entryPoint.handleOps(ops, beneficiary);
        // verify the amount has not changed
        assertEq(testTokenPlugin.balanceOf(ownerAddr), 0);
        vm.stopPrank();
    }

    /// https://eips.ethereum.org/assets/eip-6900/Plugin_Execution_Flow.svg
    function testExecuteFromPluginWithPostOnlyHookWithPermission() public {
        testExecuteFromPluginWithPreOrPostOnlyHookWithPermission(
            testTokenWithPostHookOnlyPlugin.airdropToken.selector, testTokenWithPostHookOnlyPlugin
        );
    }

    /// https://eips.ethereum.org/assets/eip-6900/Plugin_Execution_Flow.svg
    function testExecuteFromPluginWithPreOnlyHookWithPermission() public {
        testExecuteFromPluginWithPreOrPostOnlyHookWithPermission(
            testTokenWithPreHookOnlyPlugin.airdropToken.selector, testTokenWithPreHookOnlyPlugin
        );
    }

    // whitelist one function in contract and all functions in another contract
    /// https://eips.ethereum.org/assets/eip-6900/Plugin_Execution_Flow.svg
    function testExecuteFromPluginIntoExternalContractAllowed() public {
        // deployment was done in setUp
        assertTrue(address(msca).code.length != 0);
        // start with balance
        vm.deal(address(msca), 10 ether);
        bytes32 manifestHash = keccak256(abi.encode(testTokenPlugin.pluginManifest()));
        // airdrop 1000 tokens
        bytes memory pluginInstallData = abi.encode(1000);
        FunctionReference[] memory dependencies = new FunctionReference[](1);
        // import SingleOwnerPlugin as dependency
        dependencies[0] =
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        bytes memory installPluginCallData = abi.encodeCall(
            IPluginManager.installPlugin, (address(testTokenPlugin), manifestHash, pluginInstallData, dependencies)
        );
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca),
            0,
            "0x",
            vm.toString(installPluginCallData),
            10053353,
            103353,
            45484,
            516219199704,
            1130000000,
            "0x"
        ); // no paymaster

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        // signed by singleOwnerPlugin
        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        emit UserOperationEvent(userOpHash, address(msca), address(0), 0, true, 2649665810000000, 2344837);
        entryPoint.handleOps(ops, beneficiary);
        // verify the plugin has been installed
        assertEq(msca.sizeOfPlugins(), 2);
        address[] memory installedPlugins = msca.getInstalledPlugins();
        assertEq(installedPlugins[0], address(singleOwnerPlugin));
        assertEq(installedPlugins[1], address(testTokenPlugin));
        // verify pluginDetail
        TestCircleMSCA.PluginDetailWrapper memory pluginDetail = msca.getPluginDetail(address(testTokenPlugin));
        assertFalse(pluginDetail.anyExternalAddressPermitted);
        assertEq(pluginDetail.dependentCounter, 0);
        assertEq(pluginDetail.manifestHash, manifestHash);
        assertEq(pluginDetail.dependencies.length, 1);
        TestCircleMSCA.PluginDetailWrapper memory singleOwnerPluginDetailWrapper =
            msca.getPluginDetail(address(singleOwnerPlugin));
        // now SingleOwnerPlugin has one dependent
        assertEq(singleOwnerPluginDetailWrapper.dependentCounter, 1);
        // verify airdrop amount initiated during installation
        assertEq(testTokenPlugin.balanceOf(mscaAddr), 1000);
        // can access any functions in longLiquidityPool
        assertTrue(
            msca.getPermittedExternalCall(
                address(testTokenPlugin), longLiquidityPoolAddr, TestLiquidityPool.mint.selector
            )
        );
        assertTrue(
            msca.getPermittedExternalCall(
                address(testTokenPlugin), longLiquidityPoolAddr, TestLiquidityPool.supplyLiquidity.selector
            )
        );
        // can only access mint function in shortLiquidityPool
        assertTrue(
            msca.getPermittedExternalCall(
                address(testTokenPlugin), shortLiquidityPoolAddr, TestLiquidityPool.mint.selector
            )
        );
        assertFalse(
            msca.getPermittedExternalCall(
                address(testTokenPlugin), shortLiquidityPoolAddr, TestLiquidityPool.supplyLiquidity.selector
            )
        );
        vm.stopPrank();

        // call mintToken via another userOp
        bytes memory executeFromPluginExternalAllowedCallData = abi.encodeCall(testTokenPlugin.mintToken, (123));
        userOp = buildPartialUserOp(
            address(msca),
            1,
            "0x",
            vm.toString(executeFromPluginExternalAllowedCallData),
            10053353,
            103353,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        userOpHash = entryPoint.getUserOpHash(userOp);
        // eoaPrivateKey from singleOwnerPlugin
        signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;
        ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        bytes memory data = abi.encodeCall(
            IPluginExecutor.executeFromPluginExternal,
            (longLiquidityPoolAddr, 0, abi.encodeCall(TestLiquidityPool.mint, (address(msca), 123)))
        );

        // pre execution hook event
        vm.expectEmit(true, true, true, true);
        emit PreExecutionHookCalled(
            uint8(TestTokenPlugin.FunctionId.PRE_EXECUTION_HOOK), address(testTokenPlugin), 0, data
        );

        // post execution hook event
        vm.expectEmit(true, true, true, true);
        emit PostExecutionHookCalled(uint8(TestTokenPlugin.FunctionId.POST_EXECUTION_HOOK), abi.encode(testTokenPlugin));

        // user op event
        vm.expectEmit(true, true, true, false);
        emit UserOperationEvent(userOpHash, address(msca), address(0), 1, true, 154546710000000, 136767);
        entryPoint.handleOps(ops, beneficiary);
        // verify the amount has been increased by mint
        assertEq(longLiquidityPool.balanceOf(mscaAddr), 123);
        assertEq(shortLiquidityPool.balanceOf(mscaAddr), 123);
        vm.stopPrank();
    }

    /// https://eips.ethereum.org/assets/eip-6900/Plugin_Execution_Flow.svg
    function testExecuteFromPluginIntoExternalContractNotAllowed() public {
        // deployment was done in setUp
        assertTrue(address(msca).code.length != 0);
        // start with balance
        vm.deal(address(msca), 10 ether);
        bytes32 manifestHash = keccak256(abi.encode(testTokenPlugin.pluginManifest()));
        // airdrop 1000 tokens
        bytes memory pluginInstallData = abi.encode(1000);
        FunctionReference[] memory dependencies = new FunctionReference[](1);
        // import SingleOwnerPlugin as dependency
        dependencies[0] =
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        bytes memory installPluginCallData = abi.encodeCall(
            IPluginManager.installPlugin, (address(testTokenPlugin), manifestHash, pluginInstallData, dependencies)
        );
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca),
            0,
            "0x",
            vm.toString(installPluginCallData),
            10053353,
            103353,
            45484,
            516219199704,
            1130000000,
            "0x"
        ); // no paymaster

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        // signed by singleOwnerPlugin
        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        emit UserOperationEvent(userOpHash, address(msca), address(0), 0, true, 2649665810000000, 2344837);
        entryPoint.handleOps(ops, beneficiary);
        // verify the plugin has been installed
        assertEq(msca.sizeOfPlugins(), 2);
        address[] memory installedPlugins = msca.getInstalledPlugins();
        assertEq(installedPlugins[0], address(singleOwnerPlugin));
        assertEq(installedPlugins[1], address(testTokenPlugin));
        // verify pluginDetail
        TestCircleMSCA.PluginDetailWrapper memory pluginDetail = msca.getPluginDetail(address(testTokenPlugin));
        assertFalse(pluginDetail.anyExternalAddressPermitted);
        assertEq(pluginDetail.dependentCounter, 0);
        assertEq(pluginDetail.manifestHash, manifestHash);
        assertEq(pluginDetail.dependencies.length, 1);
        TestCircleMSCA.PluginDetailWrapper memory singleOwnerPluginDetailWrapper =
            msca.getPluginDetail(address(singleOwnerPlugin));
        // now SingleOwnerPlugin has one dependent
        assertEq(singleOwnerPluginDetailWrapper.dependentCounter, 1);
        // verify airdrop amount initiated during installation
        assertEq(testTokenPlugin.balanceOf(mscaAddr), 1000);
        // can access any functions in longLiquidityPool
        assertTrue(
            msca.getPermittedExternalCall(
                address(testTokenPlugin), longLiquidityPoolAddr, TestLiquidityPool.mint.selector
            )
        );
        assertTrue(
            msca.getPermittedExternalCall(
                address(testTokenPlugin), longLiquidityPoolAddr, TestLiquidityPool.supplyLiquidity.selector
            )
        );
        // can only access mint function in shortLiquidityPool
        assertTrue(
            msca.getPermittedExternalCall(
                address(testTokenPlugin), shortLiquidityPoolAddr, TestLiquidityPool.mint.selector
            )
        );
        assertFalse(
            msca.getPermittedExternalCall(
                address(testTokenPlugin), shortLiquidityPoolAddr, TestLiquidityPool.supplyLiquidity.selector
            )
        );
        vm.stopPrank();

        // call supplyLiquidity via userOp, which is allowed for longLiquidityPool
        TestCircleMSCA recipient = new TestCircleMSCA(entryPoint, pluginManager);
        // mint to sender first
        longLiquidityPool.mint(mscaAddr, 2000000);
        // approve sender allowance
        bytes memory approveCallData = abi.encodeCall(longLiquidityPool.approve, (longLiquidityPoolAddr, 1000000));
        // executeFromPluginToExternalContract allowed
        bytes memory supplyLiquidityCallData =
            abi.encodeCall(testTokenPlugin.supplyLiquidity, (address(recipient), 123));
        // batch txs to grant allowance first
        Call[] memory calls = new Call[](2);
        calls[0].target = longLiquidityPoolAddr;
        calls[0].value = 0;
        calls[0].data = approveCallData;
        calls[1].target = mscaAddr; // plugin
        calls[1].value = 0;
        calls[1].data = supplyLiquidityCallData;
        bytes memory executeBatchCallData = abi.encodeCall(IStandardExecutor.executeBatch, calls);
        userOp = buildPartialUserOp(
            address(msca),
            1,
            "0x",
            vm.toString(executeBatchCallData),
            10053353,
            103353,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        userOpHash = entryPoint.getUserOpHash(userOp);
        // eoaPrivateKey from singleOwnerPlugin
        signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;
        ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        emit UserOperationEvent(userOpHash, address(msca), address(0), 1, true, 154546710000000, 136767);
        entryPoint.handleOps(ops, beneficiary);
        // verify the amount has been increased by supplyLiquidity
        assertEq(longLiquidityPool.balanceOf(address(recipient)), 123);
        vm.stopPrank();

        // call supplyLiquidityBad via userOp, which is not allowed for shortLiquidityPool
        recipient = new TestCircleMSCA(entryPoint, pluginManager);
        // mint to sender first
        shortLiquidityPool.mint(mscaAddr, 2000000);
        // approve address(msca) allowance
        approveCallData = abi.encodeCall(shortLiquidityPool.approve, (shortLiquidityPoolAddr, 1000000));
        // executeFromPluginToExternalContract is not allowed for supplyLiquidityBad
        supplyLiquidityCallData = abi.encodeCall(testTokenPlugin.supplyLiquidityBad, (address(recipient), 123));
        // batch txs to grant allowance first
        calls = new Call[](2);
        calls[0].target = shortLiquidityPoolAddr;
        calls[0].value = 0;
        calls[0].data = approveCallData;
        calls[1].target = mscaAddr; // plugin
        calls[1].value = 0;
        calls[1].data = supplyLiquidityCallData;
        executeBatchCallData = abi.encodeCall(IStandardExecutor.executeBatch, calls);
        userOp = buildPartialUserOp(
            address(msca),
            2,
            "0x",
            vm.toString(executeBatchCallData),
            10053353,
            103353,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        userOpHash = entryPoint.getUserOpHash(userOp);
        // eoaPrivateKey from singleOwnerPlugin
        signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;
        ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        bytes4 errorSelector = bytes4(keccak256("supplyLiquidity(address,address,uint256)"));
        bytes memory revertReason = abi.encodeWithSelector(
            bytes4(keccak256("ExecFromPluginToSelectorNotPermitted(address,bytes4)")),
            address(testTokenPlugin),
            errorSelector
        );
        vm.expectEmit(true, true, true, true);
        emit UserOperationRevertReason(userOpHash, address(msca), 2, revertReason);
        entryPoint.handleOps(ops, beneficiary);
        // verify the amount has not been increased due to lack of permission
        assertEq(shortLiquidityPool.balanceOf(address(recipient)), 0);
        vm.stopPrank();
    }

    // whitelist any contracts
    /// https://eips.ethereum.org/assets/eip-6900/Plugin_Execution_Flow.svg
    function testExecuteFromPluginIntoAnyExternalContractAllowed() public {
        // deployment was done in setUp
        assertTrue(address(msca).code.length != 0);
        uint256 acctNonce = entryPoint.getNonce(address(msca), 0);
        // start with balance
        vm.deal(address(msca), 10 ether);
        bytes32 manifestHash = keccak256(abi.encode(testPermitAnyExternalAddressPlugin.pluginManifest()));
        FunctionReference[] memory dependencies = new FunctionReference[](0);
        bytes memory installPluginCallData = abi.encodeCall(
            IPluginManager.installPlugin, (address(testPermitAnyExternalAddressPlugin), manifestHash, "", dependencies)
        );
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca),
            acctNonce,
            "0x",
            vm.toString(installPluginCallData),
            10053353,
            103353,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        // signed by singleOwnerPlugin
        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        emit UserOperationEvent(userOpHash, address(msca), address(0), acctNonce, true, 2649665810000000, 2344837);
        entryPoint.handleOps(ops, beneficiary);
        // verify the plugin has been installed
        assertEq(msca.sizeOfPlugins(), 2);
        address[] memory installedPlugins = msca.getInstalledPlugins();
        assertEq(installedPlugins[0], address(singleOwnerPlugin));
        assertEq(installedPlugins[1], address(testPermitAnyExternalAddressPlugin));
        // verify pluginDetail
        TestCircleMSCA.PluginDetailWrapper memory pluginDetail =
            msca.getPluginDetail(address(testPermitAnyExternalAddressPlugin));
        assertTrue(pluginDetail.anyExternalAddressPermitted);
        assertEq(pluginDetail.dependentCounter, 0);
        assertEq(pluginDetail.manifestHash, manifestHash);
        assertEq(pluginDetail.dependencies.length, 0);
        // can access any functions in longLiquidityPool
        assertTrue(
            msca.getPermittedExternalCall(
                address(testPermitAnyExternalAddressPlugin), longLiquidityPoolAddr, TestLiquidityPool.mint.selector
            )
        );
        assertTrue(
            msca.getPermittedExternalCall(
                address(testPermitAnyExternalAddressPlugin),
                longLiquidityPoolAddr,
                TestLiquidityPool.supplyLiquidity.selector
            )
        );
        // can access any function in shortLiquidityPool
        assertTrue(
            msca.getPermittedExternalCall(
                address(testPermitAnyExternalAddressPlugin), shortLiquidityPoolAddr, TestLiquidityPool.mint.selector
            )
        );
        assertTrue(
            msca.getPermittedExternalCall(
                address(testPermitAnyExternalAddressPlugin),
                shortLiquidityPoolAddr,
                TestLiquidityPool.supplyLiquidity.selector
            )
        );
        vm.stopPrank();

        // call mintToken via another userOp
        bytes memory executeFromPluginExternalAllowedCallData = abi.encodeCall(
            testPermitAnyExternalAddressPlugin.mintToken, (234, longLiquidityPoolAddr, shortLiquidityPoolAddr)
        );
        userOp = buildPartialUserOp(
            address(msca),
            acctNonce + 1,
            "0x",
            vm.toString(executeFromPluginExternalAllowedCallData),
            10053353,
            103353,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        userOpHash = entryPoint.getUserOpHash(userOp);
        // eoaPrivateKey from singleOwnerPlugin
        signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;
        ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));

        // pre execution hook event
        vm.expectEmit(true, true, true, true);
        emit PreExecutionHookCalled(
            uint8(TestPermitAnyExternalAddressPlugin.FunctionId.PRE_EXECUTION_HOOK),
            address(testPermitAnyExternalAddressPlugin),
            0,
            abi.encodeCall(
                IPluginExecutor.executeFromPluginExternal,
                (longLiquidityPoolAddr, 0, abi.encodeCall(TestLiquidityPool.mint, (address(msca), 234)))
            )
        );

        // post execution hook event
        vm.expectEmit(true, true, true, true);
        emit PostExecutionHookCalled(
            uint8(TestPermitAnyExternalAddressPlugin.FunctionId.POST_EXECUTION_HOOK),
            abi.encode(testPermitAnyExternalAddressPlugin)
        );

        // user op event
        vm.expectEmit(true, true, true, false);
        emit UserOperationEvent(userOpHash, address(msca), address(0), acctNonce + 1, true, 154546710000000, 136767);
        entryPoint.handleOps(ops, beneficiary);
        // verify the amount has been increased by mint
        assertEq(longLiquidityPool.balanceOf(mscaAddr), 234);
        assertEq(shortLiquidityPool.balanceOf(mscaAddr), 234);
        vm.stopPrank();
    }

    /// https://eips.ethereum.org/assets/eip-6900/Plugin_Execution_Flow.svg
    function testExecuteFromPluginIntoExternalContractNotAllowedToSpendNativeToken() public {
        // deployment was done in setUp
        assertTrue(address(msca).code.length != 0);
        uint256 acctNonce = entryPoint.getNonce(address(msca), 0);
        // start with balance
        vm.deal(address(msca), 10 ether);
        bytes32 manifestHash = keccak256(abi.encode(testPermitAnyExternalAddressPlugin.pluginManifest()));
        FunctionReference[] memory dependencies = new FunctionReference[](0);
        bytes memory installPluginCallData = abi.encodeCall(
            IPluginManager.installPlugin, (address(testPermitAnyExternalAddressPlugin), manifestHash, "", dependencies)
        );
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca),
            acctNonce,
            "0x",
            vm.toString(installPluginCallData),
            10053353,
            103353,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        // signed by singleOwnerPlugin
        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        emit UserOperationEvent(userOpHash, address(msca), address(0), acctNonce, true, 2649665810000000, 2344837);
        entryPoint.handleOps(ops, beneficiary);
        // verify the plugin has been installed
        assertEq(msca.sizeOfPlugins(), 2);
        address[] memory installedPlugins = msca.getInstalledPlugins();
        assertEq(installedPlugins[0], address(singleOwnerPlugin));
        assertEq(installedPlugins[1], address(testPermitAnyExternalAddressPlugin));
        // verify pluginDetail
        TestCircleMSCA.PluginDetailWrapper memory pluginDetail =
            msca.getPluginDetail(address(testPermitAnyExternalAddressPlugin));
        assertTrue(pluginDetail.anyExternalAddressPermitted);
        assertEq(pluginDetail.dependentCounter, 0);
        assertEq(pluginDetail.manifestHash, manifestHash);
        assertEq(pluginDetail.dependencies.length, 0);
        assertFalse(pluginDetail.canSpendNativeToken);
        vm.stopPrank();

        // send native token via another userOp
        bytes memory spendNativeTokenNotAllowedCallData =
            abi.encodeCall(testPermitAnyExternalAddressPlugin.spendNativeToken, (234, longLiquidityPoolAddr));
        userOp = buildPartialUserOp(
            address(msca),
            acctNonce + 1,
            "0x",
            vm.toString(spendNativeTokenNotAllowedCallData),
            10053353,
            103353,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        userOpHash = entryPoint.getUserOpHash(userOp);
        // eoaPrivateKey from singleOwnerPlugin
        signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;
        ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, true);
        bytes4 errorSelector = bytes4(keccak256("NativeTokenSpendingNotPermitted(address)"));
        emit UserOperationRevertReason(
            userOpHash,
            address(msca),
            acctNonce + 1,
            abi.encodeWithSelector(errorSelector, testPermitAnyExternalAddressPlugin)
        );
        entryPoint.handleOps(ops, beneficiary);
        // verify the call didn't succeed
        assertEq(longLiquidityPoolAddr.balance, 0 ether);
        vm.stopPrank();
    }

    /// https://eips.ethereum.org/assets/eip-6900/Plugin_Execution_Flow.svg
    function testExecuteFromPluginIntoAnyExternalContractWithPostHookOnlyAllowed() public {
        testExecuteFromPluginIntoExternalContractWithPreOrPostHookOnlyAllowed(
            testPermitAnyExternalAddressWithPostHookOnlyPlugin.mintToken.selector,
            testPermitAnyExternalAddressWithPostHookOnlyPlugin
        );
    }

    /// https://eips.ethereum.org/assets/eip-6900/Plugin_Execution_Flow.svg
    function testExecuteFromPluginIntoExternalContractWithPreHookOnlyAllowed() public {
        testExecuteFromPluginIntoExternalContractWithPreOrPostHookOnlyAllowed(
            testPermitAnyExternalAddressWithPreHookOnlyPlugin.mintToken.selector,
            testPermitAnyExternalAddressWithPreHookOnlyPlugin
        );
    }

    function testExecuteFromPluginIntoExternalContractNotAllowedToCallItself() public {
        // deployment was done in setUp
        assertTrue(address(msca).code.length != 0);
        uint256 acctNonce = entryPoint.getNonce(address(msca), 0);
        // start with balance
        vm.deal(address(msca), 10 ether);
        bytes32 manifestHash = keccak256(abi.encode(testPermitAnyExternalAddressPlugin.pluginManifest()));
        FunctionReference[] memory dependencies = new FunctionReference[](0);
        bytes memory installPluginCallData = abi.encodeCall(
            IPluginManager.installPlugin, (address(testPermitAnyExternalAddressPlugin), manifestHash, "", dependencies)
        );
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca),
            acctNonce,
            "0x",
            vm.toString(installPluginCallData),
            10053353,
            103353,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        // signed by singleOwnerPlugin
        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        emit UserOperationEvent(userOpHash, address(msca), address(0), acctNonce, true, 2649665810000000, 2344837);
        entryPoint.handleOps(ops, beneficiary);
        // verify the plugin has been installed
        assertEq(msca.sizeOfPlugins(), 2);
        address[] memory installedPlugins = msca.getInstalledPlugins();
        assertEq(installedPlugins[0], address(singleOwnerPlugin));
        assertEq(installedPlugins[1], address(testPermitAnyExternalAddressPlugin));
        vm.stopPrank();

        bytes memory callbackNotAllowedCallData =
            abi.encodeCall(testPermitAnyExternalAddressPlugin.callBackToAccount, ());
        userOp = buildPartialUserOp(
            address(msca),
            acctNonce + 1,
            "0x",
            vm.toString(callbackNotAllowedCallData),
            10053353,
            103353,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        userOpHash = entryPoint.getUserOpHash(userOp);
        // eoaPrivateKey from singleOwnerPlugin
        signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;
        ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, true);
        bytes4 errorSelector = bytes4(keccak256("ExecuteFromPluginToExternalNotPermitted()"));
        emit UserOperationRevertReason(userOpHash, address(msca), acctNonce + 1, abi.encodeWithSelector(errorSelector));
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
    }

    /// https://eips.ethereum.org/assets/eip-6900/Plugin_Execution_Flow.svg
    function testExecuteFromPluginWithPreOrPostOnlyHookWithPermission(bytes4 hookPluginSelector, IPlugin hookPlugin)
        private
    {
        // deployment was done in setUp
        assertTrue(address(msca).code.length != 0);
        // nonce key is 0
        // start with balance
        vm.deal(address(msca), 10 ether);
        bytes32 manifestHash = keccak256(abi.encode(hookPlugin.pluginManifest()));
        // airdrop 1000 tokens
        FunctionReference[] memory dependencies = new FunctionReference[](1);
        // import SingleOwnerPlugin as dependency
        dependencies[0] =
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        bytes memory installPluginCallData = abi.encodeCall(
            IPluginManager.installPlugin, (address(hookPlugin), manifestHash, abi.encode(1000), dependencies)
        );
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca),
            0,
            "0x",
            vm.toString(installPluginCallData),
            10053353,
            103353,
            45484,
            516219199704,
            1130000000,
            "0x"
        ); // no paymaster

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        // signed by singleOwnerPlugin
        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        emit UserOperationEvent(userOpHash, address(msca), address(0), 0, true, 2649665810000000, 2344837);
        entryPoint.handleOps(ops, beneficiary);
        // verify the plugin has been installed
        assertEq(msca.sizeOfPlugins(), 2);
        address[] memory installedPlugins = msca.getInstalledPlugins();
        assertEq(installedPlugins[0], address(singleOwnerPlugin));
        assertEq(installedPlugins[1], address(hookPlugin));
        // verify pluginDetail
        TestCircleMSCA.PluginDetailWrapper memory pluginDetail = msca.getPluginDetail(address(hookPlugin));
        assertFalse(pluginDetail.anyExternalAddressPermitted);
        assertEq(pluginDetail.dependentCounter, 0);
        assertEq(pluginDetail.manifestHash, manifestHash);
        assertEq(pluginDetail.dependencies.length, 1);
        TestCircleMSCA.PluginDetailWrapper memory singleOwnerPluginDetailWrapper =
            msca.getPluginDetail(address(singleOwnerPlugin));
        // now SingleOwnerPlugin has one dependent
        assertEq(singleOwnerPluginDetailWrapper.dependentCounter, 1);
        bool selectorPermitted =
            msca.getPermittedPluginCallSelectorPermitted(address(hookPlugin), ISingleOwnerPlugin.getOwnerOf.selector);
        assertTrue(selectorPermitted);
        vm.stopPrank();

        // call airdropToken via another userOp
        bytes memory executeFromPluginAllowedCallData = abi.encodeWithSelector(hookPluginSelector, 234);
        userOp = buildPartialUserOp(
            address(msca),
            1,
            "0x",
            vm.toString(executeFromPluginAllowedCallData),
            10053353,
            103353,
            45484,
            516219199704,
            1130000000,
            "0x"
        ); // no paymaster

        userOpHash = entryPoint.getUserOpHash(userOp);
        // eoaPrivateKey from singleOwnerPlugin
        signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;
        ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        // no paymaster
        emit UserOperationEvent(userOpHash, address(msca), address(0), 1, true, 154546710000000, 136767);
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
    }

    function testExecuteFromPluginIntoExternalContractWithPreOrPostHookOnlyAllowed(
        bytes4 hookPluginSelector,
        IPlugin hookPlugin
    ) private {
        // deployment was done in setUp
        assertTrue(address(msca).code.length != 0);
        uint256 acctNonce = entryPoint.getNonce(address(msca), 0);
        // start with balance
        vm.deal(address(msca), 10 ether);
        bytes32 manifestHash = keccak256(abi.encode(hookPlugin.pluginManifest()));
        FunctionReference[] memory dependencies = new FunctionReference[](0);
        bytes memory installPluginCallData =
            abi.encodeCall(IPluginManager.installPlugin, (address(hookPlugin), manifestHash, "", dependencies));
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca),
            acctNonce,
            "0x",
            vm.toString(installPluginCallData),
            10053353,
            103353,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        // signed by singleOwnerPlugin
        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        emit UserOperationEvent(userOpHash, address(msca), address(0), acctNonce, true, 2649665810000000, 2344837);
        entryPoint.handleOps(ops, beneficiary);
        // verify the plugin has been installed
        assertEq(msca.sizeOfPlugins(), 2);
        address[] memory installedPlugins = msca.getInstalledPlugins();
        assertEq(installedPlugins[0], address(singleOwnerPlugin));
        assertEq(installedPlugins[1], address(hookPlugin));
        // verify pluginDetail
        TestCircleMSCA.PluginDetailWrapper memory pluginDetail = msca.getPluginDetail(address(hookPlugin));
        assertTrue(pluginDetail.anyExternalAddressPermitted);
        assertEq(pluginDetail.dependentCounter, 0);
        assertEq(pluginDetail.manifestHash, manifestHash);
        assertEq(pluginDetail.dependencies.length, 0);
        // can access any functions in longLiquidityPool
        assertTrue(
            msca.getPermittedExternalCall(address(hookPlugin), longLiquidityPoolAddr, TestLiquidityPool.mint.selector)
        );
        assertTrue(
            msca.getPermittedExternalCall(
                address(hookPlugin), longLiquidityPoolAddr, TestLiquidityPool.supplyLiquidity.selector
            )
        );
        // can access any function in shortLiquidityPool
        assertTrue(
            msca.getPermittedExternalCall(address(hookPlugin), shortLiquidityPoolAddr, TestLiquidityPool.mint.selector)
        );
        assertTrue(
            msca.getPermittedExternalCall(
                address(hookPlugin), shortLiquidityPoolAddr, TestLiquidityPool.supplyLiquidity.selector
            )
        );
        vm.stopPrank();

        // call mintToken via another userOp
        bytes memory executeFromPluginExternalAllowedCallData =
            abi.encodeWithSelector(hookPluginSelector, 234, longLiquidityPoolAddr, shortLiquidityPoolAddr);
        userOp = buildPartialUserOp(
            address(msca),
            acctNonce + 1,
            "0x",
            vm.toString(executeFromPluginExternalAllowedCallData),
            10053353,
            103353,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        userOpHash = entryPoint.getUserOpHash(userOp);
        // eoaPrivateKey from singleOwnerPlugin
        signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;
        ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        emit UserOperationEvent(userOpHash, address(msca), address(0), acctNonce + 1, true, 154546710000000, 136767);
        entryPoint.handleOps(ops, beneficiary);
        // verify the amount has been increased by mint
        assertEq(longLiquidityPool.balanceOf(mscaAddr), 234);
        assertEq(shortLiquidityPool.balanceOf(mscaAddr), 234);
        vm.stopPrank();
    }
}
