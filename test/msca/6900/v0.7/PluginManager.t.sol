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
import "./TestUserOpValidatorWithDependencyHook.sol";
import {EMPTY_FUNCTION_REFERENCE} from "../../../../src/common/Constants.sol";

/// Tests for install/uninstall
contract PluginManagerTest is TestUtils {
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

    IEntryPoint private entryPoint = new EntryPoint();
    PluginManager private pluginManager = new PluginManager();
    uint256 internal eoaPrivateKey;
    address private ownerAddr;
    address payable beneficiary; // e.g. bundler
    TestCircleMSCAFactory private factory;
    SingleOwnerPlugin private singleOwnerPlugin;
    TestCircleMSCA private msca;
    TestTokenPlugin private testTokenPlugin;
    address private mscaAddr;
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

        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("PluginManagerTest");
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
        vm.stopPrank();
    }

    /// try to install a random smart contract that doesnt' implement the plugin interface
    /// try to install it from owner and non-owner separately
    function testInstallSCButNotPlugin() public {
        // try to install testLiquidityPool, which is not a plugin
        TestLiquidityPool testLiquidityPool = new TestLiquidityPool("bad", "bad");
        bytes32 manifestHash = keccak256(abi.encode(""));
        // install from an authenticated owner
        vm.startPrank(ownerAddr);
        bytes4 errorSelector = bytes4(keccak256("PluginNotImplementInterface()"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector));
        msca.installPlugin(address(testLiquidityPool), manifestHash, "", new FunctionReference[](0));
        vm.stopPrank();

        // install from a random address, should be rejected
        // UnauthorizedCaller is caught by the caller and converted to RuntimeValidationFailed
        vm.startPrank(address(1));
        bytes memory revertReason = abi.encodeWithSelector(bytes4(keccak256("UnauthorizedCaller()")));
        // function id from manifest
        uint8 functionId = uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF);
        vm.expectRevert(
            abi.encodeWithSelector(
                bytes4(keccak256("RuntimeValidationFailed(address,uint8,bytes)")),
                singleOwnerPlugin,
                functionId,
                revertReason
            )
        );
        msca.installPlugin(address(testLiquidityPool), manifestHash, "", new FunctionReference[](0));
        vm.stopPrank();
    }

    /// try to install and uninstall a new plugin via user op after single owner plugin has been installed as part of
    /// account deployment
    function testInstallAndUninstallNewPluginAfterAccountDeploymentWithSingleOwnerPlugin() public {
        // deployment was done in setUp
        assertTrue(address(msca).code.length != 0);
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
        // eoaPrivateKey from singleOwnerPlugin
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        // no paymaster
        emit UserOperationEvent(userOpHash, address(msca), address(0), 0, true, 264430170000000, 234009);
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
        vm.stopPrank();

        // uninstall via another userOp
        // we'll just use plugin manifest
        TestCircleMSCA anotherMSCA = new TestCircleMSCA(entryPoint, pluginManager);
        bytes memory pluginUninstallData = abi.encode(address(anotherMSCA), 999);
        bytes memory uninstallPluginCallData =
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(testTokenPlugin), "", pluginUninstallData));
        userOp = buildPartialUserOp(
            address(msca),
            1,
            "0x",
            vm.toString(uninstallPluginCallData),
            10053353,
            103353,
            45484,
            516219199704,
            1130000000,
            "0x"
        ); // no paymaster

        userOpHash = entryPoint.getUserOpHash(userOp);
        // eoaPrivateKey from singleOwnerPlugin
        signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        // no paymaster
        emit UserOperationEvent(userOpHash, address(msca), address(0), 1, true, 264430170000000, 234009);
        entryPoint.handleOps(ops, beneficiary);
        // verify the plugin has been uninstalled
        assertEq(msca.sizeOfPlugins(), 1);
        installedPlugins = msca.getInstalledPlugins();
        assertEq(installedPlugins[0], address(singleOwnerPlugin));
        // verify pluginDetail does not exist
        pluginDetail = msca.getPluginDetail(address(testTokenPlugin));
        assertEq(pluginDetail.manifestHash, "");
        // verify permittedExternalCalls
        // the plugin requested to call address(0) on 0x12345678
        assertFalse(msca.getPermittedExternalCall(address(testTokenPlugin), address(0x0), 0x12345678));
        // verify executionDetails
        // the plugin requested to install transferToken and balanceOf
        TestCircleMSCA.ExecutionDetailWrapper memory executionDetailWrapper =
            msca.getExecutionDetail(testTokenPlugin.transferToken.selector);
        assertEq(executionDetailWrapper.plugin, address(0));
        assertEq(executionDetailWrapper.userOpValidationFunction.pack(), EMPTY_FUNCTION_REFERENCE);
        assertEq(executionDetailWrapper.runtimeValidationFunction.pack(), EMPTY_FUNCTION_REFERENCE);
        assertEq(executionDetailWrapper.preUserOpValidationHooks.length, 0);
        assertEq(executionDetailWrapper.preRuntimeValidationHooks.length, 0);
        assertEq(executionDetailWrapper.executionHooks.length, 0);
        // balanceOf
        executionDetailWrapper = msca.getExecutionDetail(testTokenPlugin.balanceOf.selector);
        assertEq(executionDetailWrapper.plugin, address(0));
        assertEq(executionDetailWrapper.userOpValidationFunction.pack(), EMPTY_FUNCTION_REFERENCE);
        assertEq(executionDetailWrapper.runtimeValidationFunction.pack(), EMPTY_FUNCTION_REFERENCE);
        assertEq(executionDetailWrapper.preUserOpValidationHooks.length, 0);
        assertEq(executionDetailWrapper.preRuntimeValidationHooks.length, 0);
        assertEq(executionDetailWrapper.executionHooks.length, 0);
        // verify pluginDetail
        singleOwnerPluginDetailWrapper = msca.getPluginDetail(address(singleOwnerPlugin));
        // now SingleOwnerPlugin has zero dependent
        assertEq(singleOwnerPluginDetailWrapper.dependentCounter, 0);
        // verify the amount has been destroyed
        assertEq(testTokenPlugin.balanceOf(mscaAddr), 0);
        assertEq(testTokenPlugin.balanceOf(address(anotherMSCA)), 999);
        vm.stopPrank();
    }

    function testInstallHookAsDependency() public {
        TestUserOpValidatorWithDependencyHook testValidatorHook = new TestUserOpValidatorWithDependencyHook();
        bytes32 manifestHash = keccak256(abi.encode(testValidatorHook.pluginManifest()));
        // install from an authenticated owner
        vm.startPrank(ownerAddr);
        FunctionReference[] memory dependencies = new FunctionReference[](1);
        // import SingleOwnerPlugin as dependency
        dependencies[0] =
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        bytes4 errorSelector = bytes4(keccak256("HookDependencyNotPermitted()"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector));
        msca.installPlugin(address(testValidatorHook), manifestHash, "", dependencies);
        vm.stopPrank();
    }
}
