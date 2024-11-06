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

/* solhint-disable max-states-count */

import {EMPTY_FUNCTION_REFERENCE, PLUGIN_AUTHOR, PLUGIN_VERSION_1} from "../../../../src/common/Constants.sol";

import {NotImplemented} from "../../../../src/msca/6900/shared/common/Errors.sol";

import {RUNTIME_VALIDATION_ALWAYS_ALLOW_FUNCTION_REFERENCE} from "../../../../src/msca/6900/v0.7/common/Constants.sol";
import {PluginMetadata} from "../../../../src/msca/6900/v0.7/common/PluginManifest.sol";
import {FunctionReference} from "../../../../src/msca/6900/v0.7/common/Structs.sol";

import {IPluginManager} from "../../../../src/msca/6900/v0.7/interfaces/IPluginManager.sol";
import {IStandardExecutor} from "../../../../src/msca/6900/v0.7/interfaces/IStandardExecutor.sol";
import {FunctionReferenceLib} from "../../../../src/msca/6900/v0.7/libs/FunctionReferenceLib.sol";
import {PluginManager} from "../../../../src/msca/6900/v0.7/managers/PluginManager.sol";

import {BasePlugin} from "../../../../src/msca/6900/v0.7/plugins/BasePlugin.sol";
import {ISingleOwnerPlugin} from "../../../../src/msca/6900/v0.7/plugins/v1_0_0/acl/ISingleOwnerPlugin.sol";
import {SingleOwnerPlugin} from "../../../../src/msca/6900/v0.7/plugins/v1_0_0/acl/SingleOwnerPlugin.sol";

import {TestLiquidityPool} from "../../../util/TestLiquidityPool.sol";
import {TestUtils} from "../../../util/TestUtils.sol";
import {TestCircleMSCA} from "./TestCircleMSCA.sol";
import {TestCircleMSCAFactory} from "./TestCircleMSCAFactory.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {console} from "forge-std/src/console.sol";

/// Tests for SingleOwnerPlugin
contract SingleOwnerPluginTest is TestUtils {
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
    uint256 internal eoaPrivateKey1;
    uint256 internal eoaPrivateKey2;
    address private ownerAddr1;
    address private ownerAddr2;
    address payable private beneficiary; // e.g. bundler
    TestCircleMSCAFactory private factory;
    SingleOwnerPlugin private singleOwnerPlugin;
    TestCircleMSCA private msca1;
    TestCircleMSCA private msca2;
    TestLiquidityPool private testLiquidityPool;
    address private singleOwnerPluginAddr;
    address private mscaAddr1;
    address private mscaAddr2;
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

        PluginMetadata memory pluginMetadata = singleOwnerPlugin.pluginMetadata();
        assertEq(pluginMetadata.name, "Single Owner Plugin");
        assertEq(pluginMetadata.version, PLUGIN_VERSION_1);
        assertEq(pluginMetadata.author, PLUGIN_AUTHOR);
        (ownerAddr1, eoaPrivateKey1) = makeAddrAndKey("SingleOwnerPluginTest1");
        (ownerAddr2, eoaPrivateKey2) = makeAddrAndKey("SingleOwnerPluginTest2");
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        address[] memory plugins = new address[](1);
        bytes32[] memory manifestHashes = new bytes32[](1);
        bytes[] memory pluginInstallData = new bytes[](1);
        plugins[0] = address(singleOwnerPlugin);
        manifestHashes[0] = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
        pluginInstallData[0] = abi.encode(ownerAddr1);
        bytes memory initializingData = abi.encode(plugins, manifestHashes, pluginInstallData);
        vm.startPrank(ownerAddr1);
        msca1 = factory.createAccount(ownerAddr1, salt, initializingData);
        vm.stopPrank();
        pluginInstallData[0] = abi.encode(ownerAddr2);
        vm.startPrank(ownerAddr2);
        initializingData = abi.encode(plugins, manifestHashes, pluginInstallData);
        msca2 = factory.createAccount(ownerAddr2, salt, initializingData);
        vm.stopPrank();
        console.logString("single owner plugin address:");
        console.logAddress(address(singleOwnerPlugin));
        singleOwnerPluginAddr = address(singleOwnerPlugin);
        mscaAddr1 = address(msca1);
        mscaAddr2 = address(msca2);
        testLiquidityPool = new TestLiquidityPool("getrich", "$$$");
    }

    /// SingleOwnerPlugin is installed in setUp function, this test is just verifying details
    function testSingleOwnerPluginDetailsInstalledDuringAccountDeployment() public view {
        address sender = address(msca1);
        // deployment was done in setUp
        assertTrue(sender.code.length != 0);
        // verify the plugin has been installed
        address[] memory installedPlugins = msca1.getInstalledPlugins();
        assertEq(installedPlugins.length, 1);
        assertEq(installedPlugins[0], singleOwnerPluginAddr);
        // verify pluginDetail
        TestCircleMSCA.PluginDetailWrapper memory pluginDetail = msca1.getPluginDetail(singleOwnerPluginAddr);
        assertFalse(pluginDetail.anyExternalAddressPermitted);
        assertEq(pluginDetail.dependentCounter, 0);
        assertEq(pluginDetail.manifestHash, keccak256(abi.encode(singleOwnerPlugin.pluginManifest())));
        assertEq(pluginDetail.dependencies.length, 0);
        // verify executionDetail
        //    address plugin; // plugin address that implements the execution function, for native functions, the value
        // is set to address(0)
        //    FunctionReference userOpValidationFunction;
        //    FunctionReference[] preUserOpValidationHooks;
        //    FunctionReference runtimeValidationFunction;
        //    FunctionReference[] preRuntimeValidationHooks;
        //    ExecutionHooks[] executionHooks;
        // transferOwnership function
        TestCircleMSCA.ExecutionDetailWrapper memory executionDetail =
            msca1.getExecutionDetail(singleOwnerPlugin.transferOwnership.selector);
        assertEq(executionDetail.plugin, singleOwnerPluginAddr);
        assertEq(
            executionDetail.userOpValidationFunction.pack(),
            FunctionReference(singleOwnerPluginAddr, uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER)).pack(
            )
        );
        assertEq(
            executionDetail.runtimeValidationFunction.pack(),
            FunctionReference(
                singleOwnerPluginAddr, uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
            ).pack()
        );
        assertEq(executionDetail.preUserOpValidationHooks.length, 0);
        assertEq(executionDetail.preRuntimeValidationHooks.length, 0);
        assertEq(executionDetail.executionHooks.length, 0);

        // getOwner function
        executionDetail = msca1.getExecutionDetail(singleOwnerPlugin.getOwner.selector);
        assertEq(executionDetail.plugin, singleOwnerPluginAddr);
        assertEq(executionDetail.userOpValidationFunction.pack(), EMPTY_FUNCTION_REFERENCE);
        assertEq(executionDetail.runtimeValidationFunction.pack(), RUNTIME_VALIDATION_ALWAYS_ALLOW_FUNCTION_REFERENCE);
        assertEq(executionDetail.preUserOpValidationHooks.length, 0);
        assertEq(executionDetail.preRuntimeValidationHooks.length, 0);
        assertEq(executionDetail.executionHooks.length, 0);

        // getOwnerOf function
        executionDetail = msca1.getExecutionDetail(singleOwnerPlugin.getOwnerOf.selector);
        assertEq(executionDetail.plugin, singleOwnerPluginAddr);
        assertEq(executionDetail.userOpValidationFunction.pack(), EMPTY_FUNCTION_REFERENCE);
        assertEq(executionDetail.runtimeValidationFunction.pack(), RUNTIME_VALIDATION_ALWAYS_ALLOW_FUNCTION_REFERENCE);
        assertEq(executionDetail.preUserOpValidationHooks.length, 0);
        assertEq(executionDetail.preRuntimeValidationHooks.length, 0);
        assertEq(executionDetail.executionHooks.length, 0);

        // isValidSignature function
        executionDetail = msca1.getExecutionDetail(singleOwnerPlugin.isValidSignature.selector);
        assertEq(executionDetail.plugin, singleOwnerPluginAddr);
        assertEq(executionDetail.userOpValidationFunction.pack(), EMPTY_FUNCTION_REFERENCE);
        assertEq(executionDetail.runtimeValidationFunction.pack(), RUNTIME_VALIDATION_ALWAYS_ALLOW_FUNCTION_REFERENCE);
        assertEq(executionDetail.preUserOpValidationHooks.length, 0);
        assertEq(executionDetail.preRuntimeValidationHooks.length, 0);
        assertEq(executionDetail.executionHooks.length, 0);

        // execute function
        executionDetail = msca1.getExecutionDetail(IStandardExecutor.execute.selector);
        // account itself
        assertEq(executionDetail.plugin, mscaAddr1);
        assertEq(
            executionDetail.userOpValidationFunction.pack(),
            FunctionReference(singleOwnerPluginAddr, uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER)).pack(
            )
        );
        assertEq(
            executionDetail.runtimeValidationFunction.pack(),
            FunctionReference(
                singleOwnerPluginAddr, uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
            ).pack()
        );
        assertEq(executionDetail.preUserOpValidationHooks.length, 0);
        assertEq(executionDetail.preRuntimeValidationHooks.length, 0);
        assertEq(executionDetail.executionHooks.length, 0);

        // executeBatch function
        executionDetail = msca1.getExecutionDetail(IStandardExecutor.executeBatch.selector);
        assertEq(executionDetail.plugin, mscaAddr1);
        assertEq(
            executionDetail.userOpValidationFunction.pack(),
            FunctionReference(singleOwnerPluginAddr, uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER)).pack(
            )
        );
        assertEq(
            executionDetail.runtimeValidationFunction.pack(),
            FunctionReference(
                singleOwnerPluginAddr, uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
            ).pack()
        );
        assertEq(executionDetail.preUserOpValidationHooks.length, 0);
        assertEq(executionDetail.preRuntimeValidationHooks.length, 0);
        assertEq(executionDetail.executionHooks.length, 0);

        // installPlugin function
        executionDetail = msca1.getExecutionDetail(IPluginManager.installPlugin.selector);
        assertEq(executionDetail.plugin, mscaAddr1);
        assertEq(
            executionDetail.userOpValidationFunction.pack(),
            FunctionReference(singleOwnerPluginAddr, uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER)).pack(
            )
        );
        assertEq(
            executionDetail.runtimeValidationFunction.pack(),
            FunctionReference(
                singleOwnerPluginAddr, uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
            ).pack()
        );
        assertEq(executionDetail.preUserOpValidationHooks.length, 0);
        assertEq(executionDetail.preRuntimeValidationHooks.length, 0);
        assertEq(executionDetail.executionHooks.length, 0);

        // uninstallPlugin function
        executionDetail = msca1.getExecutionDetail(IPluginManager.uninstallPlugin.selector);
        assertEq(executionDetail.plugin, mscaAddr1);
        assertEq(
            executionDetail.userOpValidationFunction.pack(),
            FunctionReference(singleOwnerPluginAddr, uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER)).pack(
            )
        );
        assertEq(
            executionDetail.runtimeValidationFunction.pack(),
            FunctionReference(
                singleOwnerPluginAddr, uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
            ).pack()
        );
        assertEq(executionDetail.preUserOpValidationHooks.length, 0);
        assertEq(executionDetail.preRuntimeValidationHooks.length, 0);
        assertEq(executionDetail.executionHooks.length, 0);

        // upgradeToAndCall function
        executionDetail = msca1.getExecutionDetail(UUPSUpgradeable.upgradeToAndCall.selector);
        assertEq(executionDetail.plugin, mscaAddr1);
        assertEq(
            executionDetail.userOpValidationFunction.pack(),
            FunctionReference(singleOwnerPluginAddr, uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER)).pack(
            )
        );
        assertEq(
            executionDetail.runtimeValidationFunction.pack(),
            FunctionReference(
                singleOwnerPluginAddr, uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
            ).pack()
        );
        assertEq(executionDetail.preUserOpValidationHooks.length, 0);
        assertEq(executionDetail.preRuntimeValidationHooks.length, 0);
        assertEq(executionDetail.executionHooks.length, 0);

        // verify permittedExternalCalls
        // can SingleOwnerPlugin call its own function?
        assertFalse(
            msca1.getPermittedExternalCall(
                singleOwnerPluginAddr, mscaAddr1, singleOwnerPlugin.transferOwnership.selector
            )
        );
        assertFalse(
            msca1.getPermittedExternalCall(singleOwnerPluginAddr, mscaAddr1, singleOwnerPlugin.getOwner.selector)
        );
        // can SingleOwnerPlugin call native function?
        assertFalse(
            msca1.getPermittedExternalCall(singleOwnerPluginAddr, mscaAddr1, IStandardExecutor.execute.selector)
        );
        // can SingleOwnerPlugin mint?
        assertFalse(
            msca1.getPermittedExternalCall(
                singleOwnerPluginAddr, address(testLiquidityPool), testLiquidityPool.mint.selector
            )
        );

        // verify supportedInterfaces
        assertEq(bytes32(msca1.getSupportedInterface(type(IERC1271).interfaceId)), bytes32(uint256(1)));

        executionDetail = msca1.getExecutionDetail(singleOwnerPlugin.getReplaySafeMessageHash.selector);
        assertEq(executionDetail.plugin, singleOwnerPluginAddr);
        assertEq(executionDetail.userOpValidationFunction.pack(), EMPTY_FUNCTION_REFERENCE);
        assertEq(executionDetail.runtimeValidationFunction.pack(), RUNTIME_VALIDATION_ALWAYS_ALLOW_FUNCTION_REFERENCE);
    }

    function testTransferOwnership() public {
        address sender = address(msca1);
        // it should start with the deployed ownerAddr
        assertEq(singleOwnerPlugin.getOwnerOf(mscaAddr1), ownerAddr1);
        // could be any address, I'm using TestCircleMSCA for simplicity
        TestCircleMSCA newOwner = new TestCircleMSCA(entryPoint, pluginManager);
        // deployment was done in setUp
        assertTrue(sender.code.length != 0);
        // nonce key is 0
        uint256 acctNonce = entryPoint.getNonce(sender, 0);
        // start with balance
        vm.deal(sender, 10 ether);
        bytes memory transferOwnershipCallData =
            abi.encodeCall(singleOwnerPlugin.transferOwnership, (address(newOwner)));
        bytes memory initCode = "";
        PackedUserOperation memory userOp = buildPartialUserOp(
            sender,
            acctNonce,
            vm.toString(initCode),
            vm.toString(transferOwnershipCallData),
            10053353,
            103353,
            45484,
            516219199704,
            1130000000,
            "0x"
        ); // no paymaster

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        // eoaPrivateKey from singleOwnerPlugin
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey1, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        // no paymaster
        emit UserOperationEvent(userOpHash, sender, address(0), acctNonce, true, 158506230000000, 140271);
        entryPoint.handleOps(ops, beneficiary);
        // now it's the new owner
        assertEq(singleOwnerPlugin.getOwnerOf(mscaAddr1), address(newOwner));
        vm.stopPrank();
    }

    /// it's unnecessary because transferOwnership has already been installed in MSCA, but it still works with more gas
    function testTransferOwnershipViaExecuteFunction() public {
        address sender = address(msca2);
        // it should start with the deployed ownerAddr
        assertEq(singleOwnerPlugin.getOwnerOf(mscaAddr2), ownerAddr2);
        // could be any address, I'm using TestCircleMSCA for simplicity
        TestCircleMSCA newOwner = new TestCircleMSCA(entryPoint, pluginManager);
        // deployment was done in setUp
        assertTrue(sender.code.length != 0);
        // nonce key is 0
        uint256 acctNonce = entryPoint.getNonce(sender, 0);
        // start with balance
        vm.deal(sender, 10 ether);
        bytes memory transferOwnershipCallData =
            abi.encodeCall(singleOwnerPlugin.transferOwnership, (address(newOwner)));
        // wrap transferOwnershipCallData into execute function for fun
        bytes memory executeCallData = abi.encodeCall(IStandardExecutor.execute, (sender, 0, transferOwnershipCallData));
        bytes memory initCode = "";
        PackedUserOperation memory userOp = buildPartialUserOp(
            sender,
            acctNonce,
            vm.toString(initCode),
            vm.toString(executeCallData),
            10053353,
            103353,
            45484,
            516219199704,
            1130000000,
            "0x"
        ); // no paymaster

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        // eoaPrivateKey from singleOwnerPlugin
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey2, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        // no paymaster
        emit UserOperationEvent(userOpHash, sender, address(0), acctNonce, true, 179020250000000, 158425);
        entryPoint.handleOps(ops, beneficiary);
        // now it's the new owner
        assertEq(singleOwnerPlugin.getOwnerOf(mscaAddr2), address(newOwner));
        vm.stopPrank();
    }

    function testNotImplementedFuncs() public {
        uint8 functionId;
        PackedUserOperation memory uo;
        bytes32 userOpHash;
        vm.expectRevert(
            abi.encodeWithSelector(NotImplemented.selector, BasePlugin.preUserOpValidationHook.selector, functionId)
        );
        singleOwnerPlugin.preUserOpValidationHook(functionId, uo, userOpHash);

        address sender;
        uint256 value;
        bytes memory data;
        vm.expectRevert(
            abi.encodeWithSelector(NotImplemented.selector, BasePlugin.preRuntimeValidationHook.selector, functionId)
        );
        singleOwnerPlugin.preRuntimeValidationHook(functionId, sender, value, data);

        vm.expectRevert(
            abi.encodeWithSelector(NotImplemented.selector, BasePlugin.preExecutionHook.selector, functionId)
        );
        singleOwnerPlugin.preExecutionHook(functionId, sender, value, data);

        vm.expectRevert(
            abi.encodeWithSelector(NotImplemented.selector, BasePlugin.postExecutionHook.selector, functionId)
        );
        singleOwnerPlugin.postExecutionHook(functionId, data);
    }
}
