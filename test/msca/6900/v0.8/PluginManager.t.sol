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

import {PLUGIN_AUTHOR, PLUGIN_VERSION_1} from "../../../../src/common/Constants.sol";
import {PluginMetadata} from "../../../../src/msca/6900/v0.8/common/PluginManifest.sol";

import {ModuleEntity, ValidationConfig} from "../../../../src/msca/6900/v0.8/common/Types.sol";
import {IPluginManager} from "../../../../src/msca/6900/v0.8/interfaces/IPluginManager.sol";
import {ModuleEntityLib} from "../../../../src/msca/6900/v0.8/libs/thirdparty/ModuleEntityLib.sol";

import {ValidationConfigLib} from "../../../../src/msca/6900/v0.8/libs/thirdparty/ValidationConfigLib.sol";
import {PluginManager} from "../../../../src/msca/6900/v0.8/managers/PluginManager.sol";
import {SingleSignerValidationModule} from
    "../../../../src/msca/6900/v0.8/plugins/v1_0_0/validation/SingleSignerValidationModule.sol";
import {TestLiquidityPool} from "../../../util/TestLiquidityPool.sol";
import {TestCircleMSCA} from "./TestCircleMSCA.sol";

import {TestCircleMSCAFactory} from "./TestCircleMSCAFactory.sol";
import {TestTokenPlugin} from "./TestTokenPlugin.sol";
import {AccountTestUtils} from "./utils/AccountTestUtils.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";

import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {console} from "forge-std/src/console.sol";

/// Tests for install/uninstall
contract PluginManagerTest is AccountTestUtils {
    using ModuleEntityLib for ModuleEntity;

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
    address payable private beneficiary; // e.g. bundler
    TestCircleMSCAFactory private factory;
    SingleSignerValidationModule private singleSignerValidationModule;
    TestCircleMSCA private msca;
    TestTokenPlugin private testTokenPlugin;
    address private mscaAddr;
    address private factoryOwner;
    ModuleEntity private ownerValidation;

    function setUp() public {
        factoryOwner = makeAddr("factoryOwner");
        beneficiary = payable(address(makeAddr("bundler")));
        factory = new TestCircleMSCAFactory(factoryOwner, entryPoint, pluginManager);
        singleSignerValidationModule = new SingleSignerValidationModule();

        address[] memory _plugins = new address[](1);
        _plugins[0] = address(singleSignerValidationModule);
        bool[] memory _permissions = new bool[](1);
        _permissions[0] = true;
        vm.startPrank(factoryOwner);
        factory.setPlugins(_plugins, _permissions);
        vm.stopPrank();

        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("PluginManagerTest");
        vm.startPrank(ownerAddr);
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), bytes(""), bytes(""));
        msca = factory.createAccountWithValidation(ownerAddr, salt, initializingData);
        console.logString("msca address:");
        console.logAddress(address(msca));
        console.logString("single owner plugin address:");
        console.logAddress(address(singleSignerValidationModule));
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
        // install from an authenticated owner
        vm.startPrank(address(entryPoint));
        bytes4 errorSelector = bytes4(keccak256("PluginNotImplementInterface()"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector));
        msca.installPlugin(address(testLiquidityPool), "");
        vm.stopPrank();

        // install from a random address, should be rejected
        // UnauthorizedCaller is caught by the caller and converted to RuntimeValidationFailed
        vm.startPrank(address(1));
        // function id from manifest
        vm.expectRevert(
            abi.encodeWithSelector(
                bytes4(keccak256("ExecFromPluginToSelectorNotPermitted(address,bytes4)")),
                address(1),
                IPluginManager.installPlugin.selector
            )
        );
        msca.installPlugin(address(testLiquidityPool), "");
        vm.stopPrank();
    }

    /// try to install and uninstall a new plugin via user op after single owner plugin has been installed as part of
    /// account deployment
    function testInstallAndUninstallTestPluginWithValidationAndHooks() public {
        // deployment was done in setUp
        assertTrue(address(msca).code.length != 0);
        // start with balance
        vm.deal(address(msca), 10 ether);
        bytes memory installPluginCallData =
            abi.encodeCall(IPluginManager.installPlugin, (address(testTokenPlugin), abi.encode(1000)));
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
        // eoaPrivateKey from singleSignerValidationModule
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = encodeSignature(new PreValidationHookData[](0), ownerValidation, signature, true);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        // no paymaster
        emit UserOperationEvent(userOpHash, address(msca), address(0), 0, true, 264430170000000, 234009);
        entryPoint.handleOps(ops, beneficiary);

        // install hooks
        ModuleEntity[] memory preValidationHooks = new ModuleEntity[](2);
        preValidationHooks[0] =
            ModuleEntityLib.pack(address(testTokenPlugin), uint32(TestTokenPlugin.EntityId.PRE_VALIDATION_HOOK_PASS1));
        preValidationHooks[1] =
            ModuleEntityLib.pack(address(testTokenPlugin), uint32(TestTokenPlugin.EntityId.PRE_VALIDATION_HOOK_PASS2));
        bytes memory installHooksCalldata = abi.encodeCall(
            IPluginManager.installValidation,
            (
                ValidationConfigLib.pack(ownerValidation, true, true),
                new bytes4[](0),
                bytes(""),
                abi.encode(preValidationHooks, new bytes[](2)),
                bytes("")
            )
        );
        userOp = buildPartialUserOp(
            address(msca),
            1,
            "0x",
            vm.toString(installHooksCalldata),
            10053353,
            103353,
            45484,
            516219199704,
            1130000000,
            "0x"
        ); // no paymaster

        userOpHash = entryPoint.getUserOpHash(userOp);
        signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = encodeSignature(new PreValidationHookData[](0), ownerValidation, signature, true);
        ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        // no paymaster
        emit UserOperationEvent(userOpHash, address(msca), address(0), 0, true, 264430170000000, 234009);
        entryPoint.handleOps(ops, beneficiary);

        // verify the plugin has been installed
        assertEq(msca.sizeOfPlugins(), 1);
        address[] memory installedPlugins = msca.getInstalledPlugins();
        assertEq(installedPlugins[0], address(testTokenPlugin));
        // verify airdrop amount initiated during installation
        assertEq(testTokenPlugin.balanceOf(mscaAddr), 1000);

        assertEq(msca.getSelectors(ownerValidation).length, 0);
        assertEq(msca.getPreValidationHooks(ownerValidation).length, 2);
        vm.stopPrank();

        //
        // TODO: we currently don't have a good way of uninstalling hook function only
        // 6900 team is looking into this
        //
        // uninstall via another userOp
        // we'll just use plugin manifest
        TestCircleMSCA anotherMSCA = new TestCircleMSCA(entryPoint, pluginManager);
        bytes memory pluginUninstallData = abi.encode(address(anotherMSCA), 999);
        bytes memory uninstallPluginCalldata =
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(testTokenPlugin), "", pluginUninstallData));
        userOp = buildPartialUserOp(
            address(msca),
            2,
            "0x",
            vm.toString(uninstallPluginCalldata),
            10053353,
            103353,
            45484,
            516219199704,
            1130000000,
            "0x"
        ); // no paymaster

        userOpHash = entryPoint.getUserOpHash(userOp);
        // eoaPrivateKey from singleSignerValidationModule
        signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = encodeSignature(new PreValidationHookData[](0), ownerValidation, signature, true);
        ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        // no paymaster
        emit UserOperationEvent(userOpHash, address(msca), address(0), 1, true, 264430170000000, 234009);
        entryPoint.handleOps(ops, beneficiary);

        // uninstall hooks
        bytes memory uninstallHooksCallData =
            abi.encodeCall(IPluginManager.uninstallValidation, (ownerValidation, bytes(""), bytes(""), bytes("")));
        userOp = buildPartialUserOp(
            address(msca),
            3,
            "0x",
            vm.toString(uninstallHooksCallData),
            10053353,
            103353,
            45484,
            516219199704,
            1130000000,
            "0x"
        ); // no paymaster

        userOpHash = entryPoint.getUserOpHash(userOp);
        signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = encodeSignature(new PreValidationHookData[](0), ownerValidation, signature, true);
        ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        // no paymaster
        emit UserOperationEvent(userOpHash, address(msca), address(0), 1, true, 264430170000000, 234009);
        entryPoint.handleOps(ops, beneficiary);

        // verify the plugin has been uninstalled
        assertEq(msca.sizeOfPlugins(), 0);
        // verify executionDetails
        // the plugin requested to install transferToken and balanceOf
        TestCircleMSCA.ExecutionDetailWrapper memory executionDetailWrapper =
            msca.getExecutionDetail(testTokenPlugin.transferToken.selector);
        assertEq(executionDetailWrapper.plugin, address(0));
        assertEq(msca.getSelectors(ownerValidation).length, 0);
        assertEq(msca.getPreValidationHooks(ownerValidation).length, 2);
        assertEq(executionDetailWrapper.executionHooks.length, 0);
        // balanceOf
        executionDetailWrapper = msca.getExecutionDetail(testTokenPlugin.balanceOf.selector);
        assertEq(executionDetailWrapper.plugin, address(0));
        assertEq(executionDetailWrapper.executionHooks.length, 0);
        // verify the amount has been destroyed
        assertEq(testTokenPlugin.balanceOf(mscaAddr), 0);
        assertEq(testTokenPlugin.balanceOf(address(anotherMSCA)), 999);
        vm.stopPrank();
    }
}
