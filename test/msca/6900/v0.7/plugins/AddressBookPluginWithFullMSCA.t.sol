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

import {UnauthorizedCaller} from "../../../../../src/common/Errors.sol";
import {BaseMSCA} from "../../../../../src/msca/6900/v0.7/account/BaseMSCA.sol";

import {UpgradableMSCA} from "../../../../../src/msca/6900/v0.7/account/UpgradableMSCA.sol";
import {PRE_HOOK_ALWAYS_DENY_FUNCTION_REFERENCE} from "../../../../../src/msca/6900/v0.7/common/Constants.sol";
import {
    Call,
    ExecutionFunctionConfig,
    ExecutionHooks,
    FunctionReference
} from "../../../../../src/msca/6900/v0.7/common/Structs.sol";
import {UpgradableMSCAFactory} from "../../../../../src/msca/6900/v0.7/factories/UpgradableMSCAFactory.sol";
import {IStandardExecutor} from "../../../../../src/msca/6900/v0.7/interfaces/IStandardExecutor.sol";
import {FunctionReferenceLib} from "../../../../../src/msca/6900/v0.7/libs/FunctionReferenceLib.sol";
import {PluginManager} from "../../../../../src/msca/6900/v0.7/managers/PluginManager.sol";
import {ISingleOwnerPlugin} from "../../../../../src/msca/6900/v0.7/plugins/v1_0_0/acl/ISingleOwnerPlugin.sol";
import {SingleOwnerPlugin} from "../../../../../src/msca/6900/v0.7/plugins/v1_0_0/acl/SingleOwnerPlugin.sol";
import {IPluginManager} from "src/msca/6900/v0.7/interfaces/IPluginManager.sol";

import {AddressBookPlugin} from "../../../../../src/msca/6900/v0.7/plugins/v1_0_0/addressbook/AddressBookPlugin.sol";
import {IAddressBookPlugin} from "../../../../../src/msca/6900/v0.7/plugins/v1_0_0/addressbook/IAddressBookPlugin.sol";
import {ExecutionUtils} from "../../../../../src/utils/ExecutionUtils.sol";
import {TestLiquidityPool} from "../../../../util/TestLiquidityPool.sol";
import {TestUtils} from "../../../../util/TestUtils.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {UserOperation} from "@account-abstraction/contracts/interfaces/UserOperation.sol";
import {console} from "forge-std/src/console.sol";

// some common test cases related to plugin itself is covered in AddressBookPluginWithSemiMSCATest
contract AddressBookPluginWithFullMSCATest is TestUtils {
    using FunctionReferenceLib for bytes21;
    using FunctionReferenceLib for FunctionReference;
    using ExecutionUtils for address;
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
    UpgradableMSCAFactory private factory;
    AddressBookPlugin private addressBookPlugin;
    TestLiquidityPool private testLiquidityPool;
    address private addressBookPluginAddr;
    UpgradableMSCA private msca;
    address private mscaAddr;
    bytes32 private addressBookPluginManifest;
    SingleOwnerPlugin private singleOwnerPlugin;
    address private factoryOwner;

    function setUp() public {
        factoryOwner = makeAddr("factoryOwner");
        beneficiary = payable(address(makeAddr("bundler")));
        factory = new UpgradableMSCAFactory(factoryOwner, address(entryPoint), address(pluginManager));
        addressBookPlugin = new AddressBookPlugin();
        singleOwnerPlugin = new SingleOwnerPlugin();

        address[] memory _plugins = new address[](2);
        _plugins[0] = address(singleOwnerPlugin);
        _plugins[1] = address(addressBookPlugin);
        bool[] memory _permissions = new bool[](2);
        _permissions[0] = true;
        _permissions[1] = true;
        vm.startPrank(factoryOwner);
        factory.setPlugins(_plugins, _permissions);
        vm.stopPrank();

        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("AddressBookPluginWithFullMSCATest");
        address[] memory plugins = new address[](1);
        bytes32[] memory manifestHashes = new bytes32[](1);
        bytes[] memory pluginInstallData = new bytes[](1);
        plugins[0] = address(singleOwnerPlugin);
        manifestHashes[0] = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
        pluginInstallData[0] = abi.encode(ownerAddr);
        bytes memory initializingData = abi.encode(plugins, manifestHashes, pluginInstallData);
        vm.startPrank(ownerAddr);
        msca = factory.createAccount(addressToBytes32(ownerAddr), salt, initializingData);
        // deployment was done
        assertTrue(address(msca).code.length != 0);
        vm.stopPrank();
        addressBookPluginAddr = address(addressBookPlugin);
        console.logString("address book plugin address:");
        console.logAddress(addressBookPluginAddr);
        mscaAddr = address(msca);
        console.logString("msca address:");
        console.logAddress(mscaAddr);
        addressBookPluginManifest = keccak256(abi.encode(addressBookPlugin.pluginManifest()));
        testLiquidityPool = new TestLiquidityPool("getrich", "$$$");
    }

    function testInstalledAddressBookPluginDetails() public {
        // install plugin first
        address[] memory recipients = new address[](1);
        recipients[0] = vm.addr(1);
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] = FunctionReference(
            address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        );
        dependencies[1] =
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        vm.startPrank(ownerAddr);
        msca.installPlugin(addressBookPluginAddr, addressBookPluginManifest, abi.encode(recipients), dependencies);
        vm.stopPrank();

        // verify the plugin has been installed
        address[] memory installedPlugins = msca.getInstalledPlugins();
        assertEq(installedPlugins.length, 2);
        assertEq(installedPlugins[1], addressBookPluginAddr);
        // verify executionDetail
        //    address plugin; // plugin address that implements the execution function, for native functions, the value
        // is set to address(0)
        //    FunctionReference userOpValidationFunction;
        //    FunctionReference[] preUserOpValidationHooks;
        //    FunctionReference runtimeValidationFunction;
        //    FunctionReference[] preRuntimeValidationHooks;
        //    ExecutionHooks[] executionHooks;
        // addAllowedRecipients function
        ExecutionFunctionConfig memory executionDetail =
            msca.getExecutionFunctionConfig(addressBookPlugin.addAllowedRecipients.selector);
        assertEq(executionDetail.plugin, addressBookPluginAddr);
        // use native validation instead
        assertEq(
            executionDetail.userOpValidationFunction.pack(),
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER))
                .pack()
        );
        assertEq(
            executionDetail.runtimeValidationFunction.pack(),
            FunctionReference(
                address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
            ).pack()
        );

        // removeAllowedRecipients
        executionDetail = msca.getExecutionFunctionConfig(addressBookPlugin.removeAllowedRecipients.selector);
        assertEq(executionDetail.plugin, addressBookPluginAddr);
        assertEq(
            executionDetail.userOpValidationFunction.pack(),
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER))
                .pack()
        );
        assertEq(
            executionDetail.runtimeValidationFunction.pack(),
            FunctionReference(
                address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
            ).pack()
        );

        // getAllowedRecipients
        executionDetail = msca.getExecutionFunctionConfig(addressBookPlugin.getAllowedRecipients.selector);
        assertEq(executionDetail.plugin, addressBookPluginAddr);
        // waste of gas
        assertEq(
            executionDetail.userOpValidationFunction.pack(),
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER))
                .pack()
        );
        assertEq(
            executionDetail.runtimeValidationFunction.pack(),
            FunctionReference(
                address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
            ).pack()
        );

        // executeWithAddressBook
        executionDetail = msca.getExecutionFunctionConfig(addressBookPlugin.executeWithAddressBook.selector);
        assertEq(executionDetail.plugin, addressBookPluginAddr);
        assertEq(
            executionDetail.userOpValidationFunction.pack(),
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER))
                .pack()
        );
        assertEq(
            executionDetail.runtimeValidationFunction.pack(),
            FunctionReference(
                address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
            ).pack()
        );

        // executeBatchWithAddressBook
        executionDetail = msca.getExecutionFunctionConfig(addressBookPlugin.executeBatchWithAddressBook.selector);
        assertEq(executionDetail.plugin, addressBookPluginAddr);
        assertEq(
            executionDetail.userOpValidationFunction.pack(),
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER))
                .pack()
        );
        assertEq(
            executionDetail.runtimeValidationFunction.pack(),
            FunctionReference(
                address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
            ).pack()
        );

        // execution hooks
        ExecutionHooks[] memory executionHooks = msca.getExecutionHooks(addressBookPlugin.addAllowedRecipients.selector);
        assertEq(executionHooks.length, 0);

        msca.getExecutionHooks(addressBookPlugin.removeAllowedRecipients.selector);
        assertEq(executionHooks.length, 0);

        msca.getExecutionHooks(addressBookPlugin.getAllowedRecipients.selector);
        assertEq(executionHooks.length, 0);

        // pre validation hooks
        (FunctionReference[] memory preUserOpValidationHooks, FunctionReference[] memory preRuntimeValidationHooks) =
            msca.getPreValidationHooks(AddressBookPlugin.executeWithAddressBook.selector);
        assertEq(preUserOpValidationHooks.length, 1);
        assertEq(
            preUserOpValidationHooks[0].pack(),
            FunctionReference(
                addressBookPluginAddr, uint8(AddressBookPlugin.FunctionId.PRE_USER_OP_VALIDATION_HOOK_ADDRESS_BOOK)
            ).pack()
        );
        assertEq(preRuntimeValidationHooks.length, 1);
        assertEq(
            preRuntimeValidationHooks[0].pack(),
            FunctionReference(
                addressBookPluginAddr, uint8(AddressBookPlugin.FunctionId.PRE_RUNTIME_VALIDATION_HOOK_ADDRESS_BOOK)
            ).pack()
        );

        (preUserOpValidationHooks, preRuntimeValidationHooks) =
            msca.getPreValidationHooks(IStandardExecutor.execute.selector);
        assertEq(preUserOpValidationHooks.length, 1);
        assertEq(preUserOpValidationHooks[0].pack(), PRE_HOOK_ALWAYS_DENY_FUNCTION_REFERENCE);
        assertEq(preRuntimeValidationHooks.length, 1);
        assertEq(preRuntimeValidationHooks[0].pack(), PRE_HOOK_ALWAYS_DENY_FUNCTION_REFERENCE);
    }

    // send native token, run through userOp hook (pass) => validation (pass)
    function testExecuteWithAddressBookPassPreUserOpHookAndValidation() public {
        // install plugin first
        address recipientAddr = vm.addr(1);
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] = FunctionReference(
            address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        );
        dependencies[1] =
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        vm.startPrank(ownerAddr);
        address[] memory recipients = new address[](1);
        recipients[0] = recipientAddr;
        msca.installPlugin(addressBookPluginAddr, addressBookPluginManifest, abi.encode(recipients), dependencies);
        vm.stopPrank();

        vm.deal(mscaAddr, 1 ether);
        uint256 acctNonce = entryPoint.getNonce(mscaAddr, 0);
        bytes memory executeCallData =
            abi.encodeCall(AddressBookPlugin.executeWithAddressBook, (recipientAddr, 1, "", recipientAddr));
        UserOperation memory userOp = buildPartialUserOp(
            mscaAddr,
            acctNonce,
            "0x",
            vm.toString(executeCallData),
            83353,
            1028650,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
        // verify recipient balance
        assertEq(recipientAddr.balance, 1);
    }

    // send native token, run through userOp hook (pass) => validation (fail due to wrong signature)
    function testExecuteWithAddressBookPassPreUserOpHookButFailValidation() public {
        // install plugin first
        address recipientAddr = vm.addr(1);
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] = FunctionReference(
            address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        );
        dependencies[1] =
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        vm.startPrank(ownerAddr);
        address[] memory recipients = new address[](1);
        recipients[0] = recipientAddr;
        msca.installPlugin(addressBookPluginAddr, addressBookPluginManifest, abi.encode(recipients), dependencies);
        vm.stopPrank();

        vm.deal(mscaAddr, 1 ether);
        uint256 acctNonce = entryPoint.getNonce(mscaAddr, 0);
        bytes memory executeCallData =
            abi.encodeCall(AddressBookPlugin.executeWithAddressBook, (recipientAddr, 1, "", recipientAddr));
        UserOperation memory userOp = buildPartialUserOp(
            mscaAddr,
            acctNonce,
            "0x",
            vm.toString(executeCallData),
            83353,
            1028650,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        (, uint256 randomPrivateKey) = makeAddrAndKey("testExecuteWithAddressBookPassPreUserOpHookButFailValidation");
        bytes memory signature = signUserOpHash(entryPoint, vm, randomPrivateKey, userOp);
        userOp.signature = signature;
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        // revert due to validation
        vm.expectRevert();
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
        // verify recipient balance is still 0
        assertEq(recipientAddr.balance, 0);
    }

    // send native token, run through userOp hook (fail due to empty allow list) => validation (pass)
    function testExecuteWithAddressBookFailPreUserOpHookButPassValidation() public {
        // install plugin first
        address recipientAddr = vm.addr(1);
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] = FunctionReference(
            address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        );
        dependencies[1] =
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        vm.startPrank(ownerAddr);
        address[] memory recipients = new address[](0);
        msca.installPlugin(addressBookPluginAddr, addressBookPluginManifest, abi.encode(recipients), dependencies);
        vm.stopPrank();

        vm.deal(mscaAddr, 1 ether);
        uint256 acctNonce = entryPoint.getNonce(mscaAddr, 0);
        bytes memory executeCallData =
            abi.encodeCall(AddressBookPlugin.executeWithAddressBook, (recipientAddr, 1, "", recipientAddr));
        UserOperation memory userOp = buildPartialUserOp(
            mscaAddr,
            acctNonce,
            "0x",
            vm.toString(executeCallData),
            83353,
            1028650,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        // revert due to preUserOpValidationHook == 1
        vm.expectRevert();
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
        // verify recipient balance is still 0
        assertEq(recipientAddr.balance, 0);
    }

    // send native token, run through userOp hook (fail due to empty allow list) => validation (fail due to invalid
    // signature)
    function testExecuteWithAddressBookFailPreUserOpHookAndValidation() public {
        // install plugin first
        address recipientAddr = vm.addr(1);
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] = FunctionReference(
            address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        );
        dependencies[1] =
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        vm.startPrank(ownerAddr);
        address[] memory recipients = new address[](0);
        msca.installPlugin(addressBookPluginAddr, addressBookPluginManifest, abi.encode(recipients), dependencies);
        vm.stopPrank();

        vm.deal(mscaAddr, 1 ether);
        uint256 acctNonce = entryPoint.getNonce(mscaAddr, 0);
        bytes memory executeCallData =
            abi.encodeCall(AddressBookPlugin.executeWithAddressBook, (recipientAddr, 1, "", recipientAddr));
        UserOperation memory userOp = buildPartialUserOp(
            mscaAddr,
            acctNonce,
            "0x",
            vm.toString(executeCallData),
            83353,
            1028650,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        (, uint256 randomPrivateKey) = makeAddrAndKey("testExecuteWithAddressBookFailPreUserOpHookAndValidation");
        bytes memory signature = signUserOpHash(entryPoint, vm, randomPrivateKey, userOp);
        userOp.signature = signature;
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        // revert due to preUserOpValidationHook == 1 and validation
        vm.expectRevert();
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
        // verify recipient balance
        assertEq(recipientAddr.balance, 0);
    }

    // send native token, run through runtime hook (pass) => validation (pass)
    function testExecuteWithAddressBookPassPreRuntimeHookAndValidation() public {
        address[] memory recipients = new address[](1);
        address recipientAddr = vm.addr(1);
        recipients[0] = recipientAddr;
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] = FunctionReference(
            address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        );
        dependencies[1] =
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        vm.startPrank(ownerAddr);
        msca.installPlugin(addressBookPluginAddr, addressBookPluginManifest, abi.encode(recipients), dependencies);
        vm.stopPrank();

        vm.deal(mscaAddr, 1 ether);
        vm.startPrank(ownerAddr);
        mscaAddr.callWithReturnDataOrRevert(
            0, abi.encodeCall(AddressBookPlugin.executeWithAddressBook, (recipientAddr, 1, "", recipientAddr))
        );
        vm.stopPrank();
        assertEq(recipients[0].balance, 1);
    }

    // send native token, run through runtime hook (pass) => validation (fail because the call is not from owner)
    function testExecuteWithAddressBookPassPreRuntimeHookButFailValidation() public {
        address[] memory recipients = new address[](1);
        address recipientAddr = vm.addr(1);
        recipients[0] = recipientAddr;
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] = FunctionReference(
            address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        );
        dependencies[1] =
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        vm.startPrank(ownerAddr);
        msca.installPlugin(addressBookPluginAddr, addressBookPluginManifest, abi.encode(recipients), dependencies);
        vm.stopPrank();

        vm.deal(mscaAddr, 1 ether);
        vm.startPrank(vm.addr(123));
        bytes memory revertReason = abi.encodeWithSelector(UnauthorizedCaller.selector);
        vm.expectRevert(
            abi.encodeWithSelector(
                BaseMSCA.RuntimeValidationFailed.selector, address(singleOwnerPlugin), 0, revertReason
            )
        );
        mscaAddr.callWithReturnDataOrRevert(
            0, abi.encodeCall(AddressBookPlugin.executeWithAddressBook, (recipientAddr, 1, "", recipientAddr))
        );
        vm.stopPrank();
        assertEq(recipients[0].balance, 0);
    }

    // send native token, run through runtime hook (fail because of empty allow list) => validation (pass)
    function testExecuteWithAddressBookFailPreRuntimeHookButPassValidation() public {
        address[] memory recipients = new address[](0);
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] = FunctionReference(
            address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        );
        dependencies[1] =
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        vm.startPrank(ownerAddr);
        msca.installPlugin(addressBookPluginAddr, addressBookPluginManifest, abi.encode(recipients), dependencies);
        vm.stopPrank();

        address randomRecipient = vm.addr(1);
        vm.deal(mscaAddr, 1 ether);
        vm.startPrank(ownerAddr);
        bytes memory revertReason =
            abi.encodeWithSelector(IAddressBookPlugin.UnauthorizedRecipient.selector, ownerAddr, randomRecipient);
        vm.expectRevert(
            abi.encodeWithSelector(
                BaseMSCA.PreRuntimeValidationHookFailed.selector, address(addressBookPlugin), 1, revertReason
            )
        );
        mscaAddr.callWithReturnDataOrRevert(
            0, abi.encodeCall(AddressBookPlugin.executeWithAddressBook, (randomRecipient, 1, "", randomRecipient))
        );
        vm.stopPrank();
        assertEq(randomRecipient.balance, 0);
    }

    // send native token, run through hook (fail because of empty allow list) => validation (fail because the call is
    // not from owner)
    function testExecuteWithAddressBookFailPreRuntimeHookAndValidation() public {
        address[] memory recipients = new address[](0);
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] = FunctionReference(
            address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        );
        dependencies[1] =
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        vm.startPrank(ownerAddr);
        msca.installPlugin(addressBookPluginAddr, addressBookPluginManifest, abi.encode(recipients), dependencies);
        vm.stopPrank();

        address randomRecipient = vm.addr(1);
        vm.deal(mscaAddr, 1 ether);
        // call from random address
        vm.startPrank(vm.addr(123));
        bytes memory revertReason =
            abi.encodeWithSelector(IAddressBookPlugin.UnauthorizedRecipient.selector, vm.addr(123), randomRecipient);
        vm.expectRevert(
            abi.encodeWithSelector(
                BaseMSCA.PreRuntimeValidationHookFailed.selector, address(addressBookPlugin), 1, revertReason
            )
        );
        mscaAddr.callWithReturnDataOrRevert(
            0, abi.encodeCall(AddressBookPlugin.executeWithAddressBook, (randomRecipient, 1, "", randomRecipient))
        );
        vm.stopPrank();
        assertEq(randomRecipient.balance, 0);
    }

    function testInstallThenUninstallAddressBookPlugin() public {
        address[] memory recipients = new address[](3);
        recipients[0] = vm.addr(1);
        recipients[1] = vm.addr(2);
        recipients[2] = vm.addr(3);
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] = FunctionReference(
            address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        );
        dependencies[1] =
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        vm.startPrank(ownerAddr);
        msca.installPlugin(addressBookPluginAddr, addressBookPluginManifest, abi.encode(recipients), dependencies);
        vm.stopPrank();

        vm.startPrank(ownerAddr);
        bytes memory returnData =
            mscaAddr.callWithReturnDataOrRevert(0, abi.encodeCall(IAddressBookPlugin.getAllowedRecipients, (mscaAddr)));
        address[] memory allowedRecipients = abi.decode(returnData, (address[]));
        vm.stopPrank();
        assertEq(allowedRecipients.length, 3);
        assertEq(allowedRecipients[0], recipients[2]);
        assertEq(allowedRecipients[1], recipients[1]);
        assertEq(allowedRecipients[2], recipients[0]);

        // calls from a random address to view other address's recipients are banned
        vm.startPrank(vm.addr(456));
        bytes memory revertReason = abi.encodeWithSelector(UnauthorizedCaller.selector);
        vm.expectRevert(
            abi.encodeWithSelector(
                BaseMSCA.RuntimeValidationFailed.selector, address(singleOwnerPlugin), 0, revertReason
            )
        );
        returnData =
            mscaAddr.callWithReturnDataOrRevert(0, abi.encodeCall(IAddressBookPlugin.getAllowedRecipients, (mscaAddr)));
        vm.stopPrank();

        // however you can still call into plugin directly to read the data
        allowedRecipients = addressBookPlugin.getAllowedRecipients(mscaAddr);
        assertEq(allowedRecipients.length, 3);

        // now uninstall
        vm.startPrank(ownerAddr);
        msca.uninstallPlugin(addressBookPluginAddr, "", "");
        vm.stopPrank();
        assertEq(msca.getInstalledPlugins().length, 1);
        allowedRecipients = addressBookPlugin.getAllowedRecipients(mscaAddr);
        assertEq(allowedRecipients.length, 0);
    }

    // 1. add the recipient, send ERC20 tokens successfully, run through hook (pass) => validation (pass)
    // 2. remove the recipient
    // 3. hook should fail now
    function testExecuteWithAddressBookViaUserOpWithERC20PassThenFail() public {
        // install plugin first
        address recipientAddr = vm.addr(1);
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] = FunctionReference(
            address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        );
        dependencies[1] =
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        vm.startPrank(ownerAddr);
        address[] memory recipients = new address[](1);
        recipients[0] = recipientAddr;
        msca.installPlugin(addressBookPluginAddr, addressBookPluginManifest, abi.encode(recipients), dependencies);
        vm.stopPrank();

        vm.deal(mscaAddr, 1 ether);
        testLiquidityPool.mint(mscaAddr, 10);
        address target = address(testLiquidityPool);
        uint256 value = 0;
        bytes memory data = abi.encodeCall(testLiquidityPool.transfer, (recipientAddr, 2));
        uint256 acctNonce = entryPoint.getNonce(mscaAddr, 0);
        bytes memory executeCallData =
            abi.encodeCall(AddressBookPlugin.executeWithAddressBook, (target, value, data, recipientAddr));
        UserOperation memory userOp = buildPartialUserOp(
            mscaAddr,
            acctNonce,
            "0x",
            vm.toString(executeCallData),
            83353,
            1028650,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
        // verify recipient balance
        assertEq(testLiquidityPool.balanceOf(recipientAddr), 2);

        // remove the recipient now
        vm.startPrank(ownerAddr);
        mscaAddr.callWithReturnDataOrRevert(0, abi.encodeCall(IAddressBookPlugin.removeAllowedRecipients, (recipients)));
        vm.stopPrank();

        // do another user op with same calldata this time
        userOp = buildPartialUserOp(
            mscaAddr,
            entryPoint.getNonce(mscaAddr, 0),
            "0x",
            vm.toString(executeCallData),
            83353,
            1028650,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        ops = new UserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectRevert();
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
        // verify recipient balance now still has 2 tokens as before
        assertEq(testLiquidityPool.balanceOf(recipientAddr), 2);
    }

    // 1. empty allow list, fail to send ERC20 tokens, run through hook (fail because of empty allow list) => validation
    // (pass)
    // 2. allow the recipient
    // 3. send ERC20 tokens successfully, pass both hook and validation
    function testExecuteWithAddressBookViaUserOpWithERC20FailThenPass() public {
        // install plugin first
        address recipientAddr = vm.addr(1);
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] = FunctionReference(
            address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        );
        dependencies[1] =
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        vm.startPrank(ownerAddr);
        address[] memory recipients = new address[](0);
        msca.installPlugin(addressBookPluginAddr, addressBookPluginManifest, abi.encode(recipients), dependencies);
        vm.stopPrank();

        vm.deal(mscaAddr, 1 ether);
        testLiquidityPool.mint(mscaAddr, 10);
        address target = address(testLiquidityPool);
        uint256 value = 0;
        bytes memory data = abi.encodeCall(testLiquidityPool.transfer, (recipientAddr, 2));
        uint256 acctNonce = entryPoint.getNonce(mscaAddr, 0);
        bytes memory executeCallData =
            abi.encodeCall(AddressBookPlugin.executeWithAddressBook, (target, value, data, recipientAddr));
        UserOperation memory userOp = buildPartialUserOp(
            mscaAddr,
            acctNonce,
            "0x",
            vm.toString(executeCallData),
            83353,
            1028650,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectRevert();
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
        // verify recipient balance
        assertEq(testLiquidityPool.balanceOf(recipientAddr), 0);

        // allow the recipient now
        recipients = new address[](1);
        recipients[0] = recipientAddr;
        vm.startPrank(ownerAddr);
        mscaAddr.callWithReturnDataOrRevert(0, abi.encodeCall(IAddressBookPlugin.addAllowedRecipients, (recipients)));
        vm.stopPrank();

        // do another user op with same calldata this time
        userOp = buildPartialUserOp(
            mscaAddr,
            entryPoint.getNonce(mscaAddr, 0),
            "0x",
            vm.toString(executeCallData),
            83353,
            1028650,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        ops = new UserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
        // verify recipient balance now has 2 tokens
        assertEq(testLiquidityPool.balanceOf(recipientAddr), 2);
    }

    // 1. add the recipient, send ERC20 tokens successfully, run through hook (pass) => validation (pass)
    // 2. remove the recipient
    // 3. hook should fail now
    function testExecuteWithAddressBookViaRuntimeWithERC20PassThenFail() public {
        address[] memory recipients = new address[](1);
        address recipientAddr = vm.addr(1);
        recipients[0] = recipientAddr;
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] = FunctionReference(
            address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        );
        dependencies[1] =
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        vm.startPrank(ownerAddr);
        msca.installPlugin(addressBookPluginAddr, addressBookPluginManifest, abi.encode(recipients), dependencies);
        vm.stopPrank();

        vm.deal(mscaAddr, 1 ether);
        testLiquidityPool.mint(mscaAddr, 10);
        address target = address(testLiquidityPool);
        uint256 value = 0;
        bytes memory data = abi.encodeCall(testLiquidityPool.transfer, (recipientAddr, 2));
        vm.startPrank(ownerAddr);
        mscaAddr.callWithReturnDataOrRevert(
            0, abi.encodeCall(AddressBookPlugin.executeWithAddressBook, (target, value, data, recipientAddr))
        );
        vm.stopPrank();
        assertEq(testLiquidityPool.balanceOf(recipientAddr), 2);

        // remove the recipient now
        vm.startPrank(ownerAddr);
        mscaAddr.callWithReturnDataOrRevert(0, abi.encodeCall(IAddressBookPlugin.removeAllowedRecipients, (recipients)));
        vm.stopPrank();

        // now execute w/o allowed recipient
        vm.startPrank(ownerAddr);
        bytes memory revertReason =
            abi.encodeWithSelector(IAddressBookPlugin.UnauthorizedRecipient.selector, ownerAddr, recipientAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                BaseMSCA.PreRuntimeValidationHookFailed.selector, address(addressBookPlugin), 1, revertReason
            )
        );
        mscaAddr.callWithReturnDataOrRevert(
            0, abi.encodeCall(AddressBookPlugin.executeWithAddressBook, (target, value, data, recipientAddr))
        );
        vm.stopPrank();
        // didn't change
        assertEq(testLiquidityPool.balanceOf(recipientAddr), 2);
    }

    // 1. empty allow list, fail to send ERC20 tokens, run through hook (fail) => validation (pass)
    // 2. allow the recipient
    // 3. send ERC20 tokens successfully, pass both hook and validation
    function testExecuteWithAddressBookViaRuntimeWithERC20FailThenPass() public {
        address[] memory recipients = new address[](0);
        // unused now
        address recipientAddr = vm.addr(1);
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] = FunctionReference(
            address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        );
        dependencies[1] =
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        vm.startPrank(ownerAddr);
        msca.installPlugin(addressBookPluginAddr, addressBookPluginManifest, abi.encode(recipients), dependencies);
        vm.stopPrank();

        vm.deal(mscaAddr, 1 ether);
        testLiquidityPool.mint(mscaAddr, 10);
        address target = address(testLiquidityPool);
        uint256 value = 0;
        bytes memory data = abi.encodeCall(testLiquidityPool.transfer, (recipientAddr, 2));
        vm.startPrank(ownerAddr);
        bytes memory revertReason =
            abi.encodeWithSelector(IAddressBookPlugin.UnauthorizedRecipient.selector, ownerAddr, recipientAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                BaseMSCA.PreRuntimeValidationHookFailed.selector, address(addressBookPlugin), 1, revertReason
            )
        );
        mscaAddr.callWithReturnDataOrRevert(
            0, abi.encodeCall(AddressBookPlugin.executeWithAddressBook, (target, value, data, recipientAddr))
        );
        vm.stopPrank();
        // didn't change
        assertEq(testLiquidityPool.balanceOf(recipientAddr), 0);

        // add the recipient now
        vm.startPrank(ownerAddr);
        recipients = new address[](1);
        recipients[0] = recipientAddr;
        mscaAddr.callWithReturnDataOrRevert(0, abi.encodeCall(IAddressBookPlugin.addAllowedRecipients, (recipients)));
        vm.stopPrank();

        // now execute with allowed recipient
        vm.startPrank(ownerAddr);
        mscaAddr.callWithReturnDataOrRevert(
            0, abi.encodeCall(AddressBookPlugin.executeWithAddressBook, (target, value, data, recipientAddr))
        );
        vm.stopPrank();
        // balance increase
        assertEq(testLiquidityPool.balanceOf(recipientAddr), 2);
    }

    function testAddAndRemoveAllowedRecipientsViaRuntime() public {
        // install plugin first
        vm.startPrank(ownerAddr);
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] = FunctionReference(
            address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        );
        dependencies[1] =
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        address[] memory recipients = new address[](0);
        msca.installPlugin(addressBookPluginAddr, addressBookPluginManifest, abi.encode(recipients), dependencies);
        bytes memory returnData =
            mscaAddr.callWithReturnDataOrRevert(0, abi.encodeCall(IAddressBookPlugin.getAllowedRecipients, (mscaAddr)));
        address[] memory allowedRecipients = abi.decode(returnData, (address[]));
        assertEq(allowedRecipients.length, 0);

        address recipientAddr = vm.addr(1);
        recipients = new address[](1);
        recipients[0] = recipientAddr;
        bytes memory executeCallData = abi.encodeCall(IAddressBookPlugin.addAllowedRecipients, (recipients));
        mscaAddr.callWithReturnDataOrRevert(0, executeCallData);
        returnData =
            mscaAddr.callWithReturnDataOrRevert(0, abi.encodeCall(IAddressBookPlugin.getAllowedRecipients, (mscaAddr)));
        allowedRecipients = abi.decode(returnData, (address[]));
        assertEq(allowedRecipients.length, 1);
        assertEq(allowedRecipients[0], recipientAddr);

        // add the same recipient again
        executeCallData = abi.encodeCall(IAddressBookPlugin.addAllowedRecipients, (recipients));
        bytes memory revertReason =
            abi.encodeWithSelector(IAddressBookPlugin.FailToAddRecipient.selector, mscaAddr, recipientAddr);
        vm.expectRevert(revertReason);
        mscaAddr.callWithReturnDataOrRevert(0, executeCallData);
        returnData =
            mscaAddr.callWithReturnDataOrRevert(0, abi.encodeCall(IAddressBookPlugin.getAllowedRecipients, (mscaAddr)));
        allowedRecipients = abi.decode(returnData, (address[]));
        // didn't change
        assertEq(allowedRecipients.length, 1);
        assertEq(allowedRecipients[0], recipientAddr);

        executeCallData = abi.encodeCall(IAddressBookPlugin.removeAllowedRecipients, (recipients));
        mscaAddr.callWithReturnDataOrRevert(0, executeCallData);
        returnData =
            mscaAddr.callWithReturnDataOrRevert(0, abi.encodeCall(IAddressBookPlugin.getAllowedRecipients, (mscaAddr)));
        allowedRecipients = abi.decode(returnData, (address[]));
        assertEq(allowedRecipients.length, 0);

        // delete from empty recipients
        abi.encodeCall(IAddressBookPlugin.removeAllowedRecipients, (recipients));
        revertReason =
            abi.encodeWithSelector(IAddressBookPlugin.FailToRemoveRecipient.selector, mscaAddr, recipientAddr);
        vm.expectRevert(revertReason);
        mscaAddr.callWithReturnDataOrRevert(0, executeCallData);
        returnData =
            mscaAddr.callWithReturnDataOrRevert(0, abi.encodeCall(IAddressBookPlugin.getAllowedRecipients, (mscaAddr)));
        allowedRecipients = abi.decode(returnData, (address[]));
        assertEq(allowedRecipients.length, 0);
        vm.stopPrank();

        vm.startPrank(vm.addr(123));
        // add the same recipient again
        executeCallData = abi.encodeCall(IAddressBookPlugin.addAllowedRecipients, (recipients));
        revertReason = abi.encodeWithSelector(UnauthorizedCaller.selector);
        vm.expectRevert(
            abi.encodeWithSelector(
                BaseMSCA.RuntimeValidationFailed.selector, address(singleOwnerPlugin), 0, revertReason
            )
        );
        mscaAddr.callWithReturnDataOrRevert(0, executeCallData);

        // delete from empty recipients
        abi.encodeCall(IAddressBookPlugin.removeAllowedRecipients, (recipients));
        revertReason = abi.encodeWithSelector(UnauthorizedCaller.selector);
        vm.expectRevert(
            abi.encodeWithSelector(
                BaseMSCA.RuntimeValidationFailed.selector, address(singleOwnerPlugin), 0, revertReason
            )
        );
        mscaAddr.callWithReturnDataOrRevert(0, executeCallData);
        vm.stopPrank();
    }

    function testAddAndRemoveAllowedRecipientsViaUserOp() public {
        // install plugin first
        vm.startPrank(ownerAddr);
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] = FunctionReference(
            address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        );
        dependencies[1] =
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        address[] memory recipients = new address[](0);
        msca.installPlugin(addressBookPluginAddr, addressBookPluginManifest, abi.encode(recipients), dependencies);
        bytes memory returnData =
            mscaAddr.callWithReturnDataOrRevert(0, abi.encodeCall(IAddressBookPlugin.getAllowedRecipients, (mscaAddr)));
        address[] memory allowedRecipients = abi.decode(returnData, (address[]));
        assertEq(allowedRecipients.length, 0);

        vm.deal(mscaAddr, 1 ether);
        address recipientAddr = vm.addr(1);
        recipients = new address[](1);
        recipients[0] = recipientAddr;
        uint256 acctNonce = entryPoint.getNonce(mscaAddr, 0);
        bytes memory executeCallData = abi.encodeCall(IAddressBookPlugin.addAllowedRecipients, (recipients));
        UserOperation memory userOp = buildPartialUserOp(
            mscaAddr,
            acctNonce,
            "0x",
            vm.toString(executeCallData),
            83353,
            1028650,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();

        vm.startPrank(ownerAddr);
        returnData =
            mscaAddr.callWithReturnDataOrRevert(0, abi.encodeCall(IAddressBookPlugin.getAllowedRecipients, (mscaAddr)));
        allowedRecipients = abi.decode(returnData, (address[]));
        assertEq(allowedRecipients.length, 1);
        assertEq(allowedRecipients[0], recipientAddr);
        vm.stopPrank();

        executeCallData = abi.encodeCall(IAddressBookPlugin.removeAllowedRecipients, (recipients));
        userOp = buildPartialUserOp(
            mscaAddr,
            entryPoint.getNonce(mscaAddr, 0),
            "0x",
            vm.toString(executeCallData),
            83353,
            1028650,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        ops = new UserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();

        vm.startPrank(ownerAddr);
        returnData =
            mscaAddr.callWithReturnDataOrRevert(0, abi.encodeCall(IAddressBookPlugin.getAllowedRecipients, (mscaAddr)));
        allowedRecipients = abi.decode(returnData, (address[]));
        assertEq(allowedRecipients.length, 0);
        vm.stopPrank();
    }

    function testSkipInstallingAnyRecipient() public {
        vm.deal(ownerAddr, 10e18);
        vm.startPrank(ownerAddr, ownerAddr);
        address[] memory plugins = new address[](1);
        bytes32[] memory manifestHashes = new bytes32[](1);
        bytes[] memory pluginInstallData = new bytes[](1);
        plugins[0] = address(singleOwnerPlugin);
        manifestHashes[0] = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
        pluginInstallData[0] = abi.encode(ownerAddr);
        bytes memory _initializingData = abi.encode(plugins, manifestHashes, pluginInstallData);
        console.log(
            "\nOwner(%s) calls < UpgradableMSCAFactory.createAccount(ownerAddr, bytes32(0), _initializingData) >",
            ownerAddr
        );
        msca = factory.createAccount(addressToBytes32(ownerAddr), bytes32(0), _initializingData);
        console.log("address(msca) -> %s", address(msca));
        (bool sent,) = address(msca).call{value: 10e18}("");
        assertTrue(sent);
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] = FunctionReference(
            address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        );
        dependencies[1] =
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        Call[] memory _calls = new Call[](1);
        address[] memory recipients = new address[](0);
        _calls[0].target = address(msca);
        _calls[0].value = 0;
        _calls[0].data = abi.encodeCall(
            IPluginManager.installPlugin,
            (addressBookPluginAddr, addressBookPluginManifest, abi.encode(recipients), dependencies)
        );
        console.log("\nOwner(%s) calls < executeBatch(_calls) >", ownerAddr);
        msca.executeBatch(_calls);
        address destAddr = makeAddr("testSkipInstallingAnyRecipient_dest");
        address target = destAddr;
        uint256 value = 4e18;
        bytes memory data = "";
        address recipient = address(0);
        bytes memory executeCallData =
            abi.encodeCall(AddressBookPlugin.executeWithAddressBook, (target, value, data, recipient));
        UserOperation memory userOp =
            buildPartialUserOp(address(msca), 0, "0x", vm.toString(executeCallData), 5000000, 20000000, 0, 2, 1, "0x");
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        userOp.signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;
        console.log("");
        console.log("address(msca).balance -> %s", address(msca).balance);
        console.log("address(dest).balance -> %s", address(destAddr).balance);
        console.log("\nOwner(%s) calls < entryPoint.handleOps(userOps, msca) >", ownerAddr);
        entryPoint.handleOps(userOps, payable(address(msca)));
        console.log("");
        console.log("address(msca).balance -> %s", address(msca).balance);
        console.log("address(dest).balance -> %s", address(destAddr).balance);
        assertEq(address(destAddr).balance, 4e18);

        // test execute batch
        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        bytes[] memory dataArr = new bytes[](1);
        address[] memory verifiedRecipients = new address[](1);
        targets[0] = destAddr;
        values[0] = 4e18;
        verifiedRecipients[0] = address(0);
        executeCallData = abi.encodeCall(
            AddressBookPlugin.executeBatchWithAddressBook, (targets, values, dataArr, verifiedRecipients)
        );
        userOp =
            buildPartialUserOp(address(msca), 1, "0x", vm.toString(executeCallData), 5000000, 20000000, 0, 2, 1, "0x");
        userOpHash = entryPoint.getUserOpHash(userOp);
        userOp.signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOps = new UserOperation[](1);
        userOps[0] = userOp;
        console.log("");
        console.log("address(msca).balance -> %s", address(msca).balance);
        console.log("address(dest).balance -> %s", address(destAddr).balance);
        console.log("\nOwner(%s) calls < entryPoint.handleOps(userOps, msca) >", ownerAddr);
        entryPoint.handleOps(userOps, payable(address(msca)));
        console.log("");
        console.log("address(msca).balance -> %s", address(msca).balance);
        console.log("address(dest).balance -> %s", address(destAddr).balance);
        assertEq(address(destAddr).balance, 8e18);
        vm.stopPrank();
    }
}
