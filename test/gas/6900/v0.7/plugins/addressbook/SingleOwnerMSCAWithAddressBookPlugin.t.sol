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

import {FunctionReference} from "../../../../../../src/msca/6900/v0.7/common/Structs.sol";

import {
    PluginManager,
    SingleOwnerMSCA,
    SingleOwnerMSCAFactory
} from "../../../../../../src/msca/6900/v0.7/factories/semi/SingleOwnerMSCAFactory.sol";
import {
    AddressBookPlugin,
    IAddressBookPlugin,
    UserOperation
} from "../../../../../../src/msca/6900/v0.7/plugins/v1_0_0/addressbook/AddressBookPlugin.sol";
import {PluginGasProfileBaseTest} from "../../../../PluginGasProfileBase.t.sol";

contract SingleOwnerMSCAWithAddressBookPluginTest is PluginGasProfileBaseTest {
    event PluginInstalled(address indexed plugin, bytes32 manifestHash, FunctionReference[] dependencies);
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

    PluginManager private pluginManager = new PluginManager();
    uint256 internal ownerPrivateKey;
    address private ownerAddr;
    SingleOwnerMSCAFactory private factory;
    AddressBookPlugin private addressBookPlugin;
    SingleOwnerMSCA private msca;
    address private singleOwnerPluginAddr;
    address private mscaAddr;
    string public accountAndPluginType;

    function setUp() public override {
        super.setUp();
        accountAndPluginType = "SingleOwnerMSCAWithAddressBookPlugin";
        factory = new SingleOwnerMSCAFactory(address(entryPoint), address(pluginManager));
        addressBookPlugin = new AddressBookPlugin();
        singleOwnerPluginAddr = address(addressBookPlugin);
    }

    function testBenchmarkAll() external override {
        testBenchmarkPluginInstall();
        testBenchmarkPluginUninstall();
        testBenchmarkAddRecipient();
        testBenchmarkRemoveRecipient();
        testBenchmarkExecuteWithAddressBookNativeToken();
        writeTestResult(accountAndPluginType);
    }

    function testBenchmarkAddRecipient() internal {
        // create account first
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testBenchmarkAddRecipient");
        createAccount();
        bytes32 manifestHash = keccak256(abi.encode(addressBookPlugin.pluginManifest()));
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] =
            FunctionReference(mscaAddr, uint8(SingleOwnerMSCA.FunctionId.NATIVE_RUNTIME_VALIDATION_OWNER_OR_SELF));
        dependencies[1] = FunctionReference(mscaAddr, uint8(SingleOwnerMSCA.FunctionId.NATIVE_USER_OP_VALIDATION_OWNER));
        vm.startPrank(ownerAddr);
        msca.installPlugin(address(addressBookPlugin), manifestHash, "", dependencies);
        vm.stopPrank();

        uint256 acctNonce = entryPoint.getNonce(mscaAddr, 0);
        address[] memory recipients = new address[](1);
        recipients[0] = vm.addr(1);
        bytes memory executeCallData = abi.encodeCall(IAddressBookPlugin.addAllowedRecipients, (recipients));
        UserOperation memory userOp = buildPartialUserOp(mscaAddr, acctNonce, vm.toString(executeCallData));

        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;

        string memory testName = "0003_addRecipient";
        executeUserOp(mscaAddr, userOp, testName, 0);
    }

    function testBenchmarkRemoveRecipient() internal {
        // create account first
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testBenchmarkRemoveRecipient");
        createAccount();
        bytes32 manifestHash = keccak256(abi.encode(addressBookPlugin.pluginManifest()));
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] =
            FunctionReference(mscaAddr, uint8(SingleOwnerMSCA.FunctionId.NATIVE_RUNTIME_VALIDATION_OWNER_OR_SELF));
        dependencies[1] = FunctionReference(mscaAddr, uint8(SingleOwnerMSCA.FunctionId.NATIVE_USER_OP_VALIDATION_OWNER));
        address[] memory recipients = new address[](1);
        recipients[0] = vm.addr(1);
        vm.startPrank(ownerAddr);
        msca.installPlugin(address(addressBookPlugin), manifestHash, abi.encode(recipients), dependencies);
        vm.stopPrank();

        uint256 acctNonce = entryPoint.getNonce(mscaAddr, 0);
        bytes memory executeCallData = abi.encodeCall(IAddressBookPlugin.removeAllowedRecipients, (recipients));
        UserOperation memory userOp = buildPartialUserOp(mscaAddr, acctNonce, vm.toString(executeCallData));

        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;

        string memory testName = "0004_removeRecipient";
        executeUserOp(mscaAddr, userOp, testName, 0);
    }

    function testBenchmarkExecuteWithAddressBookNativeToken() internal {
        // create account first
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testBenchmarkExecuteWithAddressBookNativeToken");
        createAccount();
        bytes32 manifestHash = keccak256(abi.encode(addressBookPlugin.pluginManifest()));
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] =
            FunctionReference(mscaAddr, uint8(SingleOwnerMSCA.FunctionId.NATIVE_RUNTIME_VALIDATION_OWNER_OR_SELF));
        dependencies[1] = FunctionReference(mscaAddr, uint8(SingleOwnerMSCA.FunctionId.NATIVE_USER_OP_VALIDATION_OWNER));
        address recipientAddr = vm.addr(1);
        address[] memory recipients = new address[](1);
        recipients[0] = recipientAddr;
        vm.startPrank(ownerAddr);
        msca.installPlugin(address(addressBookPlugin), manifestHash, abi.encode(recipients), dependencies);
        vm.stopPrank();

        uint256 acctNonce = entryPoint.getNonce(mscaAddr, 0);
        bytes memory executeCallData =
            abi.encodeCall(AddressBookPlugin.executeWithAddressBook, (recipientAddr, 1, "", recipientAddr));
        UserOperation memory userOp = buildPartialUserOp(mscaAddr, acctNonce, vm.toString(executeCallData));

        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;

        string memory testName = "0005_executeWithAddressBook_transferNativeToken";
        executeUserOp(mscaAddr, userOp, testName, 0);
    }

    function testBenchmarkPluginInstall() internal override {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testBenchmarkPluginInstall");
        // create account first
        createAccount();

        // now install
        uint256 acctNonce = entryPoint.getNonce(mscaAddr, 0);
        bytes32 manifestHash = keccak256(abi.encode(addressBookPlugin.pluginManifest()));
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] =
            FunctionReference(mscaAddr, uint8(SingleOwnerMSCA.FunctionId.NATIVE_RUNTIME_VALIDATION_OWNER_OR_SELF));
        dependencies[1] = FunctionReference(mscaAddr, uint8(SingleOwnerMSCA.FunctionId.NATIVE_USER_OP_VALIDATION_OWNER));
        bytes memory installCallData =
            abi.encodeCall(msca.installPlugin, (address(addressBookPlugin), manifestHash, "", dependencies));
        UserOperation memory userOp = buildPartialUserOp(mscaAddr, acctNonce, vm.toString(installCallData));

        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;

        string memory testName = "0001_install";
        executeUserOp(mscaAddr, userOp, testName, 0);
    }

    function testBenchmarkPluginUninstall() internal override {
        // create account first
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testBenchmarkPluginUninstall");
        createAccount();
        bytes32 manifestHash = keccak256(abi.encode(addressBookPlugin.pluginManifest()));
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] =
            FunctionReference(mscaAddr, uint8(SingleOwnerMSCA.FunctionId.NATIVE_RUNTIME_VALIDATION_OWNER_OR_SELF));
        dependencies[1] = FunctionReference(mscaAddr, uint8(SingleOwnerMSCA.FunctionId.NATIVE_USER_OP_VALIDATION_OWNER));
        vm.startPrank(ownerAddr);
        msca.installPlugin(address(addressBookPlugin), manifestHash, "", dependencies);
        vm.stopPrank();

        // now uninstall
        uint256 acctNonce = entryPoint.getNonce(mscaAddr, 0);
        bytes memory uninstallCallData = abi.encodeCall(msca.uninstallPlugin, (address(addressBookPlugin), "", ""));
        UserOperation memory userOp = buildPartialUserOp(mscaAddr, acctNonce, vm.toString(uninstallCallData));

        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;

        string memory testName = "0002_uninstall";
        executeUserOp(mscaAddr, userOp, testName, 0);
    }

    function createAccount() internal returns (address) {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        bytes memory initializingData = abi.encode(ownerAddr);
        vm.startPrank(ownerAddr);
        msca = factory.createAccount(ownerAddr, salt, initializingData);
        vm.stopPrank();
        mscaAddr = address(msca);
        vm.deal(mscaAddr, 1 ether);
        return mscaAddr;
    }
}
