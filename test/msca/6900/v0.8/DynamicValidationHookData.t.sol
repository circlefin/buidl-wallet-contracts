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

import {AccountTestUtils} from "./utils/AccountTestUtils.sol";
import {UpgradableMSCA} from "../../../../src/msca/6900/v0.8/account/UpgradableMSCA.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {TestCircleMSCA} from "./TestCircleMSCA.sol";
import {ModuleEntity} from "../../../../src/msca/6900/v0.8/common/Types.sol";
import {TestCircleMSCAFactory} from "./TestCircleMSCAFactory.sol";
import {SingleSignerValidationModule} from
    "../../../../src/msca/6900/v0.8/plugins/v1_0_0/validation/SingleSignerValidationModule.sol";
import {ModuleEntityLib} from "../../../../src/msca/6900/v0.8/libs/thirdparty/ModuleEntityLib.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PluginManager} from "../../../../src/msca/6900/v0.8/managers/PluginManager.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IStandardExecutor} from "../../../../src/msca/6900/v0.8/interfaces/IStandardExecutor.sol";
import {TestAddressBookPlugin} from "./helpers/TestAddressBookPlugin.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ValidationConfigLib} from "../../../../src/msca/6900/v0.8/libs/thirdparty/ValidationConfigLib.sol";

// We use TestCircleMSCA (that inherits from UpgradableMSCA) because it has some convenience functions
contract DynamicValidationHookDataTest is AccountTestUtils {
    using ModuleEntityLib for ModuleEntity;

    error PreRuntimeValidationHookFailed(address plugin, uint32 entityId, bytes revertReason);

    IEntryPoint private entryPoint = new EntryPoint();
    PluginManager private pluginManager = new PluginManager();
    uint256 internal ownerPrivateKey;
    address private ownerAddr;
    address payable private beneficiary; // e.g. bundler
    TestCircleMSCAFactory private factory;
    address private factoryOwner;
    SingleSignerValidationModule private singleSignerValidationModule;
    ModuleEntity private ownerValidation;
    TestAddressBookPlugin private addressBookPlugin;
    bytes private initializingData;
    bytes32 private salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
    UpgradableMSCA private msca;

    function setUp() public {
        factoryOwner = makeAddr("factoryOwner");
        beneficiary = payable(address(makeAddr("bundler")));
        factory = new TestCircleMSCAFactory(factoryOwner, entryPoint, pluginManager);
        singleSignerValidationModule = new SingleSignerValidationModule();
        addressBookPlugin = new TestAddressBookPlugin();
        address[] memory plugins = new address[](2);
        plugins[0] = address(singleSignerValidationModule);
        plugins[1] = address(addressBookPlugin);
        bool[] memory _permissions = new bool[](2);
        _permissions[0] = true;
        _permissions[1] = true;
        vm.startPrank(factoryOwner);
        factory.setPlugins(plugins, _permissions);
        vm.stopPrank();
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));

        address accountImplementation = address(factory.accountImplementation());
        msca = TestCircleMSCA(payable(new ERC1967Proxy(accountImplementation, "")));
    }

    // send native token, run through pre userOp hook (pass) => validation (pass)
    function testPreUserOpHookAndValidationBothPass() public {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testPreUserOpHookAndValidationBothPass");
        address recipientAddr = vm.addr(1);
        _installValidationForMSCA(recipientAddr);

        // send eth
        // build userOp
        bytes memory executeCallData = abi.encodeCall(IStandardExecutor.execute, (recipientAddr, 1, ""));
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca), 0, "0x", vm.toString(executeCallData), 83353, 1028650, 45484, 516219199704, 1130000000, "0x"
        );
        // signature is the data for ownerValidation
        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);

        // pack the recipientAddr into hook data for check
        PreValidationHookData[] memory validationHookData = new PreValidationHookData[](1);
        validationHookData[0] = PreValidationHookData({index: 0, hookData: abi.encodePacked(recipientAddr)});
        // now encode the signature with hook function, validation function, global validation function flag
        userOp.signature = encodeSignature(validationHookData, ownerValidation, signature, true);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
        // verify recipient balance
        assertEq(recipientAddr.balance, 1);
    }

    // send native token, run through pre runtime hook (pass) => validation (pass)
    function testPreRuntimeHookAndValidationBothPass() public {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testPreRuntimeHookAndValidationBothPass");
        address recipientAddr = vm.addr(1);
        _installValidationForMSCA(recipientAddr);

        // send eth
        bytes memory executeCallData = abi.encodeCall(IStandardExecutor.execute, (recipientAddr, 1, ""));
        // pack the recipientAddr into hook data for check
        PreValidationHookData[] memory validationHookData = new PreValidationHookData[](1);
        validationHookData[0] = PreValidationHookData({index: 0, hookData: abi.encodePacked(recipientAddr)});
        // now encode the signature with hook function, validation function, global validation function flag
        bytes memory authorizationData = encodeSignature(validationHookData, ownerValidation, "", true);

        vm.startPrank(ownerAddr);
        msca.executeWithAuthorization(executeCallData, authorizationData);
        vm.stopPrank();
        // verify recipient balance
        assertEq(recipientAddr.balance, 1);
    }

    // pre userOp hook (fail the recipient address check)
    function testPreUserOpHookFail_randomHookData() public {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testPreUserOpHookFail_randomHookData");
        address recipientAddr = vm.addr(1);
        _installValidationForMSCA(recipientAddr);

        // send eth
        // build userOp
        bytes memory executeCallData = abi.encodeCall(IStandardExecutor.execute, (recipientAddr, 1, ""));
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca), 0, "0x", vm.toString(executeCallData), 83353, 1028650, 45484, 516219199704, 1130000000, "0x"
        );
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        // signature is the data for ownerValidation
        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);

        // pack a randomRecipient into hook data for check, would fail
        address randomRecipient = vm.addr(2);
        PreValidationHookData[] memory validationHookData = new PreValidationHookData[](1);
        validationHookData[0] = PreValidationHookData({index: 0, hookData: abi.encodePacked(randomRecipient)});
        // now encode the signature with hook function, validation function, global validation function flag
        userOp.signature = encodeSignature(validationHookData, ownerValidation, signature, true);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSignature("UnauthorizedRecipient(address,address)", address(msca), randomRecipient)
            )
        );
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
        // verify recipient balance
        assertEq(recipientAddr.balance, 0);
    }

    // pre userOp hook (fail on zero hook data)
    function testPreUserOpHookFail_noHookData() public {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testPreUserOpHookFail_noHookData");
        address recipientAddr = vm.addr(1);
        _installValidationForMSCA(recipientAddr);

        // send eth
        // build userOp
        bytes memory executeCallData = abi.encodeCall(IStandardExecutor.execute, (recipientAddr, 1, ""));
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca), 0, "0x", vm.toString(executeCallData), 83353, 1028650, 45484, 516219199704, 1130000000, "0x"
        );
        // signature is the data for ownerValidation
        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);

        // do not pack any hook data for check, would fail
        PreValidationHookData[] memory validationHookData = new PreValidationHookData[](0);
        // now encode the signature with empty hook function, validation function, global validation function flag
        userOp.signature = encodeSignature(validationHookData, ownerValidation, signature, true);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSignature("UnauthorizedRecipient(address,address)", address(msca), address(0))
            )
        );
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
        // verify recipient balance
        assertEq(recipientAddr.balance, 0);
    }

    // pre userOp hook (fail on more hook data)
    function testPreUserOpHookFail_badHookIndex() public {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testPreUserOpHookFail_badHookIndex");
        address recipientAddr = vm.addr(1);
        _installValidationForMSCA(recipientAddr);

        // send eth
        // build userOp
        bytes memory executeCallData = abi.encodeCall(IStandardExecutor.execute, (recipientAddr, 1, ""));
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca), 0, "0x", vm.toString(executeCallData), 83353, 1028650, 45484, 516219199704, 1130000000, "0x"
        );
        // signature is the data for ownerValidation
        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);

        // pack more hook data than installed for check, would fail on validation function boundary check
        PreValidationHookData[] memory validationHookData = new PreValidationHookData[](2);
        validationHookData[0] = PreValidationHookData({index: 0, hookData: abi.encodePacked(recipientAddr)});
        validationHookData[1] = PreValidationHookData({index: 1, hookData: abi.encodePacked(recipientAddr)});
        // now encode the signature with hook function, validation function, global validation function flag
        userOp.signature = encodeSignature(validationHookData, ownerValidation, signature, true);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSignature("InvalidSignatureSegmentPacking()")
            )
        );
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
        // verify recipient balance
        assertEq(recipientAddr.balance, 0);
    }

    // pre userOp hook (fail on out of order signature segment)
    function testPreUserOpHookFail_hookIndexOutOfOrder() public {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testPreUserOpHookFail_hookIndexOutOfOrder");
        address recipientAddr = vm.addr(1);
        _installValidationForMSCA(recipientAddr);

        // send eth
        // build userOp
        bytes memory executeCallData = abi.encodeCall(IStandardExecutor.execute, (recipientAddr, 1, ""));
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca), 0, "0x", vm.toString(executeCallData), 83353, 1028650, 45484, 516219199704, 1130000000, "0x"
        );
        // signature is the data for ownerValidation
        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);

        // pack out of order hook data for check, would fail on out of order check
        PreValidationHookData[] memory validationHookData = new PreValidationHookData[](2);
        validationHookData[0] = PreValidationHookData({index: 0, hookData: abi.encodePacked(recipientAddr)});
        // supposed to be 1, but we set to 0 to trigger OOO
        validationHookData[1] = PreValidationHookData({index: 0, hookData: abi.encodePacked(recipientAddr)});
        // now encode the signature with hook function, validation function, global validation function flag
        userOp.signature = encodeSignature(validationHookData, ownerValidation, signature, true);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSignature("SignatureSegmentOutOfOrder()")
            )
        );
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
        // verify recipient balance
        assertEq(recipientAddr.balance, 0);
    }

    // pre userOp hook (fail on empty hook data)
    function testPreUserOpHookFail_emptyHookData() public {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testPreUserOpHookFail_emptyHookData");
        address recipientAddr = vm.addr(1);
        _installValidationForMSCA(recipientAddr);

        // send eth
        // build userOp
        bytes memory executeCallData = abi.encodeCall(IStandardExecutor.execute, (recipientAddr, 1, ""));
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca), 0, "0x", vm.toString(executeCallData), 83353, 1028650, 45484, 516219199704, 1130000000, "0x"
        );
        // signature is the data for ownerValidation
        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);

        // pack "" into hook data for check
        PreValidationHookData[] memory validationHookData = new PreValidationHookData[](1);
        // empty hook data
        validationHookData[0] = PreValidationHookData({index: 0, hookData: ""});
        // now encode the signature with hook function, validation function, global validation function flag
        userOp.signature = encodeSignature(validationHookData, ownerValidation, signature, true);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSignature("ZeroSignatureSegment()")
            )
        );
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
        // verify recipient balance
        assertEq(recipientAddr.balance, 0);
    }

    // pre runtime hook (fail the recipient address check)
    function testPreRuntimeHookFail_randomHookData() public {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testPreRuntimeHookFail_randomHookData");
        address recipientAddr = vm.addr(1);
        _installValidationForMSCA(recipientAddr);

        // send eth
        bytes memory executeCallData = abi.encodeCall(IStandardExecutor.execute, (recipientAddr, 1, ""));
        // pack a randomRecipient into hook data for check, would fail
        address randomRecipient = vm.addr(2);
        PreValidationHookData[] memory validationHookData = new PreValidationHookData[](1);
        validationHookData[0] = PreValidationHookData({index: 0, hookData: abi.encodePacked(randomRecipient)});
        // now encode the signature with hook function, validation function, global validation function flag
        bytes memory authorizationData = encodeSignature(validationHookData, ownerValidation, "", true);

        vm.startPrank(ownerAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                PreRuntimeValidationHookFailed.selector,
                address(addressBookPlugin),
                uint32(TestAddressBookPlugin.EntityId.PRE_VALIDATION_HOOK_EXECUTE_ADDRESS_BOOK),
                abi.encodeWithSignature("UnauthorizedRecipient(address,address)", address(ownerAddr), randomRecipient)
            )
        );
        msca.executeWithAuthorization(executeCallData, authorizationData);
        vm.stopPrank();
        // verify recipient balance
        assertEq(recipientAddr.balance, 0);
    }

    // pre runtime hook (fail on zero hook data)
    function testPreRuntimeHookFail_noHookData() public {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testPreRuntimeHookFail_noHookData");
        address recipientAddr = vm.addr(1);
        _installValidationForMSCA(recipientAddr);

        // send eth
        bytes memory executeCallData = abi.encodeCall(IStandardExecutor.execute, (recipientAddr, 1, ""));
        // do not pack any hook data for check, would fail
        PreValidationHookData[] memory validationHookData = new PreValidationHookData[](0);
        // now encode the signature with hook function, validation function, global validation function flag
        bytes memory authorizationData = encodeSignature(validationHookData, ownerValidation, "", true);

        vm.startPrank(ownerAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                PreRuntimeValidationHookFailed.selector,
                address(addressBookPlugin),
                uint32(TestAddressBookPlugin.EntityId.PRE_VALIDATION_HOOK_EXECUTE_ADDRESS_BOOK),
                abi.encodeWithSignature("UnauthorizedRecipient(address,address)", address(ownerAddr), address(0))
            )
        );
        msca.executeWithAuthorization(executeCallData, authorizationData);
        vm.stopPrank();
        // verify recipient balance
        assertEq(recipientAddr.balance, 0);
    }

    // pre runtime hook (fail on more hook data)
    function testPreRuntimeHookFail_badHookIndex() public {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testPreRuntimeHookFail_badHookIndex");
        address recipientAddr = vm.addr(1);
        _installValidationForMSCA(recipientAddr);

        // send eth
        bytes memory executeCallData = abi.encodeCall(IStandardExecutor.execute, (recipientAddr, 1, ""));
        // pack more hook data than installed for check, would fail on validation function boundary check
        PreValidationHookData[] memory validationHookData = new PreValidationHookData[](2);
        validationHookData[0] = PreValidationHookData({index: 0, hookData: abi.encodePacked(recipientAddr)});
        validationHookData[1] = PreValidationHookData({index: 1, hookData: abi.encodePacked(recipientAddr)});
        // now encode the signature with hook function, validation function, global validation function flag
        bytes memory authorizationData = encodeSignature(validationHookData, ownerValidation, "", true);

        vm.startPrank(ownerAddr);
        vm.expectRevert(abi.encodeWithSignature("InvalidSignatureSegmentPacking()"));
        msca.executeWithAuthorization(executeCallData, authorizationData);
        vm.stopPrank();
        // verify recipient balance
        assertEq(recipientAddr.balance, 0);
    }

    // pre runtime hook (fail on out of order signature segment)
    function testPreRuntimeHookFail_hookIndexOutOfOrder() public {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testPreRuntimeHookFail_hookIndexOutOfOrder");
        address recipientAddr = vm.addr(1);
        _installValidationForMSCA(recipientAddr);

        // send eth
        bytes memory executeCallData = abi.encodeCall(IStandardExecutor.execute, (recipientAddr, 1, ""));
        // pack out of order hook data for check, would fail on out of order check
        PreValidationHookData[] memory validationHookData = new PreValidationHookData[](2);
        validationHookData[0] = PreValidationHookData({index: 0, hookData: abi.encodePacked(recipientAddr)});
        // supposed to be 1, but we set to 0 to trigger OOO
        validationHookData[1] = PreValidationHookData({index: 0, hookData: abi.encodePacked(recipientAddr)});
        // now encode the signature with hook function, validation function, global validation function flag
        bytes memory authorizationData = encodeSignature(validationHookData, ownerValidation, "", true);

        vm.startPrank(ownerAddr);
        vm.expectRevert(abi.encodeWithSignature("SignatureSegmentOutOfOrder()"));
        msca.executeWithAuthorization(executeCallData, authorizationData);
        vm.stopPrank();
        // verify recipient balance
        assertEq(recipientAddr.balance, 0);
    }

    // pre runtime hook (fail on empty hook data)
    function testPreRuntimeHookFail_emptyHookData() public {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testPreRuntimeHookFail_emptyHookData");
        address recipientAddr = vm.addr(1);
        _installValidationForMSCA(recipientAddr);

        // send eth
        bytes memory executeCallData = abi.encodeCall(IStandardExecutor.execute, (recipientAddr, 1, ""));
        // pack "" into hook data for check
        PreValidationHookData[] memory validationHookData = new PreValidationHookData[](1);
        // empty hook data
        validationHookData[0] = PreValidationHookData({index: 0, hookData: ""});
        // now encode the signature with hook function, validation function, global validation function flag
        bytes memory authorizationData = encodeSignature(validationHookData, ownerValidation, "", true);

        vm.startPrank(ownerAddr);
        vm.expectRevert(abi.encodeWithSignature("ZeroSignatureSegment()"));
        msca.executeWithAuthorization(executeCallData, authorizationData);
        vm.stopPrank();
        // verify recipient balance
        assertEq(recipientAddr.balance, 0);
    }

    function _installValidationForMSCA(address recipientAddr) internal {
        address[] memory recipients = new address[](1);
        recipients[0] = recipientAddr;

        ModuleEntity[] memory preValidationHooks = new ModuleEntity[](1);
        preValidationHooks[0] = ModuleEntityLib.pack(
            address(addressBookPlugin), uint32(TestAddressBookPlugin.EntityId.PRE_VALIDATION_HOOK_EXECUTE_ADDRESS_BOOK)
        );
        // onInstall
        bytes[] memory preValidationHooksData = new bytes[](1);
        preValidationHooksData[0] = abi.encode(recipients);
        bytes memory packedPreValidationHooks = abi.encode(preValidationHooks, preValidationHooksData);

        vm.startPrank(address(msca));
        // ownerValidation is global
        msca.installValidation(
            ValidationConfigLib.pack(ownerValidation, true, true),
            new bytes4[](0),
            abi.encode(uint32(0), ownerAddr),
            packedPreValidationHooks,
            bytes("")
        );
        vm.stopPrank();
        vm.deal(address(msca), 1 ether);
    }
}
