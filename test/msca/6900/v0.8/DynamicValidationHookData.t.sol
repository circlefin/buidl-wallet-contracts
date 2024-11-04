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

import {UpgradableMSCA} from "../../../../src/msca/6900/v0.8/account/UpgradableMSCA.sol";

import {ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";

import {SingleSignerValidationModule} from
    "../../../../src/msca/6900/v0.8/modules/validation/SingleSignerValidationModule.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";

import {UpgradableMSCAFactory} from "../../../../src/msca/6900/v0.8/factories/UpgradableMSCAFactory.sol";

import {TestAddressBookModule} from "./helpers/TestAddressBookModule.sol";
import {AccountTestUtils} from "./utils/AccountTestUtils.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

// We use UpgradableMSCA (that inherits from UpgradableMSCA) because it has some convenience functions
contract DynamicValidationHookDataTest is AccountTestUtils {
    using ModuleEntityLib for ModuleEntity;

    error PreRuntimeValidationHookFailed(address module, uint32 entityId, bytes revertReason);
    error NonCanonicalEncoding();

    IEntryPoint private entryPoint = new EntryPoint();
    uint256 internal ownerPrivateKey;
    address private ownerAddr;
    address payable private beneficiary; // e.g. bundler
    UpgradableMSCAFactory private factory;
    address private factoryOwner;
    SingleSignerValidationModule private singleSignerValidationModule;
    ModuleEntity private ownerValidation;
    TestAddressBookModule private addressBookModule;
    bytes private initializingData;
    bytes32 private salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
    UpgradableMSCA private msca;

    function setUp() public {
        factoryOwner = makeAddr("factoryOwner");
        beneficiary = payable(address(makeAddr("bundler")));
        factory = new UpgradableMSCAFactory(factoryOwner, address(entryPoint));
        singleSignerValidationModule = new SingleSignerValidationModule();
        addressBookModule = new TestAddressBookModule();
        address[] memory modules = new address[](2);
        modules[0] = address(singleSignerValidationModule);
        modules[1] = address(addressBookModule);
        bool[] memory _permissions = new bool[](2);
        _permissions[0] = true;
        _permissions[1] = true;
        vm.startPrank(factoryOwner);
        factory.setModules(modules, _permissions);
        vm.stopPrank();
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));

        address accountImplementation = address(factory.ACCOUNT_IMPLEMENTATION());
        msca = UpgradableMSCA(payable(new ERC1967Proxy(accountImplementation, "")));
    }

    // send native token, run through pre userOp hook (pass) => validation (pass)
    function testPreUserOpHookAndValidationBothPass() public {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testPreUserOpHookAndValidationBothPass");
        address recipientAddr = vm.addr(1);
        _installValidationForMSCA(recipientAddr);

        // send eth
        // build userOp
        bytes memory executeCallData = abi.encodeCall(IModularAccount.execute, (recipientAddr, 1, ""));
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
        bytes memory executeCallData = abi.encodeCall(IModularAccount.execute, (recipientAddr, 1, ""));
        // pack the recipientAddr into hook data for check
        PreValidationHookData[] memory validationHookData = new PreValidationHookData[](1);
        validationHookData[0] = PreValidationHookData({index: 0, hookData: abi.encodePacked(recipientAddr)});
        // now encode the signature with hook function, validation function, global validation function flag
        bytes memory authorizationData = encodeSignature(validationHookData, ownerValidation, "", true);

        vm.startPrank(ownerAddr);
        msca.executeWithRuntimeValidation(executeCallData, authorizationData);
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
        bytes memory executeCallData = abi.encodeCall(IModularAccount.execute, (recipientAddr, 1, ""));
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca), 0, "0x", vm.toString(executeCallData), 83353, 1028650, 45484, 516219199704, 1130000000, "0x"
        );
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
        bytes memory executeCallData = abi.encodeCall(IModularAccount.execute, (recipientAddr, 1, ""));
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
        bytes memory executeCallData = abi.encodeCall(IModularAccount.execute, (recipientAddr, 1, ""));
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
                abi.encodeWithSignature("ValidationSignatureSegmentMissing()")
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
        bytes memory executeCallData = abi.encodeCall(IModularAccount.execute, (recipientAddr, 1, ""));
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
                abi.encodeWithSignature("ValidationSignatureSegmentMissing()")
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
        bytes memory executeCallData = abi.encodeCall(IModularAccount.execute, (recipientAddr, 1, ""));
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
                abi.encodeWithSignature("NonCanonicalEncoding()")
            )
        );
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
        // verify recipient balance
        assertEq(recipientAddr.balance, 0);
    }

    function testPreUserOpHookFail_excessData() public {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testPreUserOpHookFail_excessData");
        address recipientAddr = vm.addr(1);
        _installValidationForMSCA(recipientAddr);

        // send eth
        // build userOp
        bytes memory executeCallData = abi.encodeCall(IModularAccount.execute, (recipientAddr, 1, ""));
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca), 0, "0x", vm.toString(executeCallData), 83353, 1028650, 45484, 516219199704, 1130000000, "0x"
        );
        // signature is the data for ownerValidation
        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);

        PreValidationHookData[] memory validationHookData = new PreValidationHookData[](1);
        validationHookData[0] = PreValidationHookData({index: 0, hookData: abi.encodePacked(recipientAddr)});
        // now encode the signature with hook function, validation function, global validation function flag
        userOp.signature =
            abi.encodePacked(encodeSignature(validationHookData, ownerValidation, signature, true), "excess data");
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
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
        bytes memory executeCallData = abi.encodeCall(IModularAccount.execute, (recipientAddr, 1, ""));
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
                address(addressBookModule),
                uint32(TestAddressBookModule.EntityId.PRE_VALIDATION_HOOK_EXECUTE_ADDRESS_BOOK),
                abi.encodeWithSignature("UnauthorizedRecipient(address,address)", address(ownerAddr), randomRecipient)
            )
        );
        msca.executeWithRuntimeValidation(executeCallData, authorizationData);
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
        bytes memory executeCallData = abi.encodeCall(IModularAccount.execute, (recipientAddr, 1, ""));
        // do not pack any hook data for check, would fail
        PreValidationHookData[] memory validationHookData = new PreValidationHookData[](0);
        // now encode the signature with hook function, validation function, global validation function flag
        bytes memory authorizationData = encodeSignature(validationHookData, ownerValidation, "", true);

        vm.startPrank(ownerAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                PreRuntimeValidationHookFailed.selector,
                address(addressBookModule),
                uint32(TestAddressBookModule.EntityId.PRE_VALIDATION_HOOK_EXECUTE_ADDRESS_BOOK),
                abi.encodeWithSignature("UnauthorizedRecipient(address,address)", address(ownerAddr), address(0))
            )
        );
        msca.executeWithRuntimeValidation(executeCallData, authorizationData);
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
        bytes memory executeCallData = abi.encodeCall(IModularAccount.execute, (recipientAddr, 1, ""));
        // pack more hook data than installed for check, would fail on validation function boundary check
        PreValidationHookData[] memory validationHookData = new PreValidationHookData[](2);
        validationHookData[0] = PreValidationHookData({index: 0, hookData: abi.encodePacked(recipientAddr)});
        validationHookData[1] = PreValidationHookData({index: 1, hookData: abi.encodePacked(recipientAddr)});
        // now encode the signature with hook function, validation function, global validation function flag
        bytes memory authorizationData = encodeSignature(validationHookData, ownerValidation, "", true);

        vm.startPrank(ownerAddr);
        vm.expectRevert(abi.encodeWithSignature("ValidationSignatureSegmentMissing()"));
        msca.executeWithRuntimeValidation(executeCallData, authorizationData);
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
        bytes memory executeCallData = abi.encodeCall(IModularAccount.execute, (recipientAddr, 1, ""));
        // pack out of order hook data for check, would fail on out of order check
        PreValidationHookData[] memory validationHookData = new PreValidationHookData[](2);
        validationHookData[0] = PreValidationHookData({index: 0, hookData: abi.encodePacked(recipientAddr)});
        // supposed to be 1, but we set to 0 to trigger OOO
        validationHookData[1] = PreValidationHookData({index: 0, hookData: abi.encodePacked(recipientAddr)});
        // now encode the signature with hook function, validation function, global validation function flag
        bytes memory authorizationData = encodeSignature(validationHookData, ownerValidation, "", true);

        vm.startPrank(ownerAddr);
        vm.expectRevert(abi.encodeWithSignature("ValidationSignatureSegmentMissing()"));
        msca.executeWithRuntimeValidation(executeCallData, authorizationData);
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
        bytes memory executeCallData = abi.encodeCall(IModularAccount.execute, (recipientAddr, 1, ""));
        // pack "" into hook data for check
        PreValidationHookData[] memory validationHookData = new PreValidationHookData[](1);
        // empty hook data
        validationHookData[0] = PreValidationHookData({index: 0, hookData: ""});
        // now encode the signature with hook function, validation function, global validation function flag
        bytes memory authorizationData = encodeSignature(validationHookData, ownerValidation, "", true);

        vm.startPrank(ownerAddr);
        vm.expectRevert(abi.encodeWithSignature("NonCanonicalEncoding()"));
        msca.executeWithRuntimeValidation(executeCallData, authorizationData);
        vm.stopPrank();
        // verify recipient balance
        assertEq(recipientAddr.balance, 0);
    }

    function _installValidationForMSCA(address recipientAddr) internal {
        address[] memory recipients = new address[](1);
        recipients[0] = recipientAddr;
        // onInstall
        bytes[] memory hooks = new bytes[](1);
        hooks[0] = abi.encodePacked(
            HookConfigLib.packValidationHook({
                _hookFunction: ModuleEntityLib.pack(
                    address(addressBookModule),
                    uint32(TestAddressBookModule.EntityId.PRE_VALIDATION_HOOK_EXECUTE_ADDRESS_BOOK)
                )
            }),
            abi.encode(recipients)
        );

        vm.startPrank(address(msca));
        // ownerValidation is global
        msca.installValidation(
            ValidationConfigLib.pack(ownerValidation, true, true, true),
            new bytes4[](0),
            abi.encode(uint32(0), ownerAddr),
            hooks
        );
        vm.stopPrank();
        vm.deal(address(msca), 1 ether);
    }
}
