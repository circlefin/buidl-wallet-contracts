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

import {BaseMSCA} from "../../../../src/msca/6900/v0.8/account/BaseMSCA.sol";
import {Call} from "../../../../src/msca/6900/v0.8/common/Structs.sol";
import {ModuleEntity, ValidationConfig} from "../../../../src/msca/6900/v0.8/common/Types.sol";
import {IAccountExecute} from "../../../../src/msca/6900/v0.8/interfaces/IAccountExecute.sol";
import {IStandardExecutor} from "../../../../src/msca/6900/v0.8/interfaces/IStandardExecutor.sol";
import {ModuleEntityLib} from "../../../../src/msca/6900/v0.8/libs/thirdparty/ModuleEntityLib.sol";
import {ValidationConfigLib} from "../../../../src/msca/6900/v0.8/libs/thirdparty/ValidationConfigLib.sol";
import {PluginManager} from "../../../../src/msca/6900/v0.8/managers/PluginManager.sol";
import {SingleSignerValidationModule} from
    "../../../../src/msca/6900/v0.8/plugins/v1_0_0/validation/SingleSignerValidationModule.sol";
import {FooBarPlugin} from "./FooBarPlugin.sol";

import {TestCircleMSCA} from "./TestCircleMSCA.sol";
import {TestCircleMSCAFactory} from "./TestCircleMSCAFactory.sol";
import {AccountTestUtils} from "./utils/AccountTestUtils.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract SelfCallRuleTest is AccountTestUtils {
    using ModuleEntityLib for ModuleEntity;

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
    SingleSignerValidationModule private singleSignerValidationModule;
    FooBarPlugin private fooBarPlugin;
    address private factoryOwner;
    TestCircleMSCAFactory private factory;
    TestCircleMSCA private msca;
    uint256 internal ownerPrivateKey;
    address private ownerAddr;
    bytes private initializingData;
    bytes32 private salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
    ModuleEntity private ownerValidation;
    address payable private beneficiary; // e.g. bundler

    function setUp() public {
        factoryOwner = makeAddr("factoryOwner");
        beneficiary = payable(address(makeAddr("bundler")));
        singleSignerValidationModule = new SingleSignerValidationModule();
        fooBarPlugin = new FooBarPlugin();
        factory = new TestCircleMSCAFactory(factoryOwner, entryPoint, pluginManager);

        address[] memory plugins = new address[](2);
        plugins[0] = address(singleSignerValidationModule);
        plugins[1] = address(fooBarPlugin);
        bool[] memory permissions = new bool[](2);
        permissions[0] = true;
        permissions[1] = true;
        vm.startPrank(factoryOwner);
        factory.setPlugins(plugins, permissions);
        vm.stopPrank();
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
    }

    // all fail because the outer selector is not allowed by the validation function
    // 1. direct call bar()
    // 2. executeUserOp(bar())
    // 3. execute(bar())
    // 4. executeBatch(bar())
    function testSelfCallViaUserOp_globalValidation() public {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testSelfCallViaUserOp_globalValidation");
        _installValidationAndExecutionForMSCA();
        vm.deal(address(msca), 10 ether);
        // bar doesn't allow global validation
        bytes memory userOpCallData = abi.encodeCall(FooBarPlugin.bar, ());
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca), 0, "0x", vm.toString(userOpCallData), 83353, 1028650, 45484, 516219199704, 1130000000, "0x"
        );
        // signature is the data for ownerValidation
        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        PreValidationHookData[] memory validationHookData = new PreValidationHookData[](0);
        // global validation function
        userOp.signature = encodeSignature(validationHookData, ownerValidation, signature, true);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(
                    BaseMSCA.UserOpValidationFunctionMissing.selector, fooBarPlugin.bar.selector, ownerValidation
                )
            )
        );
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();

        // via executeUserOp
        // actual selector will be extracted
        userOpCallData = abi.encodePacked(IAccountExecute.executeUserOp.selector, abi.encodeCall(FooBarPlugin.bar, ()));
        userOp = buildPartialUserOp(
            address(msca), 1, "0x", vm.toString(userOpCallData), 83353, 1028650, 45484, 516219199704, 1130000000, "0x"
        );
        // signature is the data for ownerValidation
        signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        // global validation function
        userOp.signature = encodeSignature(validationHookData, ownerValidation, signature, true);
        ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(
                    BaseMSCA.UserOpValidationFunctionMissing.selector,
                    IAccountExecute.executeUserOp.selector,
                    ownerValidation
                )
            )
        );
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();

        // via execute
        userOpCallData =
            abi.encodeCall(IStandardExecutor.execute, (address(msca), 0, abi.encodeCall(FooBarPlugin.bar, ())));
        userOp = buildPartialUserOp(
            address(msca), 2, "0x", vm.toString(userOpCallData), 83353, 1028650, 45484, 516219199704, 1130000000, "0x"
        );
        // signature is the data for ownerValidation
        signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        // global validation function
        userOp.signature = encodeSignature(validationHookData, ownerValidation, signature, true);
        ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(
                    BaseMSCA.UserOpValidationFunctionMissing.selector,
                    IStandardExecutor.execute.selector,
                    ownerValidation
                )
            )
        );
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();

        // via executeBatch
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(msca), 0, abi.encodeCall(FooBarPlugin.bar, ()));
        userOpCallData = abi.encodeCall(IStandardExecutor.executeBatch, calls);
        userOp = buildPartialUserOp(
            address(msca), 3, "0x", vm.toString(userOpCallData), 83353, 1028650, 45484, 516219199704, 1130000000, "0x"
        );
        // signature is the data for ownerValidation
        signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        // global validation function
        userOp.signature = encodeSignature(validationHookData, ownerValidation, signature, true);
        ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(
                    BaseMSCA.UserOpValidationFunctionMissing.selector,
                    IStandardExecutor.executeBatch.selector,
                    ownerValidation
                )
            )
        );
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
    }

    // use a customized validation to bypass the selector-validation check so it would not fail too early
    // 1. direct call bar()
    // 2. executeUserOp(bar())
    // 3. execute(bar())
    // 4. executeBatch(bar())
    function testSelfCallViaUserOp_perSelectorValidation() public {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testSelfCallViaUserOp_perSelectorValidation");
        _installValidationAndExecutionForMSCA();
        // start with balance
        vm.deal(address(msca), 10 ether);
        // install a customized validation that enables validation for selectors
        vm.startPrank(address(msca));
        ModuleEntity barValidation =
            ModuleEntityLib.pack({addr: address(fooBarPlugin), entityId: uint32(FooBarPlugin.EntityId.VALIDATION)});
        bytes4[] memory selectors = new bytes4[](4);
        selectors[0] = FooBarPlugin.bar.selector;
        selectors[1] = IAccountExecute.executeUserOp.selector;
        selectors[2] = IStandardExecutor.execute.selector;
        selectors[3] = IStandardExecutor.executeBatch.selector;
        msca.installValidation(
            ValidationConfigLib.pack(barValidation, false, false), selectors, bytes(""), bytes(""), bytes("")
        );
        vm.stopPrank();

        // direct call would work due to per selector validation and not self-call
        bytes memory userOpCallData = abi.encodeCall(FooBarPlugin.bar, ());
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca), 0, "0x", vm.toString(userOpCallData), 83353, 1028650, 45484, 516219199704, 1130000000, "0x"
        );
        PreValidationHookData[] memory validationHookData = new PreValidationHookData[](0);
        userOp.signature = encodeSignature(validationHookData, barValidation, "", false);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        emit UserOperationEvent(
            entryPoint.getUserOpHash(userOp), address(msca), address(0), 0, true, 287692350000000, 254595
        );
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();

        // via executeUserOp, not self call
        userOpCallData = abi.encodePacked(IAccountExecute.executeUserOp.selector, abi.encodeCall(FooBarPlugin.bar, ()));
        userOp = buildPartialUserOp(
            address(msca), 1, "0x", vm.toString(userOpCallData), 83353, 1028650, 45484, 516219199704, 1130000000, "0x"
        );

        userOp.signature = encodeSignature(validationHookData, barValidation, "", false);
        ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        emit UserOperationEvent(
            entryPoint.getUserOpHash(userOp), address(msca), address(0), 1, true, 287692350000000, 254595
        );
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();

        // via execute, self call
        userOpCallData =
            abi.encodeCall(IStandardExecutor.execute, (address(msca), 0, abi.encodeCall(FooBarPlugin.bar, ())));
        userOp = buildPartialUserOp(
            address(msca), 2, "0x", vm.toString(userOpCallData), 83353, 1028650, 45484, 516219199704, 1130000000, "0x"
        );

        userOp.signature = encodeSignature(validationHookData, barValidation, "", false);
        ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(bytes4(keccak256("SelfCallRecursionDepthExceeded()")))
            )
        );
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();

        // via executeBatch, non self call
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(msca), 0, abi.encodeCall(FooBarPlugin.bar, ()));
        userOpCallData = abi.encodeCall(IStandardExecutor.executeBatch, calls);
        userOp = buildPartialUserOp(
            address(msca),
            entryPoint.getNonce(address(msca), 0),
            "0x",
            vm.toString(userOpCallData),
            83353,
            1028650,
            45484,
            516219199704,
            1130000000,
            "0x"
        );
        userOp.signature = encodeSignature(validationHookData, barValidation, "", false);
        ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        emit UserOperationEvent(
            entryPoint.getUserOpHash(userOp), address(msca), address(0), 1, true, 287692350000000, 254595
        );
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
    }

    // use a customized validation to bypass the selector-validation check so it would not fail too early
    // 1. executeUserOp(execute(bar()))
    // 2. executeUserOp(executeBatch(bar()))
    // 3. executeUserOp(executeBatch(execute(bar())))
    function testRecursiveCallWrappingInExecuteUserOp() public {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testRecursiveCallWrappingInExecuteUserOp");
        _installValidationAndExecutionForMSCA();
        // start with balance
        vm.deal(address(msca), 10 ether);
        // install a customized validation that enables validation for selector
        vm.startPrank(address(msca));
        ModuleEntity barValidation =
            ModuleEntityLib.pack({addr: address(fooBarPlugin), entityId: uint32(FooBarPlugin.EntityId.VALIDATION)});
        bytes4[] memory selectors = new bytes4[](3);
        selectors[0] = IStandardExecutor.execute.selector;
        selectors[1] = IStandardExecutor.executeBatch.selector;
        selectors[2] = FooBarPlugin.bar.selector;
        msca.installValidation(
            ValidationConfigLib.pack(barValidation, false, false), selectors, bytes(""), bytes(""), bytes("")
        );
        vm.stopPrank();

        // executeUserOp(execute(bar()))
        bytes memory userOpCallData =
            abi.encodeCall(IStandardExecutor.execute, (address(msca), 0, abi.encodeCall(FooBarPlugin.bar, ())));
        userOpCallData = abi.encodePacked(IAccountExecute.executeUserOp.selector, userOpCallData);
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca), 0, "0x", vm.toString(userOpCallData), 83353, 1028650, 45484, 516219199704, 1130000000, "0x"
        );
        PreValidationHookData[] memory validationHookData = new PreValidationHookData[](0);
        userOp.signature = encodeSignature(validationHookData, barValidation, "", false);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(bytes4(keccak256("SelfCallRecursionDepthExceeded()")))
            )
        );
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();

        // executeUserOp(executeBatch(bar()))
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(msca), 0, abi.encodeCall(FooBarPlugin.bar, ()));
        userOpCallData = abi.encodeCall(IStandardExecutor.executeBatch, calls);
        userOpCallData = abi.encodePacked(IAccountExecute.executeUserOp.selector, userOpCallData);
        userOp = buildPartialUserOp(
            address(msca),
            entryPoint.getNonce(address(msca), 0),
            "0x",
            vm.toString(userOpCallData),
            83353,
            1028650,
            45484,
            516219199704,
            1130000000,
            "0x"
        );
        userOp.signature = encodeSignature(validationHookData, barValidation, "", false);
        ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        emit UserOperationEvent(
            entryPoint.getUserOpHash(userOp), address(msca), address(0), 2, true, 287692350000000, 254595
        );
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();

        // executeUserOp(executeBatch(execute(bar())))
        calls = new Call[](1);
        calls[0] = Call(
            address(msca),
            0,
            abi.encodeCall(IStandardExecutor.execute, (address(msca), 0, abi.encodeCall(FooBarPlugin.bar, ())))
        );
        userOpCallData = abi.encodeCall(IStandardExecutor.executeBatch, calls);
        userOpCallData = abi.encodePacked(IAccountExecute.executeUserOp.selector, userOpCallData);
        userOp = buildPartialUserOp(
            address(msca),
            entryPoint.getNonce(address(msca), 0),
            "0x",
            vm.toString(userOpCallData),
            83353,
            1028650,
            45484,
            516219199704,
            1130000000,
            "0x"
        );
        userOp.signature = encodeSignature(validationHookData, barValidation, "", false);
        ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(bytes4(keccak256("SelfCallRecursionDepthExceeded()")))
            )
        );
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
    }

    // all fail because the outer selector is not allowed by the validation function
    // 1. direct call bar()
    // 2. execute(bar())
    // 3. executeBatch(bar())
    function testSelfCallViaRuntime_globalValidation() public {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testSelfCallViaRuntime_globalValidation");
        _installValidationAndExecutionForMSCA();
        vm.deal(address(msca), 10 ether);
        // bar doesn't allow global validation
        bytes memory callData = abi.encodeCall(FooBarPlugin.bar, ());
        // signature is the data for ownerValidation
        PreValidationHookData[] memory validationHookData = new PreValidationHookData[](0);
        // global validation function
        bytes memory authorizationData = encodeSignature(validationHookData, ownerValidation, "", true);
        vm.startPrank(ownerAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                BaseMSCA.RuntimeValidationFunctionMissing.selector, FooBarPlugin.bar.selector, ownerValidation
            )
        );
        msca.executeWithAuthorization(callData, authorizationData);
        vm.stopPrank();

        // execute(bar())
        callData = abi.encodeCall(IStandardExecutor.execute, (address(msca), 0, abi.encodeCall(FooBarPlugin.bar, ())));
        // global validation function
        authorizationData = encodeSignature(validationHookData, ownerValidation, "", true);
        vm.startPrank(ownerAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                BaseMSCA.RuntimeValidationFunctionMissing.selector, IStandardExecutor.execute.selector, ownerValidation
            )
        );
        msca.executeWithAuthorization(callData, authorizationData);
        vm.stopPrank();

        // executeBatch(bar())
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(msca), 0, abi.encodeCall(FooBarPlugin.bar, ()));
        callData = abi.encodeCall(IStandardExecutor.executeBatch, calls);
        // global validation function
        authorizationData = encodeSignature(validationHookData, ownerValidation, "", true);
        vm.startPrank(ownerAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                BaseMSCA.RuntimeValidationFunctionMissing.selector,
                IStandardExecutor.executeBatch.selector,
                ownerValidation
            )
        );
        msca.executeWithAuthorization(callData, authorizationData);
        vm.stopPrank();
    }

    // use a customized validation to bypass the selector-validation check so it would not fail too early
    // 1. direct call bar()
    // 2. execute(bar())
    // 3. executeBatch(bar())
    // 4. executeBatch(execute(bar()))
    function testSelfCallViaRuntime_perSelectorValidation() public {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testSelfCallViaRuntime_perSelectorValidation");
        _installValidationAndExecutionForMSCA();
        vm.deal(address(msca), 10 ether);
        // install a customized validation that enables validation for selectors
        vm.startPrank(address(msca));
        ModuleEntity barValidation =
            ModuleEntityLib.pack({addr: address(fooBarPlugin), entityId: uint32(FooBarPlugin.EntityId.VALIDATION)});
        bytes4[] memory selectors = new bytes4[](3);
        selectors[0] = FooBarPlugin.bar.selector;
        selectors[1] = IStandardExecutor.execute.selector;
        selectors[2] = IStandardExecutor.executeBatch.selector;
        msca.installValidation(
            ValidationConfigLib.pack(barValidation, false, false), selectors, bytes(""), bytes(""), bytes("")
        );
        vm.stopPrank();

        bytes memory callData = abi.encodeCall(FooBarPlugin.bar, ());
        // signature is the data for ownerValidation
        PreValidationHookData[] memory validationHookData = new PreValidationHookData[](0);
        // customized validation function
        bytes memory authorizationData = encodeSignature(validationHookData, barValidation, "", false);
        vm.startPrank(ownerAddr);
        bytes memory result = msca.executeWithAuthorization(callData, authorizationData);
        assertEq(result, abi.encode(keccak256("bar")));
        vm.stopPrank();

        // execute(bar()), self call
        callData = abi.encodeCall(IStandardExecutor.execute, (address(msca), 0, abi.encodeCall(FooBarPlugin.bar, ())));
        // customized validation function
        authorizationData = encodeSignature(validationHookData, barValidation, "", false);
        vm.startPrank(ownerAddr);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("SelfCallRecursionDepthExceeded()"))));
        msca.executeWithAuthorization(callData, authorizationData);
        vm.stopPrank();

        // executeBatch(bar())
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(msca), 0, abi.encodeCall(FooBarPlugin.bar, ()));
        callData = abi.encodeCall(IStandardExecutor.executeBatch, calls);
        // customized validation function
        authorizationData = encodeSignature(validationHookData, barValidation, "", false);
        vm.startPrank(ownerAddr);
        result = msca.executeWithAuthorization(callData, authorizationData);
        bytes[] memory resultArr = abi.decode(result, (bytes[]));
        assertEq(resultArr[0], abi.encode(keccak256("bar")));
        vm.stopPrank();

        // executeBatch(execute(bar()))
        calls = new Call[](1);
        calls[0] = Call(
            address(msca),
            0,
            abi.encodeCall(IStandardExecutor.execute, (address(msca), 0, abi.encodeCall(FooBarPlugin.bar, ())))
        );
        callData = abi.encodeCall(IStandardExecutor.executeBatch, calls);
        // customized validation function
        authorizationData = encodeSignature(validationHookData, barValidation, "", false);
        vm.startPrank(ownerAddr);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("SelfCallRecursionDepthExceeded()"))));
        msca.executeWithAuthorization(callData, authorizationData);
        vm.stopPrank();
    }

    function _installValidationAndExecutionForMSCA() internal {
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, false, true);
        initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), bytes(""), bytes(""));
        msca = factory.createAccountWithValidation(ownerAddr, salt, initializingData);

        // install foo bar execution
        vm.startPrank(address(msca));
        msca.installPlugin(address(fooBarPlugin), bytes(""));
        vm.stopPrank();
    }
}
