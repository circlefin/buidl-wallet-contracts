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
import {DIRECT_CALL_VALIDATION_ENTITY_ID} from "@erc6900/reference-implementation/helpers/Constants.sol";
import {ExecutionManifest} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {ModuleEntity, ValidationConfig} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";

import {SingleSignerValidationModule} from
    "../../../../src/msca/6900/v0.8/modules/validation/SingleSignerValidationModule.sol";
import {TestLiquidityPool} from "../../../util/TestLiquidityPool.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";

import {TestTokenModule} from "./TestTokenModule.sol";
import {AccountTestUtils} from "./utils/AccountTestUtils.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";

import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

import {UpgradableMSCA} from "../../../../src/msca/6900/v0.8/account/UpgradableMSCA.sol";
import {UpgradableMSCAFactory} from "../../../../src/msca/6900/v0.8/factories/UpgradableMSCAFactory.sol";

import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {
    ExecutionDataView, ValidationDataView
} from "@erc6900/reference-implementation/interfaces/IModularAccountView.sol";

import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {console} from "forge-std/src/console.sol";

/// Tests for install/uninstall
contract ModuleManagementTest is AccountTestUtils {
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
    uint256 internal eoaPrivateKey;
    address private ownerAddr;
    address payable private beneficiary; // e.g. bundler
    UpgradableMSCAFactory private factory;
    SingleSignerValidationModule private singleSignerValidationModule;
    UpgradableMSCA private msca;
    TestTokenModule private testTokenModule;
    address private mscaAddr;
    address private factoryOwner;
    ModuleEntity private ownerValidation;

    function setUp() public {
        factoryOwner = makeAddr("factoryOwner");
        beneficiary = payable(address(makeAddr("bundler")));
        factory = new UpgradableMSCAFactory(factoryOwner, address(entryPoint));
        singleSignerValidationModule = new SingleSignerValidationModule();

        address[] memory _modules = new address[](1);
        _modules[0] = address(singleSignerValidationModule);
        bool[] memory _permissions = new bool[](1);
        _permissions[0] = true;
        vm.startPrank(factoryOwner);
        factory.setModules(_modules, _permissions);
        vm.stopPrank();

        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("ModuleManagerTest");
        vm.startPrank(ownerAddr);
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), bytes(""), bytes(""));
        msca = factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        console.logString("msca address:");
        console.logAddress(address(msca));
        console.logString("single owner module address:");
        console.logAddress(address(singleSignerValidationModule));
        console.logString("owner address:");
        console.logAddress(ownerAddr);
        mscaAddr = address(msca);
        testTokenModule = new TestTokenModule();
        vm.stopPrank();
    }

    /// try to install a random smart contract that doesn't implement the module interface
    /// try to install it from owner and non-owner separately
    function testInstallSCButNotModule() public {
        // try to install testLiquidityPool, which is not a module
        TestLiquidityPool testLiquidityPool = new TestLiquidityPool("bad", "bad");
        // install from an authenticated owner
        vm.startPrank(address(entryPoint));
        bytes4 errorSelector = BaseMSCA.InterfaceNotSupported.selector;
        vm.expectRevert(abi.encodeWithSelector(errorSelector, address(testLiquidityPool), type(IModule).interfaceId));
        ExecutionManifest memory executionManifest;
        // TODO: test again with empty install data
        msca.installExecution(address(testLiquidityPool), executionManifest, abi.encode("bad"));
        vm.stopPrank();

        // install from a random address, should be rejected
        // UnauthorizedCaller is caught by the caller and converted to RuntimeValidationFailed
        vm.startPrank(address(1));
        vm.expectRevert(
            abi.encodeWithSelector(
                BaseMSCA.InvalidValidationFunction.selector,
                IModularAccount.installExecution.selector,
                ModuleEntityLib.pack(address(1), DIRECT_CALL_VALIDATION_ENTITY_ID)
            )
        );
        msca.installExecution(address(testLiquidityPool), executionManifest, "");
        vm.stopPrank();
    }

    /// try to install and uninstall a new module via user op after single owner module has been installed as part of
    /// account deployment
    function testInstallAndUninstallTestModuleWithValidationAndHooks() public {
        // deployment was done in setUp
        assertTrue(address(msca).code.length != 0);
        // start with balance
        vm.deal(address(msca), 10 ether);
        bytes memory installModuleCallData = abi.encodeCall(
            IModularAccount.installExecution,
            (address(testTokenModule), testTokenModule.executionManifest(), abi.encode(1000))
        );
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca), 0, "0x", vm.toString(installModuleCallData), 1000000, 1000000, 0, 1, 1, "0x"
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
        bytes[] memory hooks = new bytes[](2);
        hooks[0] = abi.encodePacked(
            HookConfigLib.packValidationHook({
                _hookFunction: ModuleEntityLib.pack(
                    address(testTokenModule), uint32(TestTokenModule.EntityId.PRE_VALIDATION_HOOK_PASS1)
                )
            }),
            ""
        );
        hooks[1] = abi.encodePacked(
            HookConfigLib.packValidationHook({
                _hookFunction: ModuleEntityLib.pack(
                    address(testTokenModule), uint32(TestTokenModule.EntityId.PRE_VALIDATION_HOOK_PASS2)
                )
            }),
            ""
        );

        bytes memory installHooksCalldata = abi.encodeCall(
            IModularAccount.installValidation,
            (ValidationConfigLib.pack(ownerValidation, true, true, true), new bytes4[](0), bytes(""), hooks)
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

        // verify airdrop amount initiated during installation
        assertEq(testTokenModule.balanceOf(mscaAddr), 1000);

        // verify the module has been installed
        ValidationDataView memory validationData = msca.getValidationData(ownerValidation);
        assertEq(validationData.validationHooks.length, 2);
        vm.stopPrank();

        //
        // TODO: we currently don't have a good way of uninstalling hook function only
        // 6900 team is looking into this
        //
        // uninstall via another userOp
        // we'll just use module manifest
        UpgradableMSCA anotherMSCA = new UpgradableMSCA(entryPoint);
        bytes memory moduleUninstallData = abi.encode(address(anotherMSCA), 999);
        bytes memory uninstallModuleCalldata = abi.encodeCall(
            IModularAccount.uninstallExecution,
            (address(testTokenModule), testTokenModule.executionManifest(), moduleUninstallData)
        );
        userOp = buildPartialUserOp(
            address(msca),
            2,
            "0x",
            vm.toString(uninstallModuleCalldata),
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
            abi.encodeCall(IModularAccount.uninstallValidation, (ownerValidation, bytes(""), new bytes[](0)));
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

        // verify executionDetails
        // the module requested to install transferToken and balanceOf
        validationData = msca.getValidationData(ownerValidation);
        assertEq(validationData.validationHooks.length, 2);
        ExecutionDataView memory executionData = msca.getExecutionData(testTokenModule.transferToken.selector);
        assertEq(executionData.executionHooks.length, 0);
        assertEq(executionData.module, address(0));
        // balanceOf
        executionData = msca.getExecutionData(testTokenModule.balanceOf.selector);
        assertEq(executionData.executionHooks.length, 0);
        assertEq(executionData.module, address(0));
        // verify the amount has been destroyed
        assertEq(testTokenModule.balanceOf(mscaAddr), 0);
        assertEq(testTokenModule.balanceOf(address(anotherMSCA)), 999);
        vm.stopPrank();
    }
}
