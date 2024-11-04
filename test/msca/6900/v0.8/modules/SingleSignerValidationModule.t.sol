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
import {BaseMSCA} from "../../../../../src/msca/6900/v0.8/account/BaseMSCA.sol";

import {
    ExecutionDataView, ValidationDataView
} from "@erc6900/reference-implementation/interfaces/IModularAccountView.sol";

import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {ModuleEntity, ValidationConfig} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";

import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";

import {SingleSignerValidationModule} from
    "../../../../../src/msca/6900/v0.8/modules/validation/SingleSignerValidationModule.sol";
import {TestLiquidityPool} from "../../../../util/TestLiquidityPool.sol";
import {AccountTestUtils} from "../utils/AccountTestUtils.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

import {UpgradableMSCA} from "../../../../../src/msca/6900/v0.8/account/UpgradableMSCA.sol";
import {UpgradableMSCAFactory} from "../../../../../src/msca/6900/v0.8/factories/UpgradableMSCAFactory.sol";

import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {console} from "forge-std/src/console.sol";

contract SingleSignerValidationModuleTest is AccountTestUtils {
    using ModuleEntityLib for bytes21;
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

    error FailedOpWithRevert(uint256 opIndex, string reason, bytes inner);

    IEntryPoint private entryPoint = new EntryPoint();
    uint256 internal eoaPrivateKey1;
    uint256 internal eoaPrivateKey2;
    address private signerAddr1;
    address private signerAddr2;
    address payable private beneficiary; // e.g. bundler
    UpgradableMSCAFactory private factory;
    SingleSignerValidationModule private singleSignerValidationModule;
    UpgradableMSCA private msca1;
    UpgradableMSCA private msca2;
    TestLiquidityPool private testLiquidityPool;
    address private singleSignerValidationModuleAddr;
    address private mscaAddr1;
    address private mscaAddr2;
    address private factorySigner;
    ModuleEntity private signerValidation;

    function setUp() public {
        factorySigner = makeAddr("factorySigner");
        beneficiary = payable(address(makeAddr("bundler")));
        factory = new UpgradableMSCAFactory(factorySigner, address(entryPoint));
        singleSignerValidationModule = new SingleSignerValidationModule();

        address[] memory _modules = new address[](1);
        _modules[0] = address(singleSignerValidationModule);
        bool[] memory _permissions = new bool[](1);
        _permissions[0] = true;
        vm.startPrank(factorySigner);
        factory.setModules(_modules, _permissions);
        vm.stopPrank();

        signerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint8(0));
        (signerAddr1, eoaPrivateKey1) = makeAddrAndKey("Circle_Single_Signer_Validation_Module_V1_Test1");
        (signerAddr2, eoaPrivateKey2) = makeAddrAndKey("Circle_Single_Signer_Validation_Module_V1_Test2");
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        signerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint8(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(signerValidation, true, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint8(0), signerAddr1), bytes(""), bytes(""));
        vm.startPrank(signerAddr1);
        msca1 = factory.createAccountWithValidation(addressToBytes32(signerAddr1), salt, initializingData);
        vm.stopPrank();
        vm.startPrank(signerAddr2);
        initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint8(0), signerAddr2), bytes(""), bytes(""));
        msca2 = factory.createAccountWithValidation(addressToBytes32(signerAddr2), salt, initializingData);
        vm.stopPrank();
        console.logString("Circle_Single_Signer_Validation_Module_V1 address:");
        console.logAddress(address(singleSignerValidationModule));
        singleSignerValidationModuleAddr = address(singleSignerValidationModule);
        mscaAddr1 = address(msca1);
        mscaAddr2 = address(msca2);
        testLiquidityPool = new TestLiquidityPool("getrich", "$$$");
    }

    /// SingleSignerValidationModule is installed in setUp function, this test is just verifying details
    function testSingleSignerValidationModuleDetailsInstalledDuringAccountDeployment() public view {
        address sender = address(msca1);
        // deployment was done in setUp
        assertTrue(sender.code.length != 0);
        // verify the module has been installed
        ValidationDataView memory validationData = msca1.getValidationData(signerValidation);
        assertEq(validationData.selectors.length, 0);
        assertEq(validationData.validationHooks.length, 0);
        assertEq(validationData.executionHooks.length, 0);
        assertEq(validationData.isGlobal, true);
        assertEq(validationData.isSignatureValidation, true);
        // verify executionDetail
        ExecutionDataView memory executionData =
            msca1.getExecutionData(singleSignerValidationModule.transferSigner.selector);
        assertEq(executionData.module, address(0));
        assertEq(executionData.skipRuntimeValidation, false);
        assertEq(executionData.allowGlobalValidation, false);
        assertEq(executionData.executionHooks.length, 0);

        // execute function
        executionData = msca1.getExecutionData(IModularAccount.execute.selector);
        assertEq(executionData.module, address(msca1));
        assertEq(executionData.skipRuntimeValidation, false);
        assertEq(executionData.allowGlobalValidation, true);
        assertEq(executionData.executionHooks.length, 0);

        // executeBatch function
        executionData = msca1.getExecutionData(IModularAccount.executeBatch.selector);
        assertEq(executionData.module, address(msca1));
        assertEq(executionData.skipRuntimeValidation, false);
        assertEq(executionData.allowGlobalValidation, true);
        assertEq(executionData.executionHooks.length, 0);

        // installExecution function
        executionData = msca1.getExecutionData(IModularAccount.installExecution.selector);
        assertEq(executionData.module, address(msca1));
        assertEq(executionData.skipRuntimeValidation, false);
        assertEq(executionData.allowGlobalValidation, true);
        assertEq(executionData.executionHooks.length, 0);

        // uninstallExecution function
        executionData = msca1.getExecutionData(IModularAccount.uninstallExecution.selector);
        assertEq(executionData.module, address(msca1));
        assertEq(executionData.skipRuntimeValidation, false);
        assertEq(executionData.allowGlobalValidation, true);
        assertEq(executionData.executionHooks.length, 0);

        // upgradeToAndCall function
        executionData = msca1.getExecutionData(UUPSUpgradeable.upgradeToAndCall.selector);
        assertEq(executionData.module, address(msca1));
        assertEq(executionData.skipRuntimeValidation, false);
        assertEq(executionData.allowGlobalValidation, true);
        assertEq(executionData.executionHooks.length, 0);
    }

    /// fail because transferSigner was not installed in validation module
    function testTransferSigner() public {
        address sender = address(msca1);
        // it should start with the deployed signerAddr
        assertEq(singleSignerValidationModule.signers(uint8(0), mscaAddr1), signerAddr1);
        // could be any address, I'm using UpgradableMSCA for simplicity
        UpgradableMSCA newSigner = new UpgradableMSCA(entryPoint);
        // deployment was done in setUp
        assertTrue(sender.code.length != 0);
        // nonce key is 0
        uint256 acctNonce = entryPoint.getNonce(sender, 0);
        // start with balance
        vm.deal(sender, 10 ether);
        bytes memory transferSignerCallData =
            abi.encodeCall(singleSignerValidationModule.transferSigner, (uint8(0), address(newSigner)));
        bytes memory initCode = "";
        PackedUserOperation memory userOp = buildPartialUserOp(
            sender,
            acctNonce,
            vm.toString(initCode),
            vm.toString(transferSignerCallData),
            10053353,
            103353,
            45484,
            516219199704,
            1130000000,
            "0x"
        ); // no paymaster

        // eoaPrivateKey from singleSignerValidationModule
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey1, userOp);
        userOp.signature = encodeSignature(new PreValidationHookData[](0), signerValidation, signature, false);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(
                    BaseMSCA.InvalidValidationFunction.selector,
                    singleSignerValidationModule.transferSigner.selector,
                    signerValidation
                )
            )
        );
        entryPoint.handleOps(ops, beneficiary);
        // won't change
        assertEq(singleSignerValidationModule.signers(uint8(0), mscaAddr1), address(signerAddr1));
        vm.stopPrank();
    }

    /// we need to handle guarded functions like transferSigner through the execute/executeBatch workflows
    function testTransferSignerViaExecuteFunction() public {
        address sender = address(msca2);
        // it should start with the deployed signerAddr
        assertEq(singleSignerValidationModule.signers(uint8(0), mscaAddr2), signerAddr2);
        // could be any address, I'm using UpgradableMSCA for simplicity
        UpgradableMSCA newSigner = new UpgradableMSCA(entryPoint);
        // deployment was done in setUp
        assertTrue(sender.code.length != 0);
        // nonce key is 0
        uint256 acctNonce = entryPoint.getNonce(sender, 0);
        // start with balance
        vm.deal(sender, 10 ether);
        bytes memory transferSignerCallData =
            abi.encodeCall(singleSignerValidationModule.transferSigner, (uint8(0), address(newSigner)));
        bytes memory executeCallData =
            abi.encodeCall(IModularAccount.execute, (address(singleSignerValidationModule), 0, transferSignerCallData));
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
        // eoaPrivateKey from singleSignerValidationModule
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey2, userOp);
        userOp.signature = encodeSignature(new PreValidationHookData[](0), signerValidation, signature, true);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        emit UserOperationEvent(userOpHash, sender, address(0), acctNonce, true, 179020250000000, 158425);
        entryPoint.handleOps(ops, beneficiary);
        // now it's the new signer
        assertEq(singleSignerValidationModule.signers(uint8(0), mscaAddr2), address(newSigner));
        vm.stopPrank();
    }
}
