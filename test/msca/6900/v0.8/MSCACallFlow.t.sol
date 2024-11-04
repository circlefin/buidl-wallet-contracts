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

import {DIRECT_CALL_VALIDATION_ENTITY_ID} from "@erc6900/reference-implementation/helpers/Constants.sol";
import {
    ExecutionManifest, ManifestExecutionHook
} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {ModuleEntity, ValidationConfig} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {UpgradableMSCA} from "../../../../src/msca/6900/v0.8/account/UpgradableMSCA.sol";
import {UpgradableMSCAFactory} from "../../../../src/msca/6900/v0.8/factories/UpgradableMSCAFactory.sol";
import {SingleSignerValidationModule} from
    "../../../../src/msca/6900/v0.8/modules/validation/SingleSignerValidationModule.sol";
import {MSCACallFlowModule} from "./helpers/MSCACallFlowModule.sol";
import {AccountTestUtils} from "./utils/AccountTestUtils.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

// @notice Inspired by Alchemy's implementation with modifications.
// For MSCA call flow, please refer to
// https://github.com/erc6900/reference-implementation/blob/6cdcfa653eb019d27d23586a86ff8171201a4066/standard/assets/eip-6900/Modular_Account_Call_Flow.svg.
// This test asserts that all hooks, validation function, module functions and account functions are executed in the
// correct order:
// 1. All validation hooks (in forward order)
// 2. The validation function
// 3. All pre-exec hooks associated with validation (in forward order)
// 4. All pre-exec hooks associated with selector (in forward order)
// 5. The account / module exec function
// 6. All post-exec hooks associated with selector (in reverse order)
// 7. All post-exec hooks associated with validation (in reverse order)
//
// To do this, it installs a special module called HookOrderCheckerModule that is a module of every type, and each
// implementation reports it's order (from it's entityId) to a storage list. At the end of each execution flow, the
// list is asserted to be of the right length and contain the elements in the correct order.
//
// This test does not assert hook ordering after the removal of any hooks, or the addition of hooks after the first
// install. That case will need an invariant test + harness to handle the addition and removal of hooks.
contract MSCACallFlowTest is AccountTestUtils {
    IEntryPoint private entryPoint = new EntryPoint();
    uint256 internal ownerPrivateKey;
    address private ownerAddr;
    address payable private beneficiary; // e.g. bundler
    UpgradableMSCAFactory private factory;
    address private factoryOwner;
    SingleSignerValidationModule private singleSignerValidationModule;
    ModuleEntity private ownerValidationEntity;
    bytes32 private salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
    UpgradableMSCA private msca;
    MSCACallFlowModule public mscaCallFlowModule;
    ModuleEntity public mscaCallFlowValidationEntity;

    function setUp() public {
        factoryOwner = makeAddr("factoryOwner");
        beneficiary = payable(address(makeAddr("bundler")));
        factory = new UpgradableMSCAFactory(factoryOwner, address(entryPoint));
        singleSignerValidationModule = new SingleSignerValidationModule();
        address[] memory modules = new address[](1);
        modules[0] = address(singleSignerValidationModule);
        bool[] memory _permissions = new bool[](1);
        _permissions[0] = true;
        vm.startPrank(factoryOwner);
        factory.setModules(modules, _permissions);
        vm.stopPrank();
        ownerValidationEntity = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidationEntity, false, true, false);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), new bytes[](0));
        msca = factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        vm.deal(address(msca), 2 ether);
        mscaCallFlowModule = new MSCACallFlowModule();
    }

    // userOp: module exec function with validation associated exec hooks and selector associated exec hooks
    function testModuleFuncWithAllHooksViaUserOp() public {
        _installOrderCheckerModule(4);
        bytes memory executeCallData =
            abi.encodePacked(msca.executeUserOp.selector, abi.encodeCall(MSCACallFlowModule.foo, (17)));
        PackedUserOperation memory userOp =
            buildPartialUserOp(address(msca), 0, "0x", vm.toString(executeCallData), 1000000, 1000000, 0, 1, 1, "0x");
        // PER_SELECTOR_VALIDATION_FLAG
        userOp.signature = encodeSignature(new PreValidationHookData[](0), mscaCallFlowValidationEntity, "0x", false);
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;
        entryPoint.handleOps(userOps, beneficiary);

        _checkInvokeOrderWithBothValidationAndSelectorAssocExecHooks();
    }

    // userOp: module exec function, with only selector associated exec hooks, without validation-associated exec hooks
    function testModuleFuncWithOnlySelectorExecHooksViaUserOp() public {
        _installOrderCheckerModuleWithOnlySelectorExecHooks(4);
        bytes memory executeCallData = abi.encodeCall(MSCACallFlowModule.foo, (17));
        PackedUserOperation memory userOp =
            buildPartialUserOp(address(msca), 0, "0x", vm.toString(executeCallData), 1000000, 1000000, 0, 1, 1, "0x");
        // PER_SELECTOR_VALIDATION_FLAG
        userOp.signature = encodeSignature(new PreValidationHookData[](0), mscaCallFlowValidationEntity, "0x", false);
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;
        entryPoint.handleOps(userOps, beneficiary);

        _checkInvokeOrderWithOnlySelectorAssocExecHooks();
    }

    // User op: module exec function, with only selector associated exec hooks, without validation-associated exec
    // hooks, yes executeUserOp
    // Call order is the same the test without executeUserOp
    function testModuleFuncWithOnlySelectorExecHooksViaExecuteUserOp() public {
        _installOrderCheckerModuleWithOnlySelectorExecHooks(4);
        bytes memory executeCallData =
            abi.encodePacked(msca.executeUserOp.selector, abi.encodeCall(MSCACallFlowModule.foo, (17)));
        PackedUserOperation memory userOp =
            buildPartialUserOp(address(msca), 0, "0x", vm.toString(executeCallData), 1000000, 1000000, 0, 1, 1, "0x");
        // PER_SELECTOR_VALIDATION_FLAG
        userOp.signature = encodeSignature(new PreValidationHookData[](0), mscaCallFlowValidationEntity, "0x", false);
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;
        entryPoint.handleOps(userOps, beneficiary);

        _checkInvokeOrderWithOnlySelectorAssocExecHooks();
    }

    // Runtime: module exec function with validation associated exec hooks and selector associated exec hooks
    // Call order is the same as the test on userOp
    function testModuleFuncWithAllHooksViaRuntime() public {
        _installOrderCheckerModule(4);
        msca.executeWithRuntimeValidation(
            abi.encodeCall(MSCACallFlowModule.foo, (17)),
            encodeSignature(new PreValidationHookData[](0), mscaCallFlowValidationEntity, "0x", false)
        );

        _checkInvokeOrderWithBothValidationAndSelectorAssocExecHooks();
    }

    // Runtime: module exec function, with only selector-associated exec hooks, without validation-associated exec hooks
    // Call order is the same as the test on userOp
    function testModuleFuncWithOnlySelectorExecHooksViaRuntime() public {
        _installOrderCheckerModuleWithOnlySelectorExecHooks(4);
        msca.executeWithRuntimeValidation(
            abi.encodeCall(MSCACallFlowModule.foo, (17)),
            encodeSignature(new PreValidationHookData[](0), mscaCallFlowValidationEntity, "0x", false)
        );

        _checkInvokeOrderWithOnlySelectorAssocExecHooks();
    }

    // Direct call: module exec function with validation-associated exec hooks and selector-associated exec hooks
    function testModuleFuncWithAllHooksViaRuntimeDirectCall() public {
        _installOrderCheckerModule(DIRECT_CALL_VALIDATION_ENTITY_ID);

        vm.prank(address(mscaCallFlowModule));
        MSCACallFlowModule(address(msca)).foo(17);

        _checkInvokeOrderDirectCallWithBothValidationAndSelectorAssocExecHooks();
    }

    // Direct call: with only selector-associated exec hooks, without validation-associated exec hooks
    function testModuleFuncWithOnlySelectorExecHooksViaRuntimeDirectCall() public {
        _installOrderCheckerModuleWithOnlySelectorExecHooks(DIRECT_CALL_VALIDATION_ENTITY_ID);

        vm.prank(address(mscaCallFlowModule));
        MSCACallFlowModule(address(msca)).foo(17);

        _checkInvokeOrderDirectCallWithOnlySelectorAssocExecHooks();
    }

    // User op: account native function with validation-associated exec hooks and selector-associated exec hooks
    // Call order is the same as the test on module exec function
    function testAccountNativeFuncWithAllHooksViaUserOp() public {
        _installOrderCheckerModule(4);

        bytes memory executeCallData = abi.encodePacked(
            msca.executeUserOp.selector,
            abi.encodeCall(
                msca.execute, (address(mscaCallFlowModule), 0 wei, abi.encodeCall(MSCACallFlowModule.foo, (17)))
            )
        );
        PackedUserOperation memory userOp =
            buildPartialUserOp(address(msca), 0, "0x", vm.toString(executeCallData), 1000000, 1000000, 0, 1, 1, "0x");
        // PER_SELECTOR_VALIDATION_FLAG
        userOp.signature = encodeSignature(new PreValidationHookData[](0), mscaCallFlowValidationEntity, "0x", false);
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;
        entryPoint.handleOps(userOps, beneficiary);

        _checkInvokeOrderWithBothValidationAndSelectorAssocExecHooks();
    }

    // User op: account native function, with only selector-associated exec hooks, without validation-associated exec
    // hooks, no executeUserOp
    // Call order is the same as the test on module exec function
    function testAccountNativeFuncWithOnlySelectorExecHooksViaUserOp() public {
        _installOrderCheckerModuleWithOnlySelectorExecHooks(4);

        bytes memory executeCallData = abi.encodeCall(
            msca.execute, (address(mscaCallFlowModule), 0 wei, abi.encodeCall(MSCACallFlowModule.foo, (17)))
        );
        PackedUserOperation memory userOp =
            buildPartialUserOp(address(msca), 0, "0x", vm.toString(executeCallData), 1000000, 1000000, 0, 1, 1, "0x");
        // PER_SELECTOR_VALIDATION_FLAG
        userOp.signature = encodeSignature(new PreValidationHookData[](0), mscaCallFlowValidationEntity, "0x", false);
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;
        entryPoint.handleOps(userOps, beneficiary);

        _checkInvokeOrderWithOnlySelectorAssocExecHooks();
    }

    // User op: account native function, with only selector-associated exec hooks, without validation-associated exec
    // hooks
    // Call order is the same as the test on module exec function
    function testAccountNativeFuncWithOnlySelectorExecHooksViaExecuteUserOp() public {
        _installOrderCheckerModuleWithOnlySelectorExecHooks(4);

        bytes memory executeCallData = abi.encodePacked(
            msca.executeUserOp.selector,
            abi.encodeCall(
                msca.execute, (address(mscaCallFlowModule), 0 wei, abi.encodeCall(MSCACallFlowModule.foo, (17)))
            )
        );
        PackedUserOperation memory userOp =
            buildPartialUserOp(address(msca), 0, "0x", vm.toString(executeCallData), 1000000, 1000000, 0, 1, 1, "0x");
        // PER_SELECTOR_VALIDATION_FLAG
        userOp.signature = encodeSignature(new PreValidationHookData[](0), mscaCallFlowValidationEntity, "0x", false);
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;
        entryPoint.handleOps(userOps, beneficiary);

        _checkInvokeOrderWithOnlySelectorAssocExecHooks();
    }

    // Runtime: account native function with validation-associated exec hooks and selector-associated exec hooks
    // Call order is the same as the test on module exec function
    function testAccountNativeFuncWithAllHooksViaRuntime() public {
        _installOrderCheckerModule(4);

        msca.executeWithRuntimeValidation(
            abi.encodeCall(
                msca.execute, (address(mscaCallFlowModule), 0 wei, abi.encodeCall(MSCACallFlowModule.foo, (17)))
            ),
            encodeSignature(new PreValidationHookData[](0), mscaCallFlowValidationEntity, "0x", false)
        );

        _checkInvokeOrderWithBothValidationAndSelectorAssocExecHooks();
    }

    // Runtime: account native function, with only selector-associated exec hooks, without validation-associated exec
    // hooks
    // Call order is the same as the test on module exec function
    function testAccountNativeFuncWithOnlySelectorExecHooksViaRuntime() public {
        _installOrderCheckerModuleWithOnlySelectorExecHooks(4);

        msca.executeWithRuntimeValidation(
            abi.encodeCall(
                msca.execute, (address(mscaCallFlowModule), 0 wei, abi.encodeCall(MSCACallFlowModule.foo, (17)))
            ),
            encodeSignature(new PreValidationHookData[](0), mscaCallFlowValidationEntity, "0x", false)
        );

        _checkInvokeOrderWithOnlySelectorAssocExecHooks();
    }

    function testSignatureValidationWithAllHooks() public {
        _installOrderCheckerModule(4);
        // Technically, the hooks aren't supposed to make state changes during the signature validation flow
        // because it will be invoked with `staticcall`, so we call `isValidSignature` directly with `call`.
        bytes memory callData = abi.encodeCall(
            msca.isValidSignature,
            (bytes32(0), encode1271Signature(new PreValidationHookData[](0), mscaCallFlowValidationEntity, "0x"))
        );

        // solhint-disable-next-line avoid-low-level-calls
        (bool success,) = address(msca).call(callData);
        assertTrue(success);
        _checkInvokeOrderSignatureValidation();
    }

    // - install validation and validation-associated exec hooks
    // - install execution function and selector-associated exec hooks
    function _installOrderCheckerModule(uint32 validationEntityId) internal {
        (ValidationConfig validationConfig, bytes4[] memory selectors, bytes[] memory startingHooks) =
            _getValidationWithHooksForInstallation(validationEntityId);

        bytes[] memory hooks = new bytes[](9);

        // Validation hooks
        hooks[0] = startingHooks[0];
        hooks[1] = startingHooks[1];
        hooks[2] = startingHooks[2];

        // Validation-associated exec hooks
        hooks[3] = abi.encodePacked(
            HookConfigLib.packExecHook({
                _module: address(mscaCallFlowModule),
                _entityId: 5,
                _hasPre: true,
                _hasPost: false
            })
        );
        hooks[4] = abi.encodePacked(
            HookConfigLib.packExecHook({
                _module: address(mscaCallFlowModule),
                _entityId: 6,
                _hasPre: false,
                _hasPost: true
            })
        );
        hooks[5] = abi.encodePacked(
            HookConfigLib.packExecHook({
                _module: address(mscaCallFlowModule),
                _entityId: 7,
                _hasPre: true,
                _hasPost: true
            })
        );
        hooks[6] = abi.encodePacked(
            HookConfigLib.packExecHook({
                _module: address(mscaCallFlowModule),
                _entityId: 8,
                _hasPre: true,
                _hasPost: true
            })
        );
        hooks[7] = abi.encodePacked(
            HookConfigLib.packExecHook({
                _module: address(mscaCallFlowModule),
                _entityId: 9,
                _hasPre: true,
                _hasPost: false
            })
        );
        hooks[8] = abi.encodePacked(
            HookConfigLib.packExecHook({
                _module: address(mscaCallFlowModule),
                _entityId: 10,
                _hasPre: false,
                _hasPost: true
            })
        );

        vm.prank(address(entryPoint));
        msca.installValidation(validationConfig, selectors, "", hooks);

        _installExecutionFunctionWithHooks();
    }

    function _installOrderCheckerModuleWithOnlySelectorExecHooks(uint32 validationEntityId) internal {
        (ValidationConfig validationConfig, bytes4[] memory selectors, bytes[] memory hooks) =
            _getValidationWithHooksForInstallation(validationEntityId);

        vm.prank(address(entryPoint));
        msca.installValidation(validationConfig, selectors, "", hooks);
        _installExecutionFunctionWithHooks();
    }

    // Install the execution function and selector-associated hooks
    // The executionManifest only contains the execution function, we need to insert the selector-associated
    // hooks, which are more dynamic
    function _installExecutionFunctionWithHooks() internal {
        ExecutionManifest memory manifest = mscaCallFlowModule.executionManifest();
        ManifestExecutionHook[] memory execHooks = new ManifestExecutionHook[](12);

        // Apply hooks to the `foo` function
        execHooks[0] = ManifestExecutionHook({
            executionSelector: MSCACallFlowModule.foo.selector,
            entityId: 11,
            isPreHook: true,
            isPostHook: false
        });
        execHooks[1] = ManifestExecutionHook({
            executionSelector: MSCACallFlowModule.foo.selector,
            entityId: 12,
            isPreHook: false,
            isPostHook: true
        });
        execHooks[2] = ManifestExecutionHook({
            executionSelector: MSCACallFlowModule.foo.selector,
            entityId: 13,
            isPreHook: true,
            isPostHook: true
        });
        execHooks[3] = ManifestExecutionHook({
            executionSelector: MSCACallFlowModule.foo.selector,
            entityId: 14,
            isPreHook: true,
            isPostHook: true
        });
        execHooks[4] = ManifestExecutionHook({
            executionSelector: MSCACallFlowModule.foo.selector,
            entityId: 15,
            isPreHook: true,
            isPostHook: false
        });
        execHooks[5] = ManifestExecutionHook({
            executionSelector: MSCACallFlowModule.foo.selector,
            entityId: 16,
            isPreHook: false,
            isPostHook: true
        });

        // Apply hooks to the `execute` function
        execHooks[6] = ManifestExecutionHook({
            executionSelector: msca.execute.selector,
            entityId: 11,
            isPreHook: true,
            isPostHook: false
        });
        execHooks[7] = ManifestExecutionHook({
            executionSelector: msca.execute.selector,
            entityId: 12,
            isPreHook: false,
            isPostHook: true
        });
        execHooks[8] = ManifestExecutionHook({
            executionSelector: msca.execute.selector,
            entityId: 13,
            isPreHook: true,
            isPostHook: true
        });
        execHooks[9] = ManifestExecutionHook({
            executionSelector: msca.execute.selector,
            entityId: 14,
            isPreHook: true,
            isPostHook: true
        });
        execHooks[10] = ManifestExecutionHook({
            executionSelector: msca.execute.selector,
            entityId: 15,
            isPreHook: true,
            isPostHook: false
        });
        execHooks[11] = ManifestExecutionHook({
            executionSelector: msca.execute.selector,
            entityId: 16,
            isPreHook: false,
            isPostHook: true
        });

        manifest.executionHooks = execHooks;

        vm.prank(address(entryPoint));
        msca.installExecution(address(mscaCallFlowModule), manifest, "");
    }

    // Returns the validation config, selectors, and three validation hooks for the installValidation call,
    // No validation-associated exec hooks are included
    function _getValidationWithHooksForInstallation(uint32 validationEntityId)
        internal
        returns (ValidationConfig, bytes4[] memory, bytes[] memory)
    {
        ValidationConfig validationConfig = ValidationConfigLib.pack({
            _module: address(mscaCallFlowModule),
            _entityId: validationEntityId,
            _isGlobal: false,
            _isSignatureValidation: true,
            _isUserOpValidation: true
        });

        mscaCallFlowValidationEntity = ModuleEntityLib.pack(address(mscaCallFlowModule), validationEntityId);

        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = MSCACallFlowModule.foo.selector;
        selectors[1] = msca.execute.selector;

        bytes[] memory hooks = new bytes[](3);

        // Validation hooks
        hooks[0] =
            abi.encodePacked(HookConfigLib.packValidationHook({_module: address(mscaCallFlowModule), _entityId: 1}));
        hooks[1] =
            abi.encodePacked(HookConfigLib.packValidationHook({_module: address(mscaCallFlowModule), _entityId: 2}));
        hooks[2] =
            abi.encodePacked(HookConfigLib.packValidationHook({_module: address(mscaCallFlowModule), _entityId: 3}));

        return (validationConfig, selectors, hooks);
    }

    //  1. validation hook 1
    //  2. validation hook 2
    //  3. validation hook 3
    //  4. validation
    //  5. pre exec (validation-assoc) hook 1: pre only
    //  6. pre exec (validation-assoc) hook 2: post only (skipped)
    //  7. pre exec (validation-assoc) hook 3: pre and post
    //  8. pre exec (validation-assoc) hook 4: pre and post
    //  9. pre exec (validation-assoc) hook 5: pre only
    // 10. pre exec (validation-assoc) hook 6: post only (skipped)
    // 11. pre exec (selector-assoc) hook 1: pre only
    // 12. pre exec (selector-assoc) hook 2: post only (skipped)
    // 13. pre exec (selector-assoc) hook 3: pre and post
    // 14. pre exec (selector-assoc) hook 4: pre and post
    // 15. pre exec (selector-assoc) hook 5: pre only
    // 16. pre exec (selector-assoc) hook 6: post only (skipped)
    // 17. exec
    // 16. post exec (selector-assoc) hook 6: post only
    // 15. post exec (selector-assoc) hook 5: pre only (skipped)
    // 14. post exec (selector-assoc) hook 4: pre and post
    // 13. post exec (selector-assoc) hook 3: pre and post
    // 12. post exec (selector-assoc) hook 2: post only)
    // 11. post exec (selector-assoc) hook 1: pre only (skipped)
    // 10. post exec (validation-assoc) hook 6: post only
    //  9. post exec (validation-assoc) hook 5: pre only (skipped)
    //  8. post exec (validation-assoc) hook 4: pre and post
    //  7. post exec (validation-assoc) hook 3: pre and post
    //  6. post exec (validation-assoc) hook 2: post only
    //  5. post exec (validation-assoc) hook 1: pre only (skipped)
    function _checkInvokeOrderWithBothValidationAndSelectorAssocExecHooks() internal view {
        uint32[] memory expectedOrder = new uint32[](21);
        uint32[21] memory expectedOrderValues =
            [uint32(1), 2, 3, 4, 5, 7, 8, 9, 11, 13, 14, 15, 17, 16, 14, 13, 12, 10, 8, 7, 6];

        for (uint256 i = 0; i < expectedOrder.length; i++) {
            expectedOrder[i] = expectedOrderValues[i];
        }

        uint256[] memory actualOrder = mscaCallFlowModule.getRecordedFunctionCalls();
        _assertArrsEqual(expectedOrder, actualOrder);
    }

    // only validation is skipped compared to non-direct flow because the call is from the module that
    // provides the validation function
    //  1. validation hook 1
    //  2. validation hook 2
    //  3. validation hook 3
    //  4. validation (skipped)
    //  5. pre exec (validation-assoc) hook 1: pre only
    //  6. pre exec (validation-assoc) hook 2: post only (skipped)
    //  7. pre exec (validation-assoc) hook 3: pre and post
    //  8. pre exec (validation-assoc) hook 4: pre and post
    //  9. pre exec (validation-assoc) hook 5: pre only
    // 10. pre exec (validation-assoc) hook 6: post only (skipped)
    // 11. pre exec (selector-assoc) hook 1: pre only
    // 12. pre exec (selector-assoc) hook 2: post only (skipped)
    // 13. pre exec (selector-assoc) hook 3: pre and post
    // 14. pre exec (selector-assoc) hook 4: pre and post
    // 15. pre exec (selector-assoc) hook 5: pre only
    // 16. pre exec (selector-assoc) hook 6: post only (skipped)
    // 17. exec
    // 16. post exec (selector-assoc) hook 6: post only
    // 15. post exec (selector-assoc) hook 5: pre only (skipped)
    // 14. post exec (selector-assoc) hook 4: pre and post
    // 13. post exec (selector-assoc) hook 3: pre and post
    // 12. post exec (selector-assoc) hook 2: post only
    // 11. post exec (selector-assoc) hook 1: pre only (skipped)
    // 10. post exec (validation-assoc) hook 6: post only
    //  9. post exec (validation-assoc) hook 5: pre only (skipped)
    //  8. post exec (validation-assoc) hook 4: pre and post
    //  7. post exec (validation-assoc) hook 3: pre and post
    //  6. post exec (validation-assoc) hook 2: post only
    //  5. post exec (validation-assoc) hook 1: pre only (skipped)
    function _checkInvokeOrderDirectCallWithBothValidationAndSelectorAssocExecHooks() internal view {
        uint32[] memory expectedOrder = new uint32[](20);
        uint32[20] memory expectedOrderValues =
            [uint32(1), 2, 3, 5, 7, 8, 9, 11, 13, 14, 15, 17, 16, 14, 13, 12, 10, 8, 7, 6];

        for (uint256 i = 0; i < expectedOrder.length; i++) {
            expectedOrder[i] = expectedOrderValues[i];
        }

        uint256[] memory actualOrder = mscaCallFlowModule.getRecordedFunctionCalls();

        _assertArrsEqual(expectedOrder, actualOrder);
    }

    //  1. validation hook 1
    //  2. validation hook 2
    //  3. validation hook 3
    //  4. validation
    //  5. pre exec (validation-assoc) hook 1: pre only (skipped)
    //  6. pre exec (validation-assoc) hook 2: post only (skipped)
    //  7. pre exec (validation-assoc) hook 3: pre and post (skipped)
    //  8. pre exec (validation-assoc) hook 4: pre and post (skipped)
    //  9. pre exec (validation-assoc) hook 5: pre only (skipped)
    // 10. pre exec (validation-assoc) hook 6: post only (skipped)
    // 11. pre exec (selector-assoc) hook 1: pre only
    // 12. pre exec (selector-assoc) hook 2: post only (skipped)
    // 13. pre exec (selector-assoc) hook 3: pre and post
    // 14. pre exec (selector-assoc) hook 4: pre and post
    // 15. pre exec (selector-assoc) hook 5: pre only
    // 16. pre exec (selector-assoc) hook 6: post only (skipped)
    // 17. exec
    // 16. post exec (selector-assoc) hook 6: post only
    // 15. post exec (selector-assoc) hook 5: pre only (skipped)
    // 14. post exec (selector-assoc) hook 4: pre and post
    // 13. post exec (selector-assoc) hook 3: pre and post
    // 12. post exec (selector-assoc) hook 2: post only)
    // 11. post exec (selector-assoc) hook 1: pre only (skipped)
    // 10. post exec (validation-assoc) hook 6: post only (skipped)
    //  9. post exec (validation-assoc) hook 5: pre only (skipped)
    //  8. post exec (validation-assoc) hook 4: pre and post (skipped)
    //  7. post exec (validation-assoc) hook 3: pre and post (skipped)
    //  6. post exec (validation-assoc) hook 2: post only (skipped)
    //  5. post exec (validation-assoc) hook 1: pre only (skipped)
    function _checkInvokeOrderWithOnlySelectorAssocExecHooks() internal view {
        uint32[] memory expectedOrder = new uint32[](13);
        uint32[13] memory expectedOrderValues = [uint32(1), 2, 3, 4, 11, 13, 14, 15, 17, 16, 14, 13, 12];

        for (uint256 i = 0; i < expectedOrder.length; i++) {
            expectedOrder[i] = expectedOrderValues[i];
        }

        uint256[] memory actualOrder = mscaCallFlowModule.getRecordedFunctionCalls();

        _assertArrsEqual(expectedOrder, actualOrder);
    }

    // only validation is skipped compared to non-direct flow because the call is from the module that
    // provides the validation function
    //  1. validation hook 1
    //  2. validation hook 2
    //  3. validation hook 3
    //  4. validation (skipped)
    //  5. pre exec (validation-assoc) hook 1: pre only (skipped)
    //  6. pre exec (validation-assoc) hook 2: post only (skipped)
    //  7. pre exec (validation-assoc) hook 3: pre and post (skipped)
    //  8. pre exec (validation-assoc) hook 4: pre and post (skipped)
    //  9. pre exec (validation-assoc) hook 5: pre only (skipped)
    // 10. pre exec (validation-assoc) hook 6: post only (skipped)
    // 11. pre exec (selector-assoc) hook 1: pre only
    // 12. pre exec (selector-assoc) hook 2: post only (skipped)
    // 13. pre exec (selector-assoc) hook 3: pre and post
    // 14. pre exec (selector-assoc) hook 4: pre and post
    // 15. pre exec (selector-assoc) hook 5: pre only
    // 16. pre exec (selector-assoc) hook 6: post only (skipped)
    // 17. exec
    // 16. post exec (selector-assoc) hook 6: post only
    // 15. post exec (selector-assoc) hook 5: pre only (skipped)
    // 14. post exec (selector-assoc) hook 4: pre and post
    // 13. post exec (selector-assoc) hook 3: pre and post
    // 12. post exec (selector-assoc) hook 2: post only)
    // 11. post exec (selector-assoc) hook 1: pre only (skipped)
    // 10. post exec (validation-assoc) hook 6: post only (skipped)
    //  9. post exec (validation-assoc) hook 5: pre only (skipped)
    //  8. post exec (validation-assoc) hook 4: pre and post (skipped)
    //  7. post exec (validation-assoc) hook 3: pre and post (skipped)
    //  6. post exec (validation-assoc) hook 2: post only (skipped)
    //  5. post exec (validation-assoc) hook 1: pre only (skipped)
    function _checkInvokeOrderDirectCallWithOnlySelectorAssocExecHooks() internal view {
        uint32[] memory expectedOrder = new uint32[](12);
        uint32[12] memory expectedOrderValues = [uint32(1), 2, 3, 11, 13, 14, 15, 17, 16, 14, 13, 12];

        for (uint256 i = 0; i < expectedOrder.length; i++) {
            expectedOrder[i] = expectedOrderValues[i];
        }

        uint256[] memory actualOrder = mscaCallFlowModule.getRecordedFunctionCalls();

        _assertArrsEqual(expectedOrder, actualOrder);
    }

    // Signature validation is only going to trigger the validation hooks and validation function, not the exec hooks
    //  1. validation hook 1
    //  2. validation hook 2
    //  3. validation hook 3
    //  4. validation
    //  5. pre exec (validation-assoc) hook 1: pre only (skipped)
    //  6. pre exec (validation-assoc) hook 2: post only (skipped)
    //  7. pre exec (validation-assoc) hook 3: pre and post (skipped)
    //  8. pre exec (validation-assoc) hook 4: pre and post (skipped)
    //  9. pre exec (validation-assoc) hook 5: pre only (skipped)
    // 10. pre exec (validation-assoc) hook 6: post only (skipped)
    // 11. pre exec (selector-assoc) hook 1: pre only (skipped)
    // 12. pre exec (selector-assoc) hook 2: post only (skipped)
    // 13. pre exec (selector-assoc) hook 3: pre and post (skipped)
    // 14. pre exec (selector-assoc) hook 4: pre and post (skipped)
    // 15. pre exec (selector-assoc) hook 5: pre only (skipped)
    // 16. pre exec (selector-assoc) hook 6: post only (skipped)
    // 17. exec (skipped)
    // 16. post exec (selector-assoc) hook 6: post only (skipped)
    // 15. post exec (selector-assoc) hook 5: pre only (skipped)
    // 14. post exec (selector-assoc) hook 4: pre and post (skipped)
    // 13. post exec (selector-assoc) hook 3: pre and post (skipped)
    // 12. post exec (selector-assoc) hook 2: post only) (skipped)
    // 11. post exec (selector-assoc) hook 1: pre only (skipped)
    // 10. post exec (validation-assoc) hook 6: post only (skipped)
    //  9. post exec (validation-assoc) hook 5: pre only (skipped)
    //  8. post exec (validation-assoc) hook 4: pre and post (skipped)
    //  7. post exec (validation-assoc) hook 3: pre and post (skipped)
    //  6. post exec (validation-assoc) hook 2: post only (skipped)
    //  5. post exec (validation-assoc) hook 1: pre only (skipped)
    function _checkInvokeOrderSignatureValidation() internal view {
        uint32[] memory expectedOrder = new uint32[](4);
        uint32[4] memory expectedOrderValues = [uint32(1), 2, 3, 4];

        for (uint256 i = 0; i < expectedOrder.length; i++) {
            expectedOrder[i] = expectedOrderValues[i];
        }

        uint256[] memory actualOrder = mscaCallFlowModule.getRecordedFunctionCalls();

        _assertArrsEqual(expectedOrder, actualOrder);
    }

    function _assertArrsEqual(uint32[] memory expected, uint256[] memory actual) internal pure {
        assertEq(expected.length, actual.length);

        for (uint256 i = 0; i < expected.length; i++) {
            assertEq(expected[i], actual[i]);
        }
    }
}
