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
import {UpgradableMSCA} from "../../../../src/msca/6900/v0.8/account/UpgradableMSCA.sol";

import {ModuleEntity, ValidationConfig} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

import {Call, IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

import {SingleSignerValidationModule} from
    "../../../../src/msca/6900/v0.8/modules/validation/SingleSignerValidationModule.sol";
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";

import {UpgradableMSCAFactory} from "../../../../src/msca/6900/v0.8/factories/UpgradableMSCAFactory.sol";
import {DirectCallModule} from "./helpers/DirectCallModule.sol";
import {AccountTestUtils} from "./utils/AccountTestUtils.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {DIRECT_CALL_VALIDATION_ENTITY_ID} from "@erc6900/reference-implementation/helpers/Constants.sol";

/// @notice Inspired by 6900 reference implementation with some modifications
contract DirectCallsFromModuleTest is AccountTestUtils {
    using ValidationConfigLib for ValidationConfig;
    using ModuleEntityLib for ModuleEntity;

    IEntryPoint private entryPoint = new EntryPoint();
    uint256 internal ownerPrivateKey;
    address private ownerAddr;
    address payable private beneficiary; // e.g. bundler
    UpgradableMSCAFactory private factory;
    address private factoryOwner;
    SingleSignerValidationModule private singleSignerValidationModule;
    ModuleEntity private ownerValidation;
    bytes32 private salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
    UpgradableMSCA private msca;
    DirectCallModule internal directCallModule;
    ModuleEntity internal directCallModuleEntity;

    event ValidationUninstalled(address indexed module, uint32 indexed entityId, bool onUninstallSucceeded);

    modifier installRandomTypeOfValidation(bool selectorValidation) {
        if (selectorValidation) {
            bytes4[] memory selectors = new bytes4[](1);
            selectors[0] = IModularAccount.execute.selector;
            _installDirectCallValidationPerSelector(selectors);
        } else {
            _installDirectCallValidationGlobal();
        }
        _;
    }

    function setUp() public {
        factoryOwner = makeAddr("factoryOwner");
        beneficiary = payable(address(makeAddr("bundler")));
        factory = new UpgradableMSCAFactory(factoryOwner, address(entryPoint));
        singleSignerValidationModule = new SingleSignerValidationModule();
        directCallModule = new DirectCallModule();
        address[] memory modules = new address[](2);
        modules[0] = address(singleSignerValidationModule);
        modules[1] = address(directCallModule);
        bool[] memory _permissions = new bool[](2);
        _permissions[0] = true;
        _permissions[1] = true;
        vm.startPrank(factoryOwner);
        factory.setModules(modules, _permissions);
        vm.stopPrank();
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, false, true, false);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), new bytes[](0));
        msca = factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);

        assertFalse(directCallModule.preHookRan());
        assertFalse(directCallModule.postHookRan());
        directCallModuleEntity = ModuleEntityLib.pack(address(directCallModule), DIRECT_CALL_VALIDATION_ENTITY_ID);
    }

    /* -------------------------------------------------------------------------- */
    /*                                  Negatives                                 */
    /* -------------------------------------------------------------------------- */

    function testFailDirectCallModuleNotInstalled() public {
        vm.startPrank(address(directCallModule));
        vm.expectRevert(
            abi.encodeWithSelector(BaseMSCA.InvalidValidationFunction.selector, IModularAccount.execute.selector)
        );
        msca.execute(address(0), 0, "");
        vm.stopPrank();
    }

    function testFailDirectCallModuleCallOtherSelector() public {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = IModularAccount.execute.selector;
        _installDirectCallValidationPerSelector(selectors);

        Call[] memory calls = new Call[](0);
        vm.startPrank(address(directCallModule));
        vm.expectRevert(
            abi.encodeWithSelector(BaseMSCA.InvalidValidationFunction.selector, IModularAccount.executeBatch.selector)
        );
        msca.executeBatch(calls);
        vm.stopPrank();
    }

    function testFuzz_failDirectCallModuleUninstalled(bool selectorValidation)
        public
        installRandomTypeOfValidation(selectorValidation)
    {
        _uninstallDirectCallValidation();
        vm.startPrank(address(directCallModule));
        vm.expectRevert(
            abi.encodeWithSelector(
                BaseMSCA.InvalidValidationFunction.selector, IModularAccount.execute.selector, directCallModuleEntity
            )
        );
        msca.execute(address(0), 0, "");
        vm.stopPrank();
    }

    /* -------------------------------------------------------------------------- */
    /*                                  Positives                                 */
    /* -------------------------------------------------------------------------- */
    function testFuzz_passDirectCallFromModulePrank(bool selectorValidation)
        public
        installRandomTypeOfValidation(selectorValidation)
    {
        vm.startPrank(address(directCallModule));
        msca.execute(address(0), 0, "");
        assertTrue(directCallModule.preHookRan());
        assertTrue(directCallModule.postHookRan());
        vm.stopPrank();
    }

    function testFuzz_passDirectCallFromModuleCallback(bool validationType)
        public
        installRandomTypeOfValidation(validationType)
    {
        bytes memory encodedCall = abi.encodeCall(DirectCallModule.directCall, ());
        vm.startPrank(address(entryPoint));
        bytes memory result = msca.execute(address(directCallModule), 0, encodedCall);
        assertTrue(directCallModule.preHookRan());
        assertTrue(directCallModule.postHookRan());

        // the directCall() function in the module calls back into `execute()` with an encoded call back into the
        // module's getData() function.
        assertEq(abi.decode(result, (bytes)), abi.encode(directCallModule.getData()));
        vm.stopPrank();
    }

    function testFuzz_flowDirectCallFromModuleSequence(bool validationType)
        public
        installRandomTypeOfValidation(validationType)
    {
        // install => successfully call => uninstall => fail to call
        vm.startPrank(address(directCallModule));
        msca.execute(address(0), 0, "");
        assertTrue(directCallModule.preHookRan());
        assertTrue(directCallModule.postHookRan());

        _uninstallDirectCallValidation();

        vm.startPrank(address(directCallModule));
        vm.expectRevert(
            abi.encodeWithSelector(
                BaseMSCA.InvalidValidationFunction.selector, IModularAccount.execute.selector, directCallModuleEntity
            )
        );
        msca.execute(address(0), 0, "");
        vm.stopPrank();
    }

    function test_directCallsFromEOA() public {
        address extraOwner = makeAddr("extraOwner");
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = IModularAccount.execute.selector;
        vm.startPrank(address(entryPoint));
        ValidationConfig validationConfig =
            ValidationConfigLib.pack(extraOwner, DIRECT_CALL_VALIDATION_ENTITY_ID, false, false, false);
        msca.installValidation(validationConfig, selectors, bytes(""), new bytes[](0));

        vm.startPrank(extraOwner);
        msca.execute(makeAddr("dead"), 0, "");
        vm.stopPrank();
    }

    /* -------------------------------------------------------------------------- */
    /*                                  Internals                                 */
    /* -------------------------------------------------------------------------- */
    function _installDirectCallValidationPerSelector(bytes4[] memory selectors) internal {
        bytes[] memory execHooks = new bytes[](1);
        execHooks[0] = abi.encodePacked(
            HookConfigLib.packExecHook({_hookFunction: directCallModuleEntity, _hasPre: true, _hasPost: true}), ""
        );

        vm.startPrank(address(entryPoint));

        ValidationConfig validationConfig = ValidationConfigLib.pack(directCallModuleEntity, false, false, false);
        msca.installValidation(validationConfig, selectors, bytes(""), execHooks);
    }

    function _installDirectCallValidationGlobal() internal {
        bytes[] memory execHooks = new bytes[](1);
        execHooks[0] = abi.encodePacked(
            HookConfigLib.packExecHook({_hookFunction: directCallModuleEntity, _hasPre: true, _hasPost: true}), ""
        );
        vm.startPrank(address(entryPoint));

        ValidationConfig validationConfig = ValidationConfigLib.pack(directCallModuleEntity, true, false, false);
        msca.installValidation(validationConfig, new bytes4[](0), bytes(""), execHooks);
    }

    function _uninstallDirectCallValidation() internal {
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, true);
        (address moduleAddr,) = directCallModuleEntity.unpack();
        emit ValidationUninstalled(moduleAddr, DIRECT_CALL_VALIDATION_ENTITY_ID, true);
        msca.uninstallValidation(directCallModuleEntity, bytes(""), new bytes[](1));
    }
}
