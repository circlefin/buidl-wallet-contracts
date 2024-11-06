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

import {UpgradableMSCAFactory} from "../../../../src/msca/6900/v0.8/factories/UpgradableMSCAFactory.sol";
import {DIRECT_CALL_VALIDATION_ENTITY_ID} from "@erc6900/reference-implementation/helpers/Constants.sol";

import {TestUtils} from "../../../util/TestUtils.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";

import {SingleSignerValidationModule} from
    "../../../../src/msca/6900/v0.8/modules/validation/SingleSignerValidationModule.sol";
import {FooBarModule} from "./FooBarModule.sol";
import {TestPermittedCallModule} from "./TestPermittedCallModule.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {ModuleEntity, ValidationConfig} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";

contract PermittedCallTest is TestUtils {
    IEntryPoint private entryPoint = new EntryPoint();
    FooBarModule private fooBarModule;
    TestPermittedCallModule private permittedCallModule;
    address private factoryOwner;
    UpgradableMSCAFactory private factory;
    UpgradableMSCA private msca;
    uint256 internal ownerPrivateKey;
    address private ownerAddr;
    bytes private initializingData;
    bytes32 private salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
    ValidationConfig private validationConfig;

    error ExecFromModuleToSelectorNotPermitted(address module, bytes4 selector);

    function setUp() public {
        factoryOwner = makeAddr("factoryOwner");

        fooBarModule = new FooBarModule();
        permittedCallModule = new TestPermittedCallModule();
        SingleSignerValidationModule singleSignerValidationModule = new SingleSignerValidationModule();
        factory = new UpgradableMSCAFactory(factoryOwner, address(entryPoint));

        address[] memory modules = new address[](3);
        modules[0] = address(fooBarModule);
        modules[1] = address(permittedCallModule);
        modules[2] = address(singleSignerValidationModule);
        bool[] memory permissions = new bool[](3);
        permissions[0] = true;
        permissions[1] = true;
        permissions[2] = true;
        vm.startPrank(factoryOwner);
        factory.setModules(modules, permissions);
        vm.stopPrank();

        ModuleEntity ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        validationConfig = ValidationConfigLib.pack(ownerValidation, false, true, true);
    }

    function testAllowedPermittedCall() public {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testAllowedPermittedCall");
        initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), new bytes[](0));
        msca = factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        _installExecutions();

        bytes memory result = TestPermittedCallModule(address(msca)).permittedCallAllowed();
        bytes32 actual = abi.decode(result, (bytes32));
        assertEq(actual, keccak256("foo"));
    }

    function testNotAllowedPermittedCall() public {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testNotAllowedPermittedCall");
        initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), new bytes[](0));
        msca = factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        _installExecutions();

        vm.expectRevert(
            abi.encodeWithSelector(
                BaseMSCA.InvalidValidationFunction.selector,
                FooBarModule.bar.selector,
                ModuleEntityLib.pack(address(permittedCallModule), DIRECT_CALL_VALIDATION_ENTITY_ID)
            )
        );
        TestPermittedCallModule(address(msca)).permittedCallNotAllowed();
    }

    function _installExecutions() internal {
        vm.startPrank(address(entryPoint));
        msca.installExecution({
            module: address(permittedCallModule),
            manifest: permittedCallModule.executionManifest(),
            moduleInstallData: ""
        });
        msca.installExecution({
            module: address(fooBarModule),
            manifest: fooBarModule.executionManifest(),
            moduleInstallData: ""
        });
        vm.stopPrank();
    }
}
