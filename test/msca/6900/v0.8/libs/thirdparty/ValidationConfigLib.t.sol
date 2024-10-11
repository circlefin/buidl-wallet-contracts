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

import {ModuleEntity, ValidationConfig} from "../../../../../../src/msca/6900/v0.8/common/Types.sol";
import {ModuleEntityLib} from "../../../../../../src/msca/6900/v0.8/libs/thirdparty/ModuleEntityLib.sol";

import {ValidationConfigLib} from "../../../../../../src/msca/6900/v0.8/libs/thirdparty/ValidationConfigLib.sol";
import {TestUtils} from "../../../../../util/TestUtils.sol";

// @notice Inspired by 6900 reference impl with some modifications.
contract ValidationConfigLibTest is TestUtils {
    using ModuleEntityLib for ModuleEntity;
    using ValidationConfigLib for ValidationConfig;
    using ValidationConfigLib for uint8;

    // Tests the packing and unpacking of a validation config with a randomized state
    function testFuzz_packingUnderlying(
        address module,
        uint32 entityId,
        bool isGlobal,
        bool isSignatureValidation,
        bool isUserOpValidation
    ) public {
        ValidationConfig validationConfig =
            ValidationConfigLib.pack(module, entityId, isGlobal, isSignatureValidation, isUserOpValidation);

        // Test unpacking underlying
        (address unpackedModule, uint32 unpackedEntityId, uint8 unpackedFlags) = validationConfig.unpackUnderlying();

        assertEq(module, unpackedModule, "module mismatch");
        assertEq(entityId, unpackedEntityId, "entityId mismatch");
        assertEq(isGlobal, unpackedFlags.isGlobal(), "isGlobal mismatch");
        assertEq(isSignatureValidation, unpackedFlags.isSignatureValidation(), "isSignatureValidation mismatch");
        assertEq(isUserOpValidation, unpackedFlags.isUserOpValidation(), "isUserOpValidation mismatch");

        // Test unpacking to ModuleEntity
        ModuleEntity expectedModuleEntity = ModuleEntityLib.pack(module, entityId);
        (ModuleEntity validationFunction, uint8 unpackedFlagsForMe) = validationConfig.unpack();

        assertEq(
            ModuleEntity.unwrap(validationFunction),
            ModuleEntity.unwrap(expectedModuleEntity),
            "validationFunction mismatch"
        );
        assertEq(isGlobal, unpackedFlagsForMe.isGlobal(), "isGlobal mismatch");
        assertEq(isSignatureValidation, unpackedFlagsForMe.isSignatureValidation(), "isSignatureValidation mismatch");
        assertEq(isUserOpValidation, unpackedFlagsForMe.isUserOpValidation(), "isUserOpValidation mismatch");

        // Test individual view functions
        assertEq(validationConfig.module(), module, "module mismatch");
        assertEq(validationConfig.entityId(), entityId, "entityId mismatch");
        assertEq(
            ModuleEntity.unwrap(validationConfig.moduleEntity()),
            ModuleEntity.unwrap(expectedModuleEntity),
            "moduleEntity mismatch"
        );
        assertEq(validationConfig.isGlobal(), isGlobal, "isGlobal mismatch");
        assertEq(validationConfig.isSignatureValidation(), isSignatureValidation, "isSignatureValidation mismatch");
        assertEq(validationConfig.isUserOpValidation(), isUserOpValidation, "isUserOpValidation mismatch");
    }

    function testFuzz_packingModuleEntity(
        ModuleEntity validationFunction,
        bool isGlobal,
        bool isSignatureValidation,
        bool isUserOpValidation
    ) public {
        ValidationConfig validationConfig =
            ValidationConfigLib.pack(validationFunction, isGlobal, isSignatureValidation, isUserOpValidation);

        // Test unpacking underlying
        (address module, uint32 entityId) = validationFunction.unpack();
        (address unpackedModule, uint32 unpackedEntityId, uint8 unpackedFlags) = validationConfig.unpackUnderlying();

        assertEq(module, unpackedModule, "module mismatch");
        assertEq(entityId, unpackedEntityId, "entityId mismatch");
        assertEq(isGlobal, unpackedFlags.isGlobal(), "isGlobal mismatch");
        assertEq(isSignatureValidation, unpackedFlags.isSignatureValidation(), "isSignatureValidation mismatch");
        assertEq(isUserOpValidation, unpackedFlags.isUserOpValidation(), "isUserOpValidation mismatch");

        // Test unpacking to ModuleEntity
        (ModuleEntity unpackedValidationFunction, uint8 unpackedFlagsForMe) = validationConfig.unpack();

        assertEq(
            ModuleEntity.unwrap(validationFunction),
            ModuleEntity.unwrap(unpackedValidationFunction),
            "validationFunction mismatch"
        );
        assertEq(isGlobal, unpackedFlagsForMe.isGlobal(), "isGlobal mismatch");
        assertEq(isSignatureValidation, unpackedFlagsForMe.isSignatureValidation(), "isSignatureValidation mismatch");
        assertEq(isUserOpValidation, unpackedFlagsForMe.isUserOpValidation(), "isUserOpValidation mismatch");

        // Test individual view functions
        assertEq(validationConfig.module(), module, "module mismatch");
        assertEq(validationConfig.entityId(), entityId, "entityId mismatch");
        assertEq(
            ModuleEntity.unwrap(validationConfig.moduleEntity()),
            ModuleEntity.unwrap(validationFunction),
            "validationFunction mismatch"
        );
        assertEq(validationConfig.isGlobal(), isGlobal, "isGlobal mismatch");
        assertEq(validationConfig.isSignatureValidation(), isSignatureValidation, "isSignatureValidation mismatch");
        assertEq(validationConfig.isUserOpValidation(), isUserOpValidation, "isUserOpValidation mismatch");
    }
}
