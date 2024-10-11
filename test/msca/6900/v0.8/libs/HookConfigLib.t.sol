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

import {HookConfig, ModuleEntity} from "../../../../../src/msca/6900/v0.8/common/Types.sol";

import {HookConfigLib} from "../../../../../src/msca/6900/v0.8/libs/HookConfigLib.sol";
import {ModuleEntityLib} from "../../../../../src/msca/6900/v0.8/libs/thirdparty/ModuleEntityLib.sol";
import {TestUtils} from "../../../../util/TestUtils.sol";

// @notice Inspired by 6900 reference impl with some modifications.
contract HookConfigLibTest is TestUtils {
    using ModuleEntityLib for ModuleEntity;
    using HookConfigLib for HookConfig;

    // Tests the packing and unpacking of a hook config with a randomized state
    function testFuzz_hookConfig_packingUnderlying(
        address addr,
        uint32 entityId,
        bool isValidation,
        bool hasPre,
        bool hasPost
    ) public {
        HookConfig hookConfig;
        if (isValidation) {
            hookConfig = HookConfigLib.packValidationHook(addr, entityId);
        } else {
            hookConfig = HookConfigLib.packExecHook(addr, entityId, hasPre, hasPost);
        }

        assertEq(hookConfig.getModule(), addr, "module mismatch");
        assertEq(hookConfig.getEntityId(), entityId, "entityId mismatch");
        assertEq(hookConfig.isValidationHook(), isValidation, "isValidation mismatch");

        if (isValidation) {
            // unpack validation hook
            ModuleEntity unpackedModuleEntity = HookConfigLib.unpackValidationHook(hookConfig);
            (address unpackedAddr, uint32 unpackedEntityId) = unpackedModuleEntity.unpack();
            assertEq(unpackedAddr, addr, "module mismatch");
            assertEq(unpackedEntityId, entityId, "entityId mismatch");
        } else {
            assertEq(hookConfig.hasPreHook(), hasPre, "hasPre mismatch");
            assertEq(hookConfig.hasPostHook(), hasPost, "hasPost mismatch");
            // unpack exec hook
            (ModuleEntity unpackedHookFunction, bool unpackedHasPre, bool unpackedHasPost) =
                HookConfigLib.unpackExecHook(hookConfig);
            (address unpackedAddr, uint32 unpackedEntityId) = unpackedHookFunction.unpack();
            assertEq(unpackedAddr, addr, "module mismatch");
            assertEq(unpackedEntityId, entityId, "entityId mismatch");
            assertEq(unpackedHasPre, hasPre, "hasPre mismatch");
            assertEq(unpackedHasPost, hasPost, "hasPost mismatch");
        }
    }

    function testFuzz_hookConfig_packingModuleEntity(
        ModuleEntity hookFunction,
        bool isValidation,
        bool hasPre,
        bool hasPost
    ) public {
        HookConfig hookConfig;
        if (isValidation) {
            hookConfig = HookConfigLib.packValidationHook(hookFunction);
        } else {
            hookConfig = HookConfigLib.packExecHook(hookFunction, hasPre, hasPost);
        }

        assertEq(
            ModuleEntity.unwrap(hookConfig.getModuleEntity()),
            ModuleEntity.unwrap(hookFunction),
            "moduleEntity mismatch"
        );
        assertEq(hookConfig.isValidationHook(), isValidation, "isValidation mismatch");

        if (isValidation) {
            // unpack validation hook
            ModuleEntity unpackedModuleEntity = HookConfigLib.unpackValidationHook(hookConfig);
            assertEq(
                ModuleEntity.unwrap(unpackedModuleEntity), ModuleEntity.unwrap(hookFunction), "moduleEntity mismatch"
            );
        } else {
            assertEq(hookConfig.hasPreHook(), hasPre, "hasPre mismatch");
            assertEq(hookConfig.hasPostHook(), hasPost, "hasPost mismatch");
            // unpack exec hook
            (ModuleEntity unpackedHookFunction, bool unpackedHasPre, bool unpackedHasPost) =
                HookConfigLib.unpackExecHook(hookConfig);
            assertEq(
                ModuleEntity.unwrap(unpackedHookFunction), ModuleEntity.unwrap(hookFunction), "moduleEntity mismatch"
            );
            assertEq(unpackedHasPre, hasPre, "hasPre mismatch");
            assertEq(unpackedHasPost, hasPost, "hasPost mismatch");
        }
    }
}
