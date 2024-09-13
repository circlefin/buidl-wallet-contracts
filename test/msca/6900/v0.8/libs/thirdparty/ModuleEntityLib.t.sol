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

import {TestUtils} from "../../../../../util/TestUtils.sol";
import {ModuleEntityLib} from "../../../../../../src/msca/6900/v0.8/libs/thirdparty/ModuleEntityLib.sol";
import {ModuleEntity} from "../../../../../../src/msca/6900/v0.8/common/Types.sol";

contract ModuleEntityLibTest is TestUtils {
    using ModuleEntityLib for ModuleEntity;

    function testFuzz_moduleEntity_packing(address addr, uint32 entityId) public {
        // console.log("addr: ", addr);
        // console.log("entityId: ", vm.toString(entityId));
        ModuleEntity fr = ModuleEntityLib.pack(addr, entityId);
        // console.log("packed: ", vm.toString(ModuleEntity.unwrap(fr)));
        (address addr2, uint32 entityId2) = ModuleEntityLib.unpack(fr);
        // console.log("addr2: ", addr2);
        // console.log("entityId2: ", vm.toString(entityId2));
        assertEq(addr, addr2);
        assertEq(entityId, entityId2);
    }

    function testFuzz_moduleEntity_operators(ModuleEntity a, ModuleEntity b) public {
        assertTrue(a.eq(a));
        assertTrue(b.eq(b));

        if (ModuleEntity.unwrap(a) == ModuleEntity.unwrap(b)) {
            assertTrue(a.eq(b));
            assertTrue(b.eq(a));
            assertFalse(a.notEq(b));
            assertFalse(b.notEq(a));
        } else {
            assertTrue(a.notEq(b));
            assertTrue(b.notEq(a));
            assertFalse(a.eq(b));
            assertFalse(b.eq(a));
        }
    }
}
