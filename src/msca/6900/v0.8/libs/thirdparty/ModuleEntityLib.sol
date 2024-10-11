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

import {ModuleEntity} from "../../common/Types.sol";

// ModuleEntity is a packed representation of a module function
// Layout:
// 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA________________________ // Address
// 0x________________________________________BBBBBBBB________________ // Entity ID
// 0x________________________________________________0000000000000000 // unused
/// @notice Inspired by 6900 reference impl with some modifications.
library ModuleEntityLib {
    function pack(address addr, uint32 entityId) internal pure returns (ModuleEntity) {
        return ModuleEntity.wrap(bytes24(bytes20(addr)) | bytes24(uint192(entityId)));
    }

    function unpack(ModuleEntity moduleEntity) internal pure returns (address addr, uint32 entityId) {
        bytes24 underlying = ModuleEntity.unwrap(moduleEntity);
        addr = address(bytes20(underlying));
        entityId = uint32(bytes4(underlying << 160));
    }

    function isEmpty(ModuleEntity moduleEntity) internal pure returns (bool) {
        return ModuleEntity.unwrap(moduleEntity) == bytes24(0);
    }

    function notEmpty(ModuleEntity moduleEntity) internal pure returns (bool) {
        return ModuleEntity.unwrap(moduleEntity) != bytes24(0);
    }

    function eq(ModuleEntity a, ModuleEntity b) internal pure returns (bool) {
        return ModuleEntity.unwrap(a) == ModuleEntity.unwrap(b);
    }

    function notEq(ModuleEntity a, ModuleEntity b) internal pure returns (bool) {
        return ModuleEntity.unwrap(a) != ModuleEntity.unwrap(b);
    }

    function module(ModuleEntity moduleEntity) internal pure returns (address addr) {
        bytes24 underlying = ModuleEntity.unwrap(moduleEntity);
        addr = address(bytes20(underlying));
    }
}
