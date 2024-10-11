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

import {ModuleEntity, ValidationConfig} from "../../common/Types.sol";

// ValidationConfig is a packed representation of a validation function and flags for its configuration.
// Layout:
// 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA________________________ // Address
// 0x________________________________________BBBBBBBB________________ // Entity ID
// 0x________________________________________________CC______________ // Validation flags
// 0x__________________________________________________00000000000000 // unused
//
// Validation flags layout:
// 0b00000___ // unused
// 0b_____A__ // isGlobal
// 0b______B_ // isSignatureValidation
// 0b_______C // isUserOpValidation
// @notice Inspired by 6900 reference impl with some modifications.
library ValidationConfigLib {
    // is user op validation flag stored in last bit of the 25th byte
    bytes32 internal constant _VALIDATION_FLAG_IS_USER_OP = bytes32(uint256(1) << 56);
    // is signature validation flag stored in second to last bit of the 25th byte
    bytes32 internal constant _VALIDATION_FLAG_IS_SIGNATURE = bytes32(uint256(1) << 57);
    // is global flag stored in the third to last bit of the 25th byte
    bytes32 internal constant _VALIDATION_FLAG_IS_GLOBAL = bytes32(uint256(1) << 58);

    function pack(
        ModuleEntity _validationFunction,
        bool _isGlobal,
        bool _isSignatureValidation,
        bool _isUserOpValidation
    ) internal pure returns (ValidationConfig) {
        return ValidationConfig.wrap(
            bytes25(
                bytes25(ModuleEntity.unwrap(_validationFunction))
                    | bytes25(bytes32(_isGlobal ? _VALIDATION_FLAG_IS_GLOBAL : bytes32(0)))
                    | bytes25(bytes32(_isSignatureValidation ? _VALIDATION_FLAG_IS_SIGNATURE : bytes32(0)))
                    | bytes25(bytes32(_isUserOpValidation ? _VALIDATION_FLAG_IS_USER_OP : bytes32(0)))
            )
        );
    }

    function pack(
        address _module,
        uint32 _entityId,
        bool _isGlobal,
        bool _isSignatureValidation,
        bool _isUserOpValidation
    ) internal pure returns (ValidationConfig) {
        return ValidationConfig.wrap(
            bytes25(
                // module address stored in the first 20 bytes
                bytes25(bytes20(_module))
                // entityId stored in the 21st - 24th byte
                | bytes25(bytes24(uint192(_entityId)))
                    | bytes25(bytes32(_isGlobal ? _VALIDATION_FLAG_IS_GLOBAL : bytes32(0)))
                    | bytes25(bytes32(_isSignatureValidation ? _VALIDATION_FLAG_IS_SIGNATURE : bytes32(0)))
                    | bytes25(bytes32(_isUserOpValidation ? _VALIDATION_FLAG_IS_USER_OP : bytes32(0)))
            )
        );
    }

    function unpackUnderlying(ValidationConfig config)
        internal
        pure
        returns (address _module, uint32 _entityId, uint8 flags)
    {
        bytes25 configBytes = ValidationConfig.unwrap(config);
        _module = address(bytes20(configBytes));
        _entityId = uint32(bytes4(configBytes << 160));
        flags = uint8(configBytes[24]);
    }

    function unpack(ValidationConfig config) internal pure returns (ModuleEntity _validationFunction, uint8 flags) {
        bytes25 configBytes = ValidationConfig.unwrap(config);
        _validationFunction = ModuleEntity.wrap(bytes24(configBytes));
        flags = uint8(configBytes[24]);
    }

    function module(ValidationConfig config) internal pure returns (address) {
        return address(bytes20(ValidationConfig.unwrap(config)));
    }

    function entityId(ValidationConfig config) internal pure returns (uint32) {
        return uint32(bytes4(ValidationConfig.unwrap(config) << 160));
    }

    function moduleEntity(ValidationConfig config) internal pure returns (ModuleEntity) {
        return ModuleEntity.wrap(bytes24(ValidationConfig.unwrap(config)));
    }

    function isGlobal(ValidationConfig config) internal pure returns (bool) {
        return ValidationConfig.unwrap(config) & _VALIDATION_FLAG_IS_GLOBAL != 0;
    }

    function isGlobal(uint8 flags) internal pure returns (bool) {
        // 00000100
        return flags & 0x04 != 0;
    }

    function isSignatureValidation(ValidationConfig config) internal pure returns (bool) {
        return ValidationConfig.unwrap(config) & _VALIDATION_FLAG_IS_SIGNATURE != 0;
    }

    function isSignatureValidation(uint8 flags) internal pure returns (bool) {
        // 00000010
        return flags & 0x02 != 0;
    }

    function isUserOpValidation(ValidationConfig config) internal pure returns (bool) {
        return ValidationConfig.unwrap(config) & _VALIDATION_FLAG_IS_USER_OP != 0;
    }

    function isUserOpValidation(uint8 flags) internal pure returns (bool) {
        // 00000001
        return flags & 0x01 != 0;
    }
}
