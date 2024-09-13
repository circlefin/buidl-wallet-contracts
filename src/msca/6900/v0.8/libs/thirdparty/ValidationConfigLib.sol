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

// Validation config is a packed representation of a validation function and flags for its configuration.
// Layout:
// 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA________________________ // Address
// 0x________________________________________BBBBBBBB________________ // Entity ID
// 0x________________________________________________CC______________ // isGlobal
// 0x__________________________________________________DD____________ // isSignatureValidation
// 0x____________________________________________________000000000000 // unused
// TODO: add tests
// @notice Forked from 6900 reference impl with some modifications.
library ValidationConfigLib {
    function pack(ModuleEntity _validationFunction, bool _isGlobal, bool _isSignatureValidation)
        internal
        pure
        returns (ValidationConfig)
    {
        return ValidationConfig.wrap(
            bytes26(
                bytes26(ModuleEntity.unwrap(_validationFunction))
                // isGlobal flag stored in the 25th byte
                | bytes26(bytes32(_isGlobal ? uint256(1) << 56 : 0))
                // isSignatureValidation flag stored in the 26th byte
                | bytes26(bytes32(_isSignatureValidation ? uint256(1) << 48 : 0))
            )
        );
    }

    function pack(address _plugin, uint32 _entityId, bool _isGlobal, bool _isSignatureValidation)
        internal
        pure
        returns (ValidationConfig)
    {
        return ValidationConfig.wrap(
            bytes26(
                // plugin address stored in the first 20 bytes
                bytes26(bytes20(_plugin))
                // entityId stored in the 21st - 24th byte
                | bytes26(bytes24(uint192(_entityId)))
                // isGlobal flag stored in the 25th byte
                | bytes26(bytes32(_isGlobal ? uint256(1) << 56 : 0))
                // isSignatureValidation flag stored in the 26th byte
                | bytes26(bytes32(_isSignatureValidation ? uint256(1) << 48 : 0))
            )
        );
    }

    function unpackUnderlying(ValidationConfig config)
        internal
        pure
        returns (address _plugin, uint32 _entityId, bool _isGlobal, bool _isSignatureValidation)
    {
        bytes26 configBytes = ValidationConfig.unwrap(config);
        _plugin = address(bytes20(configBytes));
        _entityId = uint32(bytes4(configBytes << 160));
        _isGlobal = uint8(configBytes[24]) == 1;
        _isSignatureValidation = uint8(configBytes[25]) == 1;
    }

    function unpack(ValidationConfig config)
        internal
        pure
        returns (ModuleEntity _validationFunction, bool _isGlobal, bool _isSignatureValidation)
    {
        bytes26 configBytes = ValidationConfig.unwrap(config);
        _validationFunction = ModuleEntity.wrap(bytes24(configBytes));
        _isGlobal = uint8(configBytes[24]) == 1;
        _isSignatureValidation = uint8(configBytes[25]) == 1;
    }

    function plugin(ValidationConfig config) internal pure returns (address) {
        return address(bytes20(ValidationConfig.unwrap(config)));
    }

    function entityId(ValidationConfig config) internal pure returns (uint32) {
        return uint32(bytes4(ValidationConfig.unwrap(config) << 160));
    }

    function moduleEntity(ValidationConfig config) internal pure returns (ModuleEntity) {
        return ModuleEntity.wrap(bytes24(ValidationConfig.unwrap(config)));
    }

    function isGlobal(ValidationConfig config) internal pure returns (bool) {
        return uint8(ValidationConfig.unwrap(config)[24]) == 1;
    }

    function isSignatureValidation(ValidationConfig config) internal pure returns (bool) {
        return uint8(ValidationConfig.unwrap(config)[25]) == 1;
    }
}
