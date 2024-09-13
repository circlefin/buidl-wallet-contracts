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

/**
 * @dev Returned data from validateUserOp.
 * validateUserOp returns a uint256, with is created by `_packedValidationData` and parsed by `_parseValidationData`
 * @param validAfter - this UserOp is valid only after this timestamp.
 * @param validaUntil - this UserOp is valid only up to this timestamp.
 * @param authorizer - address(0) - the account validated the signature by itself.
 *                     address(1) - the account failed to validate the signature.
 *                     otherwise - this is an address of a signature aggregator that must be used to validate the
 * signature.
 */
struct ValidationData {
    uint48 validAfter;
    uint48 validUntil;
    address authorizer;
}

struct AddressDLL {
    mapping(address => address) next;
    mapping(address => address) prev;
    uint256 count;
}

struct Bytes4DLL {
    mapping(bytes4 => bytes4) next;
    mapping(bytes4 => bytes4) prev;
    uint256 count;
}

struct Bytes32DLL {
    mapping(bytes32 => bytes32) next;
    mapping(bytes32 => bytes32) prev;
    uint256 count;
}
