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

// ERC4337 constants

// return value in case of signature failure, with no time-range.
// equivalent to _packValidationData(true,0,0);
uint256 constant SIG_VALIDATION_FAILED = 1;
uint256 constant SIG_VALIDATION_SUCCEEDED = 0;

// sentinel values
// any values less than or equal to this will not be allowed in storage
bytes21 constant SENTINEL_BYTES21 = bytes21(0);
bytes23 constant SENTINEL_BYTES23 = bytes23(0);
bytes32 constant SENTINEL_BYTES32 = bytes32(0);

// empty or unset function reference
// we don't store the empty function reference
bytes21 constant EMPTY_FUNCTION_REFERENCE = bytes21(0);

// wallet constants
string constant WALLET_AUTHOR = "Circle Internet Financial";
string constant WALLET_VERSION_1 = "1.0.0";

// plugin constants
string constant PLUGIN_AUTHOR = "Circle Internet Financial";
string constant PLUGIN_VERSION_1 = "1.0.0";

// bytes4(keccak256("isValidSignature(bytes32,bytes)")
bytes4 constant EIP1271_VALID_SIGNATURE = 0x1626ba7e;
bytes4 constant EIP1271_INVALID_SIGNATURE = 0xffffffff;

// keccak256('')
bytes32 constant EMPTY_HASH = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;

uint256 constant ZERO = 0;

bytes32 constant ZERO_BYTES32 = bytes32(0);
bytes24 constant EMPTY_MODULE_ENTITY = bytes24(0);
