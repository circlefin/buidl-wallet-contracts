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

/// @notice Interface for ERC6900 modular smart contract account or module compatible with ERC1271 standard signature
/// validation.
/// @notice The implementation of this interface is recommended to support
/// [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271) signature
/// validation for both validating the signature on user operations and in
/// exposing its own `isValidSignature` method. This only works when the signer of
/// modular account also supports ERC-1271.
interface IERC712Compliant {
    /// @notice Wraps a replay safe hash in an EIP-712 envelope to prevent cross-account replay attacks.
    /// @param account SCA to build the message hash for.
    /// @param hash Message that should be hashed.
    /// @return Replay safe message hash.
    function getReplaySafeMessageHash(address account, bytes32 hash) external view returns (bytes32);
}
