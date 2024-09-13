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

import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IPlugin} from "./IPlugin.sol";

/**
 * @dev Implements https://eips.ethereum.org/EIPS/eip-6900. Plugins must implement this interface to support plugin
 * management and interactions with MSCAs.
 */
interface IValidationHook is IPlugin {
    /// @notice Run the pre user operation validation hook specified by the `entityId`.
    /// @dev Pre user operation validation hooks MUST NOT return an authorizer value other than 0 or 1.
    /// @param entityId An identifier that routes the call to different internal implementations, should there
    /// be more than one.
    /// @param userOp The user operation.
    /// @param userOpHash The user operation hash.
    /// @return Packed validation data for validAfter (6 bytes), validUntil (6 bytes), and authorizer (20 bytes).
    function preUserOpValidationHook(uint32 entityId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        returns (uint256);

    /// @notice Run the pre runtime validation hook specified by the `entityId`.
    /// @dev To indicate the entire call should revert, the function MUST revert.
    /// @param entityId An identifier that routes the call to different internal implementations, should there
    /// be more than one.
    /// @param sender The caller address.
    /// @param value The call value.
    /// @param data The calldata sent.
    function preRuntimeValidationHook(
        uint32 entityId,
        address sender,
        uint256 value,
        bytes calldata data,
        bytes calldata authorization
    ) external;
}
