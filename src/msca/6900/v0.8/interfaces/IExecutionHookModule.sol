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

import {IModule} from "./IModule.sol";

/**
 * @dev Implements https://eips.ethereum.org/EIPS/eip-6900. Modules must implement this interface to support module
 * management and interactions with MSCAs.
 */
interface IExecutionHookModule is IModule {
    /// @notice Run the pre execution hook specified by the `entityId`.
    /// @dev To indicate the entire call should revert, the function MUST revert.
    /// @param entityId An identifier that routes the call to different internal implementations, should there
    /// be more than one.
    /// @param sender The caller address.
    /// @param value The call value.
    /// @param data The calldata sent. For `executeUserOp` calls, hook modules should receive the full msg.data.
    /// @return Context to pass to a post execution hook, if present. An empty bytes array MAY be returned.
    function preExecutionHook(uint32 entityId, address sender, uint256 value, bytes calldata data)
        external
        returns (bytes memory);

    /// @notice Run the post execution hook specified by the `entityId`.
    /// @dev To indicate the entire call should revert, the function MUST revert.
    /// @param entityId An identifier that routes the call to different internal implementations, should there
    /// be more than one.
    /// @param preExecHookData The context returned by its associated pre execution hook.
    function postExecutionHook(uint32 entityId, bytes calldata preExecHookData) external;
}
