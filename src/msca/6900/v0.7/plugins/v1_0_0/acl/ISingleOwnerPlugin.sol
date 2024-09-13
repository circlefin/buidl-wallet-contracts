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
 * @dev Interface for SingleOwnerPlugin. Other plugin can import type(ISingleOwnerPlugin).interfaceId as dependency.
 *      Single owner plugin which is forked from OZ's Ownable. This plugin allows MSCA to be owned by an EOA or another
 * smart contract (which supports 1271).
 *      ERC4337's bundler validation rules (canonical mempool) forbid the opcodes with different outputs between the
 * simulation and execution.
 *      Meanwhile, bundler validation rules enforce storage access rules that allows the entity to use sender's
 * associated storage.
 *      When staked, an entity is also allowed to use its own associated storage.
 *      If the owner is a smart contract, the validation should not use any banned opcodes and violate any storage
 * rules.
 *      If the owner uses a storage slot not associated with itself, then the validation would fail.
 */
interface ISingleOwnerPlugin {
    // function id to plugin itself
    enum FunctionId {
        RUNTIME_VALIDATION_OWNER_OR_SELF,
        USER_OP_VALIDATION_OWNER
    }

    event OwnershipTransferred(address indexed account, address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current msg.sender.
     */
    function transferOwnership(address newOwner) external;

    /**
     * @dev Returns the address of the current msg.sender.
     */
    function getOwner() external view returns (address);

    /**
     * @dev Returns the address of the account.
     */
    function getOwnerOf(address account) external view returns (address);
}
