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

import {ExecutionStorage, ValidationStorage} from "../common/Structs.sol";
import {ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

/// @dev The same storage will be used for ERC6900 v0.8 MSCAs.
library WalletStorageLib {
    // keccak256 hash of "circle.msca.v0_8.storage" subtracted by 1
    bytes32 internal constant WALLET_STORAGE_SLOT = 0x45b8c59e88d59f48fa992cc87612124331f3e8b18f76fa4c146925e98c37c228;

    struct Layout {
        // list of ERC-165 interfaceIds to add to account to support introspection checks
        // interfaceId => counter
        mapping(bytes4 => uint256) supportedInterfaces;
        // find module or native function execution detail by selector
        mapping(bytes4 => ExecutionStorage) executionStorage;
        mapping(ModuleEntity validationFunction => ValidationStorage) validationStorage;
        /// indicates that the contract has been initialized
        uint8 initialized;
        /// indicates that the contract is in the process of being initialized
        bool initializing;
    }

    /**
     * @dev Function to read structured wallet storage.
     */
    function getLayout() internal pure returns (Layout storage walletStorage) {
        assembly ("memory-safe") {
            walletStorage.slot := WALLET_STORAGE_SLOT
        }
    }
}
