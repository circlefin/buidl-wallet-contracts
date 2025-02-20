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

/// @dev The same storage will be used for v2.x.y of MSCAs.
library WalletStorageV2Lib {
    // @notice On 12/16/2024, storage was aligned to 256 as a potential optimization in anticipation of gas schedule
    // changes following the Verkle state tree migration. This adjustment accounts for scenarios where groups
    // of 256 storage slots may become warm simultaneously and will only apply to newly deployed accounts.
    // For more details, please refer to https://eips.ethereum.org/EIPS/eip-7201.
    // 1. id = "circle.msca.v2.storage"
    // 2. keccak256(abi.encode(uint256(keccak256(id)) - 1)) & ~bytes32(uint256(0xff))
    bytes32 internal constant WALLET_STORAGE_SLOT = 0x1ffef775e8122370efaac4f28eeec94f03b0484eca026ee3ab713094c73f5d00;

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
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            walletStorage.slot := WALLET_STORAGE_SLOT
        }
    }
}
