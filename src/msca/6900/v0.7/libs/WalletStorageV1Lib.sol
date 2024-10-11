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

import {AddressDLL} from "../../shared/common/Structs.sol";
import "../common/Structs.sol";

/// @dev The same storage will be used for v1.x.y of MSCAs.
library WalletStorageV1Lib {
    // keccak256 hash of "circle.msca.v1.storage" subtracted by 1
    bytes32 internal constant WALLET_STORAGE_SLOT = 0xc6a0cc20c824c4eecc4b0fbb7fb297d07492a7bd12c83d4fa4d27b4249f9bfc8;

    struct Layout {
        // installed plugin addresses for quick query
        AddressDLL installedPlugins;
        // installed plugin details such as manifest, dependencies
        mapping(address => PluginDetail) pluginDetails;
        // permissions for executeFromPlugin into another plugin
        // callingPluginAddress => callingExecutionSelector => permittedOrNot
        mapping(address => mapping(bytes4 => bool)) permittedPluginCalls;
        // permissions for executeFromPluginExternal into external contract
        // callingPluginAddress => targetContractAddress => permission
        mapping(address => mapping(address => PermittedExternalCall)) permittedExternalCalls;
        // list of ERC-165 interfaceIds to add to account to support introspection checks
        // interfaceId => counter
        mapping(bytes4 => uint256) supportedInterfaces;
        // find plugin or native function execution detail by selector
        mapping(bytes4 => ExecutionDetail) executionDetails;
        /// indicates that the contract has been initialized
        uint8 initialized;
        /// indicates that the contract is in the process of being initialized
        bool initializing;
        // optional fields
        address owner;
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
