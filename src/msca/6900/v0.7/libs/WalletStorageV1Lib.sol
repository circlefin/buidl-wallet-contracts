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
import {ExecutionDetail, PermittedExternalCall, PluginDetail} from "../common/Structs.sol";

/// @dev The same storage will be used for v1.x.y of MSCAs.
library WalletStorageV1Lib {
    // @notice On 12/16/2024, storage was aligned to 256 as a potential optimization in anticipation of gas schedule
    // changes following the Verkle state tree migration. This adjustment accounts for scenarios where groups
    // of 256 storage slots may become warm simultaneously and will only apply to newly deployed accounts.
    // For more details, please refer to https://eips.ethereum.org/EIPS/eip-7201.
    // Old value: 0xc6a0cc20c824c4eecc4b0fbb7fb297d07492a7bd12c83d4fa4d27b4249f9bfc8, which is calculated by
    // keccak256(abi.encode(uint256(keccak256(abi.encode("circle.msca.v1.storage"))) - 1));
    // New value:
    // 1. id = "circle.msca.v1.storage"
    // 2. keccak256(abi.encode(uint256(keccak256(id)) - 1)) & ~bytes32(uint256(0xff))
    bytes32 internal constant WALLET_STORAGE_SLOT = 0x1f5beaddce7d7c52c0db456127db41c33d65f252d3a09b925e817276761a6a00;

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
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            walletStorage.slot := WALLET_STORAGE_SLOT
        }
    }
}
