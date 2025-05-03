/*
 * Copyright 2025 Circle Internet Group, Inc. All rights reserved.

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

address constant ENTRY_POINT = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
address constant DETERMINISTIC_DEPLOYMENT_FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

// Use address(0) if unknown or deploying a new version of a contract.
address constant PLUGIN_MANAGER_ADDRESS = 0xc93D6559Fe4dB59742751A857d11a04861a50CCC;
address constant SINGLEOWNER_MSCA_FACTORY_ADDRESS = 0xf61023061ed45fa9eAC4D2670649cE1FD37ce536;
address constant COLD_STORAGE_ADDRESS_BOOK_PLUGIN_ADDRESS = 0x11BACb0F0C9D04A28A2043b54c0C3C2CE15F0Af4;
address constant SPONSOR_PAYMASTER_TEMP_OWNER = 0x7e99C7725463A858C34D0Fd69a09B11fd75087CC;
address constant SPONSOR_PAYMASTER_TEMP_SIGNER = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
address constant SPONSOR_PAYMASTER_IMPL_ADDRESS = 0x26f77C6455518CAF29A5414004C5A2Ef441228b1;
address constant SPONSOR_PAYMASTER_INTERNAL_ADDRESS = 0x67aC303faB3A9507Ac48fD5B5EE176c4E39aE98C;
address constant SPONSOR_PAYMASTER_ADDRESS = 0x7ceA357B5AC0639F89F9e378a1f03Aa5005C0a25;

library Constants {
    function getChains() internal pure returns (string[12] memory) {
        return [
            "mainnet",
            "sepolia",
            "polygon",
            "amoy",
            "arbitrum",
            "arb-sepolia",
            "uni-sepolia",
            "unichain",
            "base-sepolia",
            "base",
            "op-sepolia",
            "op"
        ];
    }

    // A list of chains that need to run setup work after deployment. Please adjust the list based on the chain
    // expansion needs.
    function getChainsForSetup() internal pure returns (string[4] memory) {
        return ["base-sepolia", "base", "op-sepolia", "op"];
    }
}
