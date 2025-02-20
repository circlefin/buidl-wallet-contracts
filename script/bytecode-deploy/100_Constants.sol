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

address constant ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
address constant DETERMINISTIC_DEPLOYMENT_FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

// Use address(0) if unknown or deploying a new version of a contract.
address constant PLUGIN_MANAGER_ADDRESS = 0x00000005e69188224e4dEeF607801916DC0936d5;
address constant UPGRADABLE_MSCA_FACTORY_ADDRESS = 0x0000000DF7E6c9Dc387cAFc5eCBfa6c3a6179AdD;
address constant COLD_STORAGE_ADDRESS_BOOK_PLUGIN_ADDRESS = 0x0000000d81083B16EA76dfab46B0315B0eDBF3d0;
address constant WEIGHTED_MULTISIG_PLUGIN_ADDRESS = 0x0000000C984AFf541D6cE86Bb697e68ec57873C8;

library Constants {
    function getChains() internal pure returns (string[8] memory) {
        return ["mainnet", "sepolia", "polygon", "amoy", "arbitrum", "arb-sepolia", "uni-sepolia", "unichain"];
    }
}
