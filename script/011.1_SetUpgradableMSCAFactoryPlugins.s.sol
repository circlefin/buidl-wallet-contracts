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

import {UpgradableMSCAFactory} from "../src/msca/6900/v0.7/factories/UpgradableMSCAFactory.sol";
import {Script, console} from "forge-std/src/Script.sol";

// Only needed for MSCA v0.7 factories. This script is the same as 009_SetUpgradableMSCAFactoryPlugins.s.sol, but with the 
// default token callback plugin included).
contract SetUpgradableMSCAFactoryPlugins is Script {
    address payable EXPECTED_FACTORY_ADDRESS = payable(vm.envAddress("UPGRADABLE_MSCA_FACTORY_ADDRESS"));

    function run() public {
        uint256 key = vm.envUint("MSCA_FACTORY_OWNER_PRIVATE_KEY");

        // Initialize setPlugins exec call data
        uint256 numPlugins = 4;
        address[] memory plugins = new address[](numPlugins);
        bool[] memory pluginPermissions = new bool[](numPlugins);

        plugins[0] = vm.envAddress("SINGLE_OWNER_PLUGIN_ADDRESS");
        plugins[1] = vm.envAddress("COLD_STORAGE_ADDRESS_BOOK_PLUGIN_ADDRESS");
        plugins[2] = vm.envAddress("WEIGHTED_MULTISIG_PLUGIN_ADDRESS");
        plugins[3] = vm.envAddress("DEFAULT_TOKEN_CALLBACK_PLUGIN_ADDRESS");
        
        for (uint256 i = 0; i < numPlugins; i++) {
            pluginPermissions[i] = true;
        }

        // Ensure factory has been deployed
        if (EXPECTED_FACTORY_ADDRESS.code.length == 0) {
            console.log("Warning: unable to find factory at expected address '%s'", EXPECTED_FACTORY_ADDRESS);
            return;
        }
        UpgradableMSCAFactory factory = UpgradableMSCAFactory(EXPECTED_FACTORY_ADDRESS);
        console.log("Found existing factory at expected address: %s", address(factory));

        // Set plugins for factory
        vm.startBroadcast(key);
        factory.setPlugins(plugins, pluginPermissions);
        for (uint256 i = 0; i < numPlugins; i++) {
            console.log("Checking if plugin number", i, "is allowed:", factory.isPluginAllowed(plugins[0]));
        }
        vm.stopBroadcast();
    }
}
