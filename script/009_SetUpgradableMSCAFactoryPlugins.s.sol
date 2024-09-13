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

import {console, Script} from "forge-std/src/Script.sol";
import {UpgradableMSCAFactory} from "../src/msca/6900/v0.7/factories/UpgradableMSCAFactory.sol";

contract SetUpgradableMSCAFactoryPlugins is Script {
    address payable constant EXPECTED_FACTORY_ADDRESS = payable(address(0x95abd14795D32A4e636e976Ff31dC634Ad33A09E));

    function run() public {
        uint256 key = vm.envUint("MSCA_FACTORY_OWNER_PRIVATE_KEY");

        // Initialize setPlugins exec call data
        uint256 numPlugins = 1;
        address[] memory plugins = new address[](numPlugins);
        bool[] memory pluginPermissions = new bool[](numPlugins);

        plugins[0] = 0x5FC0e9da759812cd862625bF6d3EA02EB0666160; // WeightedWebauthnMultisigPlugin address
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
        console.log("Checking if first plugin is allowed: ", factory.isPluginAllowed(plugins[0]));
        vm.stopBroadcast();
    }
}
