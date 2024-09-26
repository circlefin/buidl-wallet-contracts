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

import {PluginManager} from "../src/msca/6900/v0.7/managers/PluginManager.sol";
import {Script, console} from "forge-std/src/Script.sol";

contract DeployPluginManagerScript is Script {
    address EXPECTED_PLUGIN_MANAGER = vm.envAddress("PLUGIN_MANAGER_ADDRESS");

    function run() public {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");

        vm.startBroadcast(deployerKey);

        PluginManager pluginManager;
        if (EXPECTED_PLUGIN_MANAGER.code.length == 0) {
            pluginManager = new PluginManager{salt: 0}();
            console.log("New plugin manager address: %s", address(pluginManager));
        } else {
            pluginManager = PluginManager(EXPECTED_PLUGIN_MANAGER);
            console.log("Found existing plugin manager at expected address: %s", address(pluginManager));
        }
        vm.stopBroadcast();
    }
}
