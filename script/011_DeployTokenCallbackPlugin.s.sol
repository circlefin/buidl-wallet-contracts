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

import {DefaultTokenCallbackPlugin} from "../src/msca/6900/v0.7/plugins/v1_0_0/utility/DefaultTokenCallbackPlugin.sol";
import {Script, console} from "forge-std/src/Script.sol";

contract DeployTokenCallbackPluginScript is Script {
    // Safety check to avoid accidental deploy. Change address to 0x0 if you want to deploy a new version.
    address payable EXPECTED_PLUGIN_ADDRESS = payable(vm.envAddress("DEFAULT_TOKEN_CALLBACK_PLUGIN_ADDRESS"));

    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        DefaultTokenCallbackPlugin plugin;
        if (EXPECTED_PLUGIN_ADDRESS.code.length == 0) {
            plugin = new DefaultTokenCallbackPlugin{salt: 0}();
        } else {
            plugin = DefaultTokenCallbackPlugin(EXPECTED_PLUGIN_ADDRESS);
        }
        console.log("Plugin address: %s", address(plugin));
        console.log("Default token callback manifest hash: ");
        console.logBytes32(keccak256(abi.encode(plugin.pluginManifest())));
        vm.stopBroadcast();
    }
}
