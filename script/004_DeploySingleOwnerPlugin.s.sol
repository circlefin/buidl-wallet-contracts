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

import "../src/msca/6900/v0.7/plugins/v1_0_0/acl/SingleOwnerPlugin.sol";

import {SINGLE_OWNER_PLUGIN_ADDRESS} from "./000_ContractAddress.sol";
import "forge-std/src/Script.sol";

contract DeploySingleOwnerPluginScript is Script {
    address payable EXPECTED_PLUGIN_ADDRESS = payable(SINGLE_OWNER_PLUGIN_ADDRESS);

    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);

        SingleOwnerPlugin plugin;

        // Deploy plugin contract if it doesn't exist at the expected address
        if (EXPECTED_PLUGIN_ADDRESS.code.length == 0) {
            plugin = new SingleOwnerPlugin{salt: 0}();
            console.log("New plugin contract deployed at address: %s", address(plugin));
        } else {
            plugin = SingleOwnerPlugin(EXPECTED_PLUGIN_ADDRESS);
            console.log("Found existing plugin at expected address: %s", address(plugin));
        }

        // Log plugin manifest hash
        console.log("Single owner plugin manifest hash: ");
        console.logBytes32(keccak256(abi.encode(plugin.pluginManifest())));

        vm.stopBroadcast();
    }
}
