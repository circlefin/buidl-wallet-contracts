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

import "forge-std/src/Script.sol";
import "../src/msca/6900/v0.7/plugins/v1_0_0/acl/SingleOwnerPlugin.sol";

contract DeploySingleOwnerPluginScript is Script {
    address payable constant EXPECTED_PLUGIN_ADDRESS = payable(address(0xFfC2440999EF1F84089Ca1418b673D4B9c089bBe));

    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        SingleOwnerPlugin plugin;
        if (EXPECTED_PLUGIN_ADDRESS.code.length == 0) {
            plugin = new SingleOwnerPlugin{salt: 0}();
        } else {
            plugin = SingleOwnerPlugin(EXPECTED_PLUGIN_ADDRESS);
        }
        console.log("Plugin address: %s", address(plugin));
        console.log("Single owner manifest hash: ");
        console.logBytes32(keccak256(abi.encode(plugin.pluginManifest())));
        vm.stopBroadcast();
    }
}
