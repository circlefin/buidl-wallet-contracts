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

import {Script} from "forge-std/src/Script.sol";
import {console} from "forge-std/src/console.sol";
import {AddressBookPlugin} from "../src/msca/6900/v0.7/plugins/v1_0_0/addressbook/AddressBookPlugin.sol";

contract DeployAddressBookPluginScript is Script {
    // TODO: replace this with officially deployed address
    address payable constant EXPECTED_PLUGIN_ADDRESS = payable(address(0x1E0689ae0171CcFbE9E7C7491B1eb09e0D5b7103));

    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        AddressBookPlugin plugin;
        if (EXPECTED_PLUGIN_ADDRESS.code.length == 0) {
            plugin = new AddressBookPlugin{salt: 0}();
        } else {
            plugin = AddressBookPlugin(EXPECTED_PLUGIN_ADDRESS);
        }
        console.log("Plugin address: %s", address(plugin));
        console.log("Address book manifest hash: ");
        console.logBytes32(keccak256(abi.encode(plugin.pluginManifest())));
        vm.stopBroadcast();
    }
}
