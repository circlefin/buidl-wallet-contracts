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

import {DETERMINISTIC_DEPLOYMENT_FACTORY, COLD_STORAGE_ADDRESS_BOOK_PLUGIN_ADDRESS} from "./100_Constants.sol";
import {ColdStorageAddressBookPlugin} from "../../src/msca/6900/v0.7/plugins/v1_0_0/addressbook/ColdStorageAddressBookPlugin.sol";
import {DeployFailed} from "./Errors.sol";
import {Script, console} from "forge-std/src/Script.sol";

contract DeployColdStorageAddressBookScript is Script {
    address payable internal constant EXPECTED_PLUGIN_ADDRESS = payable(COLD_STORAGE_ADDRESS_BOOK_PLUGIN_ADDRESS);
    string[8] internal CHAINS = ["mainnet", "sepolia", "polygon", "amoy", "arbitrum", "arb-sepolia", "uni-sepolia", "unichain"];

    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");

        for (uint256 i = 0; i < CHAINS.length; i++) {
            vm.createSelectFork(CHAINS[i]);
            vm.startBroadcast(key);

            ColdStorageAddressBookPlugin plugin;
            if (EXPECTED_PLUGIN_ADDRESS.code.length == 0) {
                string memory root = vm.projectRoot();
                string memory path = string.concat(root, "/script/bytecode-deploy/build-output/ColdStorageAddressBookPlugin.json");
                string memory json = vm.readFile(path);

                bytes32 salt = bytes32(0x36fdaa1ba01cead4cf7fd9405035fc259bb463d9411d619a7deb31d13a2bd89f);
                bytes memory creationCode = abi.decode(vm.parseJson(json, ".bytecode.object"), (bytes));

                bytes memory callData = abi.encodePacked(salt, creationCode);
                (bool success, bytes memory result) = DETERMINISTIC_DEPLOYMENT_FACTORY.call(callData);

                if (!success) {
                    revert DeployFailed();
                }

                plugin = ColdStorageAddressBookPlugin(address(bytes20(result)));
                console.log("Deployed ColdStorageAddressBookPlugin at address: %s", address(bytes20(result)));
            } else {
                plugin = ColdStorageAddressBookPlugin(EXPECTED_PLUGIN_ADDRESS);
                console.log("Found existing ColdStorageAddressBookPlugin at expected address: %s", EXPECTED_PLUGIN_ADDRESS);
            }

            // Log plugin manifest hash
            console.log("ColdStorageAddressBookPlugin manifest hash: ");
            console.logBytes32(keccak256(abi.encode(plugin.pluginManifest())));
            vm.stopBroadcast();
        }
    }
}
