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

import {WeightedWebauthnMultisigPlugin} from
    "../../src/msca/6900/v0.7/plugins/v1_0_0/multisig/WeightedWebauthnMultisigPlugin.sol";
import {
    Constants,
    DETERMINISTIC_DEPLOYMENT_FACTORY,
    ENTRY_POINT,
    WEIGHTED_MULTISIG_PLUGIN_ADDRESS
} from "./100_Constants.sol";
import {DeployFailed} from "./Errors.sol";
import {Script, console} from "forge-std/src/Script.sol";

contract DeployWeightedWebauthnMultiSigPluginScript is Script {
    address payable internal constant EXPECTED_PLUGIN_ADDRESS = payable(WEIGHTED_MULTISIG_PLUGIN_ADDRESS);

    function run() public {
        address entryPoint = ENTRY_POINT;
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");

        string[12] memory chains = Constants.getChains();
        for (uint256 i = 0; i < chains.length; i++) {
            vm.createSelectFork(chains[i]);
            vm.startBroadcast(key);

            WeightedWebauthnMultisigPlugin plugin;
            if (EXPECTED_PLUGIN_ADDRESS.code.length == 0) {
                string memory root = vm.projectRoot();
                string memory path =
                    string.concat(root, "/script/bytecode-deploy/build-output/WeightedWebauthnMultiSigPlugin.json");
                string memory json = vm.readFile(path);

                bytes32 salt = bytes32(0x2cc3c603d96a0edab755ab092bf8e79f8d8934cc586d021ddd53be945606e535);
                bytes memory creationCode = abi.decode(vm.parseJson(json, ".bytecode.object"), (bytes));
                bytes memory args = abi.encode(entryPoint);

                bytes memory callData = abi.encodePacked(salt, creationCode, args);

                // solhint-disable-next-line avoid-low-level-calls
                (bool success, bytes memory result) = DETERMINISTIC_DEPLOYMENT_FACTORY.call(callData);

                if (!success) {
                    revert DeployFailed();
                }

                plugin = WeightedWebauthnMultisigPlugin(address(bytes20(result)));
                console.log("Deployed WeightedWebauthnMultiSigPlugin at address: %s", address(bytes20(result)));
            } else {
                plugin = WeightedWebauthnMultisigPlugin(EXPECTED_PLUGIN_ADDRESS);
                console.log(
                    "Found existing WeightedWebauthnMultiSigPlugin at expected address: %s", EXPECTED_PLUGIN_ADDRESS
                );
            }

            // Log plugin manifest hash
            console.log("WeightedWebauthnMultisigPlugin manifest hash: ");
            console.logBytes32(keccak256(abi.encode(plugin.pluginManifest())));
            vm.stopBroadcast();
        }
    }
}
