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

import {
    Constants,
    ENTRY_POINT_V06,
    PLUGIN_MANAGER_EP06_ADDRESS,
    SINGLEOWNER_MSCA_FACTORY_EP06_ADDRESS,
    DETERMINISTIC_DEPLOYMENT_FACTORY
} from "./100_Constants.sol";
import {DeployFailed} from "./Errors.sol";
import {Script, console} from "forge-std/src/Script.sol";

contract DeployPluginManagerScript is Script {
    address internal constant PLUGIN_MANAGER_EP06 = PLUGIN_MANAGER_EP06_ADDRESS;
    address internal constant EXPECTED_SINGLEOWNER_MSCA_FACTORY_EP06_ADDRESS = SINGLEOWNER_MSCA_FACTORY_EP06_ADDRESS;
    function run() public {
        address entryPoint = ENTRY_POINT_V06;

        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        string[12] memory chains = Constants.getChains();
        for (uint256 i = 0; i < chains.length; i++) {
            vm.createSelectFork(chains[i]);
            vm.startBroadcast(key);

            if (EXPECTED_SINGLEOWNER_MSCA_FACTORY_EP06_ADDRESS.code.length == 0) {
                string memory root = vm.projectRoot();
                string memory path = string.concat(root, "/script/bytecode-deploy/build-output/SingleOwnerMSCAFactoryEPv06.json");
                string memory json = vm.readFile(path);

                bytes32 salt = bytes32(0);
                bytes memory creationCode = abi.decode(vm.parseJson(json, ".bytecode.object"), (bytes));
                bytes memory args = abi.encode( entryPoint, PLUGIN_MANAGER_EP06);
                bytes memory callData = abi.encodePacked(salt, creationCode, args);

                // solhint-disable-next-line avoid-low-level-calls
                (bool success, bytes memory result) = DETERMINISTIC_DEPLOYMENT_FACTORY.call(callData);

                if (!success) {
                    revert DeployFailed();
                }

                console.log("Deployed SingleOwnerMSCAFactoryEPv06 at address: %s on %s", address(bytes20(result)), chains[i]);
            } else {
                console.log("Found existing SingleOwnerMSCAFactoryEPv06 at expected address: %s on %s", EXPECTED_SINGLEOWNER_MSCA_FACTORY_EP06_ADDRESS, chains[i]);
            }
            vm.stopBroadcast();
        }
    }
}
