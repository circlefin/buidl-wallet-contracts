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

import {ENTRY_POINT, PLUGIN_MANAGER_ADDRESS, UPGRADABLE_MSCA_FACTORY_ADDRESS} from "./000_ContractAddress.sol";
import {Script, console} from "forge-std/src/Script.sol";

contract DeployUpgradableMSCAFactoryScript is Script {
    address internal constant PLUGIN_MANAGER = PLUGIN_MANAGER_ADDRESS;
    address payable internal constant EXPECTED_FACTORY_ADDRESS = payable(UPGRADABLE_MSCA_FACTORY_ADDRESS);
    address internal owner = vm.envAddress("MSCA_FACTORY_OWNER_ADDRESS");

    function run() public {
        address entryPoint = ENTRY_POINT;
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");

        vm.startBroadcast(key);

        UpgradableMSCAFactory factory;
        if (EXPECTED_FACTORY_ADDRESS.code.length == 0) {
            factory = new UpgradableMSCAFactory{salt: 0}(owner, entryPoint, PLUGIN_MANAGER);
            console.log("Deployed new factory at address: %s", address(factory));
        } else {
            factory = UpgradableMSCAFactory(EXPECTED_FACTORY_ADDRESS);
            console.log("Found existing factory at expected address: %s", address(factory));
        }
        console.log("Account implementation address: %s", address(factory.ACCOUNT_IMPLEMENTATION()));
        vm.stopBroadcast();
    }
}
