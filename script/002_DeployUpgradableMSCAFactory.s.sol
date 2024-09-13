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

contract DeployUpgradableMSCAFactoryScript is Script {
    address constant PLUGIN_MANAGER = 0x5c2099d54979B1F4c84eB5d3fc50041a78aE4E15;
    address constant OWNER = 0x0166EA90E565476f13c6a0D25ED2C35599E58785;
    address payable constant EXPECTED_FACTORY_ADDRESS = payable(address(0x95abd14795D32A4e636e976Ff31dC634Ad33A09E));

    function run() public {
        address entryPoint = vm.envAddress("ENTRY_POINT");
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");

        vm.startBroadcast(key);

        UpgradableMSCAFactory factory;
        if (EXPECTED_FACTORY_ADDRESS.code.length == 0) {
            factory = new UpgradableMSCAFactory{salt: 0}(OWNER, entryPoint, PLUGIN_MANAGER);
            console.log("Deployed new factory at address: %s", address(factory));
        } else {
            factory = UpgradableMSCAFactory(EXPECTED_FACTORY_ADDRESS);
            console.log("Found existing factory at expected address: %s", address(factory));
        }
        console.log("Account implementation address: %s", address(factory.accountImplementation()));
        vm.stopBroadcast();
    }
}
