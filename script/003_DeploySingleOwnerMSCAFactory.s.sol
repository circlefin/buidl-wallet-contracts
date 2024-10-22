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

import {SingleOwnerMSCAFactory} from "../src/msca/6900/v0.7/factories/semi/SingleOwnerMSCAFactory.sol";
import {ENTRY_POINT, PLUGIN_MANAGER_ADDRESS, SINGLE_OWNER_MSCA_FACTORY_ADDRESS} from "./000_ContractAddress.sol";
import {Script, console} from "forge-std/src/Script.sol";

contract DeploySingleOwnerMSCAFactoryScript is Script {
    address internal constant PLUGIN_MANAGER = PLUGIN_MANAGER_ADDRESS;
    address payable internal constant EXPECTED_FACTORY_ADDRESS =
        payable(SINGLE_OWNER_MSCA_FACTORY_ADDRESS);

    function run() public {
        address entryPoint = ENTRY_POINT;
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        SingleOwnerMSCAFactory factory;
        if (EXPECTED_FACTORY_ADDRESS.code.length == 0) {
            factory = new SingleOwnerMSCAFactory{salt: 0}(entryPoint, PLUGIN_MANAGER);
            console.log("New single owner MSCA factory address: %s", address(factory));
        } else {
            factory = SingleOwnerMSCAFactory(EXPECTED_FACTORY_ADDRESS);
            console.log("Found existing single owner MSCA factory at expected address: %s", address(factory));
        }
        console.log("Account implementation address: %s", address(factory.accountImplementation()));
        vm.stopBroadcast();
    }
}
