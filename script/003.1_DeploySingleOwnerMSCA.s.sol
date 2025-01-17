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

import {SingleOwnerMSCA} from "../src/msca/6900/v0.7/account/semi/SingleOwnerMSCA.sol";
import {PluginManager} from "../src/msca/6900/v0.7/managers/PluginManager.sol";
import {ENTRY_POINT, PLUGIN_MANAGER_ADDRESS, SINGLE_OWNER_MSCA_ADDRESS} from "./000_ContractAddress.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {Script, console} from "forge-std/src/Script.sol";

contract DeploySingleOwnerMSCAScript is Script {
    address payable internal constant EXPECTED_ACCOUNT_ADDRESS = payable(SINGLE_OWNER_MSCA_ADDRESS);

    event AccountImplementationDeployed(
        address indexed accountImplementation, address entryPoint, address pluginManager
    );

    function run() public {
        address entryPoint = ENTRY_POINT;
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        SingleOwnerMSCA account;
        if (EXPECTED_ACCOUNT_ADDRESS.code.length == 0) {
            account = new SingleOwnerMSCA{salt: 0}(IEntryPoint(entryPoint), PluginManager(PLUGIN_MANAGER_ADDRESS));
            emit AccountImplementationDeployed(address(account), entryPoint, PLUGIN_MANAGER_ADDRESS);
            console.log("New single owner MSCA address: %s", address(account));
        } else {
            account = SingleOwnerMSCA(EXPECTED_ACCOUNT_ADDRESS);
            console.log("Found existing single owner MSCA at expected address: %s", address(account));
        }
        vm.stopBroadcast();
    }
}
