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

import {UpgradableMSCAFactory} from "../../src/msca/6900/v0.7/factories/UpgradableMSCAFactory.sol";

import {UPGRADABLE_MSCA_FACTORY_ADDRESS} from "./100_Constants.sol";
import {Script, console} from "forge-std/src/Script.sol";

contract StakeUpgradableMSCAFactory is Script {
    address payable internal constant EXPECTED_FACTORY_ADDRESS = payable(UPGRADABLE_MSCA_FACTORY_ADDRESS);
    string[8] internal CHAINS = ["mainnet", "sepolia", "polygon", "amoy", "arbitrum", "arb-sepolia", "uni-sepolia", "unichain"];

    // Configure stake (using minimums from https://docs.alchemy.com/docs/bundler-services#minimum-stake)
    uint256[8] internal STAKE_VALUE = [0.1 ether, 0.1 ether, 100 ether, 10 ether, 0.1 ether, 0.1 ether, 0.1 ether, 0.1 ether];

    function run() public {
        uint256 key = vm.envUint("MSCA_FACTORY_OWNER_PRIVATE_KEY");

        uint32 unstakeDelaySec = 1 * 24 * 60 * 60; // 1 day

        // Set plugins for factory
        for (uint256 i = 0; i < CHAINS.length; i++) {
            vm.createSelectFork(CHAINS[i]);
            vm.startBroadcast(key);

            // Ensure factory has been deployed
            if (EXPECTED_FACTORY_ADDRESS.code.length == 0) {
                console.log("Warning: unable to find factory at expected address '%s'", EXPECTED_FACTORY_ADDRESS);
                return;
            }
            UpgradableMSCAFactory factory = UpgradableMSCAFactory(EXPECTED_FACTORY_ADDRESS);
            console.log("Found existing factory at expected address: %s", address(factory));

            factory.addStake{value: STAKE_VALUE[i]}(unstakeDelaySec);
            vm.stopBroadcast();
        }
    }
}
