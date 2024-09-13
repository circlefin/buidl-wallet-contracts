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
import "../src/account/v1/factory/ECDSAAccountFactory.sol";

/// @dev We actually still used hardhat deployment for this legacy contract. This script is more for convenience
/// purpose.
contract DeployECDSAAccountFactoryScript is Script {
    // TODO: replace this with officially deployed address
    address payable constant EXPECTED_FACTORY_ADDRESS = payable(address(0x39c09e93D074782C5ffc45da27910c14C628a183));

    function run() public {
        address entryPoint = vm.envAddress("ENTRY_POINT");
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        ECDSAAccountFactory factory;
        if (EXPECTED_FACTORY_ADDRESS.code.length == 0) {
            factory = new ECDSAAccountFactory{salt: 0}(IEntryPoint(entryPoint));
        } else {
            factory = ECDSAAccountFactory(EXPECTED_FACTORY_ADDRESS);
        }
        console.log("Factory address: %s", address(factory));
        console.log("Account implementation address: %s", address(factory.accountImplementation()));
        vm.stopBroadcast();
    }
}
