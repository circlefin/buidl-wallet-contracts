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

import {SponsorPaymaster} from "../src/paymaster/v1/permissioned/SponsorPaymaster.sol";

import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Script} from "forge-std/src/Script.sol";
import {console} from "forge-std/src/console.sol";

contract DeploySponsorPaymaster is Script {
    address payable constant EXPECTED_PAYMASTER_ADDRESS = payable(address(0x36058Cc257967db1912FC276F9CBEC072CD572cb));
    address payable constant EXPECTED_PAYMASTER_PROXY_ADDRESS =
        payable(address(0x03dF76C8c30A88f424CF3CBBC36A1Ca02763103b));

    function run() public {
        address entryPoint = vm.envAddress("ENTRY_POINT");

        vm.startBroadcast(vm.envUint("DEPLOYER_PRIVATE_KEY"));

        SponsorPaymaster paymaster;
        if (EXPECTED_PAYMASTER_ADDRESS.code.length == 0) {
            paymaster = new SponsorPaymaster{salt: 0}(IEntryPoint(entryPoint));
        } else {
            paymaster = SponsorPaymaster(EXPECTED_PAYMASTER_ADDRESS);
        }
        console.log("Paymaster address: %s", address(paymaster));

        ERC1967Proxy proxy;
        if (EXPECTED_PAYMASTER_PROXY_ADDRESS.code.length == 0) {
            address[] memory verifySigners = new address[](0);
            address paymasterOwner = vm.envAddress("PAYMASTER_OWNER");
            bytes memory data = abi.encodeCall(paymaster.initialize, (paymasterOwner, verifySigners));

            proxy = new ERC1967Proxy{salt: 0}(address(paymaster), data);
        } else {
            proxy = ERC1967Proxy(EXPECTED_PAYMASTER_PROXY_ADDRESS);
        }
        console.log("Proxy address: %s", address(proxy));

        vm.stopBroadcast();
    }
}
