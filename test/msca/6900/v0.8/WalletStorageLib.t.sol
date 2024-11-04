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

import {TestUtils} from "../../../util/TestUtils.sol";
import {console} from "forge-std/src/console.sol";

contract WalletStorageLibTest is TestUtils {
    function testWalletStorageSlot() public pure {
        bytes32 hash = keccak256(abi.encode(uint256(keccak256(abi.encode("circle.msca.v0_8.storage"))) - 1));
        console.logString("hash: ");
        console.logBytes32(hash);
        assertEq(hash, 0x45b8c59e88d59f48fa992cc87612124331f3e8b18f76fa4c146925e98c37c228);
    }
}
