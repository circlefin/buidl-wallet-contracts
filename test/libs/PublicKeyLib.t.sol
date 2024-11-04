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

import {PublicKey} from "../../src/common/CommonStructs.sol";
import {TestUtils} from "../util/TestUtils.sol";
import {PublicKeyLibCaller} from "./PublicKeyLibCaller.sol";

contract PublicKeyLibTest is TestUtils {
    PublicKeyLibCaller private publicKeyLibCaller = new PublicKeyLibCaller();

    function testFuzz_toBytes30(uint256 rand, uint256 x, uint256 y) public view {
        rand = bound(rand, 0, 1);
        x = bound(x, 0, UINT256_MAX);
        y = bound(y, 0, UINT256_MAX);
        if (x == 0 && y == 0) {
            if (rand == 0) {
                y = bound(y, 1, UINT256_MAX);
            } else {
                x = bound(x, 1, UINT256_MAX);
            }
        }
        assertNotEq(publicKeyLibCaller.toBytes30(x, y), bytes30(0));
    }

    function testFuzz_toBytes30PubKey(uint256 rand, PublicKey memory pubKey) public view {
        rand = bound(rand, 0, 1);
        pubKey.x = bound(pubKey.x, 0, UINT256_MAX);
        pubKey.y = bound(pubKey.y, 0, UINT256_MAX);
        if (pubKey.x == 0 && pubKey.y == 0) {
            if (rand == 0) {
                pubKey.y = bound(pubKey.y, 1, UINT256_MAX);
            } else {
                pubKey.x = bound(pubKey.x, 1, UINT256_MAX);
            }
        }
        assertNotEq(publicKeyLibCaller.toBytes30(pubKey), bytes30(0));
    }
}
