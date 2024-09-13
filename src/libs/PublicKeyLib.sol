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

import {PublicKey} from "../common/CommonStructs.sol";

/**
 * @dev Util functions for public key.
 */
library PublicKeyLib {
    error InvalidPublicKey(uint256 x, uint256 y);

    function toBytes30(uint256 x, uint256 y) internal pure returns (bytes30) {
        // (0, 0) is point at infinity and not on the curve and should therefore be rejected
        if (x == 0 && y == 0) {
            revert InvalidPublicKey(x, y);
        }
        return bytes30(uint240(uint256(keccak256(abi.encode(x, y)))));
    }

    function toBytes30(PublicKey memory publicKey) internal pure returns (bytes30) {
        // (0, 0) is point at infinity and not on the curve and should therefore be rejected
        uint256 x = publicKey.x;
        uint256 y = publicKey.y;
        return toBytes30(x, y);
    }
}
