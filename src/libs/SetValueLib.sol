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

import {SetValue} from "@modular-account-libs/libraries/Constants.sol";

/**
 * @dev Handles SetValue from Alchemy's library.
 */
library SetValueLib {
    /// @dev Helper function to convert set values to bytes30 with leading zeros.
    function toBytes30Array(SetValue[] memory values) internal pure returns (bytes30[] memory res) {
        uint256 len = values.length;
        res = new bytes30[](len);
        for (uint256 i = 0; i < len; ++i) {
            res[i] = SetValue.unwrap(values[i]);
        }
        return res;
    }
}
