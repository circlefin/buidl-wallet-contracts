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

import {AddressDLL} from "../../../../../src/msca/6900/shared/common/Structs.sol";
import {AddressDLLLib} from "../../../../../src/msca/6900/shared/libs/AddressDLLLib.sol";

contract TestAddressDLL {
    using AddressDLLLib for AddressDLL;

    AddressDLL private addressDLL;

    function append(address valueToAdd) external returns (bool) {
        return addressDLL.append(valueToAdd);
    }

    function remove(address valueToRemove) external returns (bool) {
        return addressDLL.remove(valueToRemove);
    }

    function size() external view returns (uint256) {
        return addressDLL.size();
    }

    function contains(address value) external view returns (bool) {
        return addressDLL.contains(value);
    }

    function getAll() external view returns (address[] memory results) {
        return addressDLL.getAll();
    }

    function getPaginated(address start, uint256 limit)
        external
        view
        returns (address[] memory results, address next)
    {
        return addressDLL.getPaginated(start, limit);
    }

    function getHead() external view returns (address) {
        return addressDLL.getHead();
    }

    function getTail() external view returns (address) {
        return addressDLL.getTail();
    }
}
