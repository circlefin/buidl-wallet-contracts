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

import {Bytes32DLL} from "../../../../../src/msca/6900/shared/common/Structs.sol";
import {Bytes32DLLLib} from "../../../../../src/msca/6900/shared/libs/Bytes32DLLLib.sol";

contract TestBytes32DLL {
    using Bytes32DLLLib for Bytes32DLL;

    Bytes32DLL private bytes32DLL;

    function append(bytes32 valueToAdd) external returns (bool) {
        return bytes32DLL.append(valueToAdd);
    }

    function remove(bytes32 valueToRemove) external returns (bool) {
        return bytes32DLL.remove(valueToRemove);
    }

    function size() external view returns (uint256) {
        return bytes32DLL.size();
    }

    function contains(bytes32 value) external view returns (bool) {
        return bytes32DLL.contains(value);
    }

    function getAll() external view returns (bytes32[] memory results) {
        return bytes32DLL.getAll();
    }

    function getPaginated(bytes32 start, uint256 limit)
        external
        view
        returns (bytes32[] memory results, bytes32 next)
    {
        return bytes32DLL.getPaginated(start, limit);
    }

    function getHead() external view returns (bytes32) {
        return bytes32DLL.getHead();
    }

    function getTail() external view returns (bytes32) {
        return bytes32DLL.getTail();
    }
}
