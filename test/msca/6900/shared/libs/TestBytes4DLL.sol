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

import {Bytes4DLL} from "../../../../../src/msca/6900/shared/common/Structs.sol";
import {Bytes4DLLLib} from "../../../../../src/msca/6900/shared/libs/Bytes4DLLLib.sol";

contract TestBytes4DLL {
    using Bytes4DLLLib for Bytes4DLL;

    Bytes4DLL private bytes4DLL;

    function append(bytes4 valueToAdd) external returns (bool) {
        return bytes4DLL.append(valueToAdd);
    }

    function remove(bytes4 valueToRemove) external returns (bool) {
        return bytes4DLL.remove(valueToRemove);
    }

    function size() external view returns (uint256) {
        return bytes4DLL.size();
    }

    function contains(bytes4 value) external returns (bool) {
        return bytes4DLL.contains(value);
    }

    function getAll() external view returns (bytes4[] memory results) {
        return bytes4DLL.getAll();
    }

    function getPaginated(bytes4 start, uint256 limit) external view returns (bytes4[] memory results, bytes4 next) {
        return bytes4DLL.getPaginated(start, limit);
    }

    function getHead() external view returns (bytes4) {
        return bytes4DLL.getHead();
    }

    function getTail() external view returns (bytes4) {
        return bytes4DLL.getTail();
    }
}
