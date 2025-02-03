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

import {Bytes21DLL, FunctionReference} from "../../../../src/msca/6900/v0.7/common/Structs.sol";
import {FunctionReferenceDLLLib} from "../../../../src/msca/6900/v0.7/libs/FunctionReferenceDLLLib.sol";

contract TestFunctionReferenceDLL {
    using FunctionReferenceDLLLib for Bytes21DLL;

    Bytes21DLL private frs;

    function append(FunctionReference memory fr) external returns (bool) {
        return frs.append(fr);
    }

    function remove(FunctionReference memory fr) external returns (bool) {
        return frs.remove(fr);
    }

    function contains(FunctionReference memory fr) external view returns (bool) {
        return frs.contains(fr);
    }

    function getSize() external view returns (uint256) {
        return frs.size();
    }

    function getAll() external view returns (FunctionReference[] memory results) {
        return frs.getAll();
    }

    function getPaginated(FunctionReference memory startFR, uint256 limit)
        external
        view
        returns (FunctionReference[] memory results, FunctionReference memory next)
    {
        return frs.getPaginated(startFR, limit);
    }

    function getFirst() external view returns (FunctionReference memory) {
        return frs.getHead();
    }

    function getLast() external view returns (FunctionReference memory) {
        return frs.getTail();
    }
}
