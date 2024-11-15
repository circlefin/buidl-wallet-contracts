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

import {FunctionReference, RepeatableBytes21DLL} from "../../../../src/msca/6900/v0.7/common/Structs.sol";
import {RepeatableFunctionReferenceDLLLib} from
    "../../../../src/msca/6900/v0.7/libs/RepeatableFunctionReferenceDLLLib.sol";

contract TestRepeatableFunctionReferenceDLL {
    using RepeatableFunctionReferenceDLLLib for RepeatableBytes21DLL;

    RepeatableBytes21DLL private preValidationHooks;

    function appendPreValidationHook(FunctionReference memory hookToAdd) external returns (uint256) {
        return preValidationHooks.append(hookToAdd);
    }

    function removePreValidationHook(FunctionReference memory hookToRemove) external returns (uint256) {
        return preValidationHooks.remove(hookToRemove);
    }

    function removeAllRepeatedPreValidationHooks(FunctionReference memory hookToRemove) external returns (bool) {
        return preValidationHooks.removeAllRepeated(hookToRemove);
    }

    function getRepeatedCountOfPreValidationHook(FunctionReference memory hook) external view returns (uint256) {
        return preValidationHooks.getRepeatedCount(hook);
    }

    function getTotalItemsOfPreValidationHooks() external view returns (uint256) {
        return preValidationHooks.getTotalItems();
    }

    function getUniqueItemsOfPreValidationHooks() external view returns (uint256) {
        return preValidationHooks.getUniqueItems();
    }

    function getAllPreValidationHooks() external view returns (FunctionReference[] memory results) {
        return preValidationHooks.getAll();
    }

    function getPreValidationHooksPaginated(FunctionReference memory startFR, uint256 limit)
        external
        view
        returns (FunctionReference[] memory results, FunctionReference memory next)
    {
        return preValidationHooks.getPaginated(startFR, limit);
    }

    function getFirstPreValidationHook() external view returns (FunctionReference memory) {
        return preValidationHooks.getHead();
    }

    function getLastPreValidationHook() external view returns (FunctionReference memory) {
        return preValidationHooks.getTail();
    }
}
