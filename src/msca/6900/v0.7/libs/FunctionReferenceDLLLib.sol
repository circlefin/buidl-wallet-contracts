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

import {EMPTY_FUNCTION_REFERENCE, SENTINEL_BYTES21} from "../../../../common/Constants.sol";
import {
    InvalidFunctionReference, InvalidLimit, ItemAlreadyExists, ItemDoesNotExist
} from "../../shared/common/Errors.sol";
import "../common/Structs.sol";
import {FunctionReferenceLib} from "./FunctionReferenceLib.sol";

/**
 * @dev Enumerable & ordered doubly linked list built using mapping(bytes21 => bytes21) for function reference.
 *      Item is expected to be unique.
 */
library FunctionReferenceDLLLib {
    using FunctionReferenceLib for FunctionReference;
    using FunctionReferenceLib for bytes21;

    modifier validFunctionReference(FunctionReference memory fr) {
        if (fr.pack() <= SENTINEL_BYTES21) {
            revert InvalidFunctionReference();
        }
        _;
    }

    /**
     * @dev Check if an item exists or not. O(1).
     */
    function contains(Bytes21DLL storage dll, FunctionReference memory fr) internal view returns (bool) {
        return contains(dll, fr.pack());
    }

    function contains(Bytes21DLL storage dll, bytes21 item) internal view returns (bool) {
        return getHeadWithoutUnpack(dll) == item || dll.next[item] != SENTINEL_BYTES21
            || dll.prev[item] != SENTINEL_BYTES21;
    }

    /**
     * @dev Get the count of dll. O(1).
     */
    function size(Bytes21DLL storage dll) internal view returns (uint256) {
        return dll.count;
    }

    /**
     * @dev Add an new item which did not exist before. Otherwise the function reverts. O(1).
     */
    function append(Bytes21DLL storage dll, FunctionReference memory fr)
        internal
        validFunctionReference(fr)
        returns (bool)
    {
        bytes21 item = fr.pack();
        if (contains(dll, item)) {
            revert ItemAlreadyExists();
        }
        bytes21 prev = getTailWithoutUnpack(dll);
        bytes21 next = SENTINEL_BYTES21;
        // prev.next = item
        dll.next[prev] = item;
        // item.next = next
        dll.next[item] = next;
        // next.prev = item
        dll.prev[next] = item;
        // item.prev = prev
        dll.prev[item] = prev;
        dll.count++;
        return true;
    }

    /**
     * @dev Remove an already existing item. Otherwise the function reverts. O(1).
     */
    function remove(Bytes21DLL storage dll, FunctionReference memory fr)
        internal
        validFunctionReference(fr)
        returns (bool)
    {
        bytes21 item = fr.pack();
        if (!contains(dll, item)) {
            revert ItemDoesNotExist();
        }
        // item.prev.next = item.next
        dll.next[dll.prev[item]] = dll.next[item];
        // item.next.prev = item.prev
        dll.prev[dll.next[item]] = dll.prev[item];
        delete dll.next[item];
        delete dll.prev[item];
        dll.count--;
        return true;
    }

    /**
     * @dev Return paginated bytes21s and next pointer bytes21. O(n).
     * @param startFR Starting bytes21, inclusive, if start == bytes21(0), this method searches from the head.
     */
    function getPaginated(Bytes21DLL storage dll, FunctionReference memory startFR, uint256 limit)
        internal
        view
        returns (FunctionReference[] memory, FunctionReference memory)
    {
        if (limit == 0) {
            revert InvalidLimit();
        }
        bytes21 start = startFR.pack();
        FunctionReference[] memory results = new FunctionReference[](limit);
        bytes21 current = start;
        if (start == SENTINEL_BYTES21) {
            current = getHeadWithoutUnpack(dll);
        }
        uint256 count = 0;
        for (; count < limit && current > SENTINEL_BYTES21; ++count) {
            results[count] = current.unpack();
            current = dll.next[current];
        }
        assembly ("memory-safe") {
            mstore(results, count)
        }
        return (results, current.unpack());
    }

    /**
     * @dev Return all the data. O(n).
     */
    function getAll(Bytes21DLL storage dll) internal view returns (FunctionReference[] memory results) {
        uint256 totalCount = size(dll);
        results = new FunctionReference[](totalCount);
        uint256 accumulatedCount = 0;
        FunctionReference memory startFR = EMPTY_FUNCTION_REFERENCE.unpack();
        for (uint256 i = 0; i < totalCount; ++i) {
            (FunctionReference[] memory currentResults, FunctionReference memory nextFR) =
                getPaginated(dll, startFR, 10);
            for (uint256 j = 0; j < currentResults.length; ++j) {
                results[accumulatedCount++] = currentResults[j];
            }
            if (nextFR.pack() == SENTINEL_BYTES21) {
                break;
            }
            startFR = nextFR;
        }
        return results;
    }

    function getHead(Bytes21DLL storage dll) internal view returns (FunctionReference memory) {
        return dll.next[SENTINEL_BYTES21].unpack();
    }

    function getTail(Bytes21DLL storage dll) internal view returns (FunctionReference memory) {
        return dll.prev[SENTINEL_BYTES21].unpack();
    }

    function getHeadWithoutUnpack(Bytes21DLL storage dll) private view returns (bytes21) {
        return dll.next[SENTINEL_BYTES21];
    }

    function getTailWithoutUnpack(Bytes21DLL storage dll) private view returns (bytes21) {
        return dll.prev[SENTINEL_BYTES21];
    }
}
