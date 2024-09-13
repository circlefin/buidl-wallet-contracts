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

import {SENTINEL_BYTES32} from "../../../../common/Constants.sol";
import {InvalidItem, InvalidLimit, ItemAlreadyExists, ItemDoesNotExist} from "../../shared/common/Errors.sol";
import {Bytes32DLL} from "../common/Structs.sol";

/**
 * @dev Enumerable & ordered doubly linked list built using mapping(bytes32 => bytes32).
 *      Item is expected to be unique.
 */
library Bytes32DLLLib {
    modifier validBytes32(bytes32 value) {
        if (value <= SENTINEL_BYTES32) {
            revert InvalidItem();
        }
        _;
    }

    /**
     * @dev Check if an item exists or not. O(1).
     */
    function contains(Bytes32DLL storage dll, bytes32 item) internal view returns (bool) {
        return getHead(dll) == item || dll.next[item] != SENTINEL_BYTES32 || dll.prev[item] != SENTINEL_BYTES32;
    }

    /**
     * @dev Get the count of dll. O(1).
     */
    function size(Bytes32DLL storage dll) internal view returns (uint256) {
        return dll.count;
    }

    /**
     * @dev Add an new item which did not exist before. Otherwise the function reverts. O(1).
     */
    function append(Bytes32DLL storage dll, bytes32 item) internal validBytes32(item) returns (bool) {
        if (contains(dll, item)) {
            revert ItemAlreadyExists();
        }
        bytes32 prev = getTail(dll);
        bytes32 next = SENTINEL_BYTES32;
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
    function remove(Bytes32DLL storage dll, bytes32 item) internal validBytes32(item) returns (bool) {
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
     * @dev Return paginated bytes32s and next pointer bytes32. O(n).
     * @param start Starting bytes32, inclusive, if start == bytes32(0), this method searches from the head.
     */
    function getPaginated(Bytes32DLL storage dll, bytes32 start, uint256 limit)
        internal
        view
        returns (bytes32[] memory, bytes32)
    {
        if (limit == 0) {
            revert InvalidLimit();
        }
        bytes32[] memory results = new bytes32[](limit);
        bytes32 current = start;
        if (start == SENTINEL_BYTES32) {
            current = getHead(dll);
        }
        uint256 count = 0;
        for (; count < limit && current > SENTINEL_BYTES32; ++count) {
            results[count] = current;
            current = dll.next[current];
        }
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            mstore(results, count)
        }
        return (results, current);
    }

    /**
     * @dev Return all the data. O(n).
     */
    function getAll(Bytes32DLL storage dll) internal view returns (bytes32[] memory results) {
        uint256 totalCount = size(dll);
        results = new bytes32[](totalCount);
        uint256 accumulatedCount = 0;
        bytes32 start = SENTINEL_BYTES32;
        for (uint256 i = 0; i < totalCount; ++i) {
            (bytes32[] memory currentResults, bytes32 next) = getPaginated(dll, start, 10);
            for (uint256 j = 0; j < currentResults.length; ++j) {
                results[accumulatedCount++] = currentResults[j];
            }
            if (next == SENTINEL_BYTES32) {
                break;
            }
            start = next;
        }
        return results;
    }

    function getHead(Bytes32DLL storage dll) internal view returns (bytes32) {
        return dll.next[SENTINEL_BYTES32];
    }

    function getTail(Bytes32DLL storage dll) internal view returns (bytes32) {
        return dll.prev[SENTINEL_BYTES32];
    }
}
