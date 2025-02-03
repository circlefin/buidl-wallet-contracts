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

import {SENTINEL_BYTES4} from "../../../../common/Constants.sol";
import {InvalidLimit, ItemAlreadyExists, ItemDoesNotExist} from "../../shared/common/Errors.sol";
import {Bytes4DLL} from "../common/Structs.sol";

/**
 * @dev Enumerable & ordered doubly linked list built using mapping(bytes4 => bytes4).
 *      Item is expected to be unique.
 */
library Bytes4DLLLib {
    error InvalidBytes4();

    modifier validBytes4(bytes4 value) {
        if (value <= SENTINEL_BYTES4) {
            revert InvalidBytes4();
        }
        _;
    }

    /**
     * @dev Check if an item exists or not. O(1).
     */
    function contains(Bytes4DLL storage dll, bytes4 item) internal view returns (bool) {
        if (item == SENTINEL_BYTES4) {
            // SENTINEL_BYTES4 is not a valid item
            return false;
        }
        return getHead(dll) == item || dll.next[item] != bytes4(0) || dll.prev[item] != bytes4(0);
    }

    /**
     * @dev Get the count of dll. O(1).
     */
    function size(Bytes4DLL storage dll) internal view returns (uint256) {
        return dll.count;
    }

    /**
     * @dev Add an new item which did not exist before. Otherwise the function reverts. O(1).
     */
    function append(Bytes4DLL storage dll, bytes4 item) internal validBytes4(item) returns (bool) {
        if (contains(dll, item)) {
            revert ItemAlreadyExists();
        }
        bytes4 prev = getTail(dll);
        bytes4 next = SENTINEL_BYTES4;
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
    function remove(Bytes4DLL storage dll, bytes4 item) internal validBytes4(item) returns (bool) {
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
     * @dev Return paginated bytes4es and next pointer bytes4. O(n).
     * @param start Starting bytes4, inclusive, if start == bytes4(0x0), this method searches from the head.
     */
    function getPaginated(Bytes4DLL storage dll, bytes4 start, uint256 limit)
        internal
        view
        returns (bytes4[] memory, bytes4)
    {
        if (limit == 0) {
            revert InvalidLimit();
        }
        bytes4[] memory results = new bytes4[](limit);
        bytes4 current = start;
        if (start == bytes4(0)) {
            current = getHead(dll);
        }
        uint256 count = 0;
        for (; count < limit && current > SENTINEL_BYTES4; ++count) {
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
    function getAll(Bytes4DLL storage dll) internal view returns (bytes4[] memory results) {
        uint256 totalCount = size(dll);
        results = new bytes4[](totalCount);
        bytes4 current = getHead(dll);
        uint256 count = 0;
        for (; count < totalCount && current > SENTINEL_BYTES4; ++count) {
            results[count] = current;
            current = dll.next[current];
        }
        return results;
    }

    function getHead(Bytes4DLL storage dll) internal view returns (bytes4) {
        return dll.next[SENTINEL_BYTES4];
    }

    function getTail(Bytes4DLL storage dll) internal view returns (bytes4) {
        return dll.prev[SENTINEL_BYTES4];
    }
}
