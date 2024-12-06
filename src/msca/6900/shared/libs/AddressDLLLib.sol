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

import {InvalidLimit, ItemAlreadyExists, ItemDoesNotExist} from "../common/Errors.sol";
import {AddressDLL} from "../common/Structs.sol";

/**
 * @dev Enumerable & ordered doubly linked list built using mapping(address => address).
 *      Item is expected to be unique.
 */
library AddressDLLLib {
    address private constant SENTINEL_ADDRESS = address(0x0);
    uint160 private constant SENTINEL_ADDRESS_UINT = 0;

    event AddressAdded(address indexed addr);
    event AddressRemoved(address indexed addr);

    error InvalidAddress();

    modifier validAddress(address addr) {
        if (uint160(addr) <= SENTINEL_ADDRESS_UINT) {
            revert InvalidAddress();
        }
        _;
    }

    /**
     * @dev Check if an item exists or not. O(1).
     */
    function contains(AddressDLL storage dll, address item) internal view returns (bool) {
        return getHead(dll) == item || dll.next[item] != address(0) || dll.prev[item] != address(0);
    }

    /**
     * @dev Get the count of dll. O(1).
     */
    function size(AddressDLL storage dll) internal view returns (uint256) {
        return dll.count;
    }

    /**
     * @dev Add an new item which did not exist before. Otherwise the function reverts. O(1).
     */
    function append(AddressDLL storage dll, address item) internal validAddress(item) returns (bool) {
        if (contains(dll, item)) {
            revert ItemAlreadyExists();
        }
        address prev = getTail(dll);
        address next = SENTINEL_ADDRESS;
        // prev.next = item
        dll.next[prev] = item;
        // item.next = next
        dll.next[item] = next;
        // next.prev = item
        dll.prev[next] = item;
        // item.prev = prev
        dll.prev[item] = prev;
        dll.count++;
        emit AddressAdded(item);
        return true;
    }

    /**
     * @dev Remove an already existing item. Otherwise the function reverts. O(1).
     */
    function remove(AddressDLL storage dll, address item) internal validAddress(item) returns (bool) {
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
        emit AddressRemoved(item);
        return true;
    }

    /**
     * @dev Return paginated addresses and next pointer address. O(n).
     * @param start Starting address, inclusive, if start == address(0x0), this method searches from the head.
     */
    function getPaginated(AddressDLL storage dll, address start, uint256 limit)
        internal
        view
        returns (address[] memory, address)
    {
        if (limit == 0) {
            revert InvalidLimit();
        }
        address[] memory results = new address[](limit);
        address current = start;
        if (start == address(0)) {
            current = getHead(dll);
        }
        uint256 count = 0;
        for (; count < limit && uint160(current) > SENTINEL_ADDRESS_UINT; ++count) {
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
    function getAll(AddressDLL storage dll) internal view returns (address[] memory results) {
        uint256 totalCount = size(dll);
        results = new address[](totalCount);
        uint256 accumulatedCount = 0;
        address startAddr = address(0x0);
        for (uint256 i = 0; i < totalCount; ++i) {
            (address[] memory currentResults, address nextAddr) = getPaginated(dll, startAddr, 10);
            for (uint256 j = 0; j < currentResults.length; ++j) {
                results[accumulatedCount++] = currentResults[j];
            }
            if (nextAddr == SENTINEL_ADDRESS) {
                break;
            }
            startAddr = nextAddr;
        }
        return results;
    }

    function getHead(AddressDLL storage dll) internal view returns (address) {
        return dll.next[SENTINEL_ADDRESS];
    }

    function getTail(AddressDLL storage dll) internal view returns (address) {
        return dll.prev[SENTINEL_ADDRESS];
    }
}
