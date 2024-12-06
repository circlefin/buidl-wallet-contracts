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
import {InvalidFunctionReference, InvalidLimit, ItemDoesNotExist} from "../../shared/common/Errors.sol";
import {FunctionReference, RepeatableBytes21DLL} from "../common/Structs.sol";
import {FunctionReferenceLib} from "./FunctionReferenceLib.sol";

/**
 * @dev Enumerable & ordered doubly linked list built using RepeatableBytes21DLL.
 *      Item is expected to be have a counter that tracks repeated number.
 */
library RepeatableFunctionReferenceDLLLib {
    using FunctionReferenceLib for FunctionReference;
    using FunctionReferenceLib for bytes21;

    modifier validFunctionReference(FunctionReference memory fr) {
        if (fr.pack() <= SENTINEL_BYTES21) {
            revert InvalidFunctionReference();
        }
        _;
    }

    /**
     * @dev Check the counter of an item. O(1).
     * @return the counter
     */
    function getRepeatedCount(RepeatableBytes21DLL storage dll, FunctionReference memory fr)
        internal
        view
        returns (uint256)
    {
        bytes21 item = fr.pack();
        if (item == SENTINEL_BYTES21) {
            return 1;
        }
        return dll.counter[item];
    }

    /**
     * @dev Get the total items of dll. O(1).
     */
    function getTotalItems(RepeatableBytes21DLL storage dll) internal view returns (uint256) {
        return dll.totalItems;
    }

    /**
     * @dev Get the unique items of dll. O(1).
     */
    function getUniqueItems(RepeatableBytes21DLL storage dll) internal view returns (uint256) {
        return dll.uniqueItems;
    }

    /**
     * @dev Add an new item. O(1).
     */
    function append(RepeatableBytes21DLL storage dll, FunctionReference memory fr)
        internal
        validFunctionReference(fr)
        returns (uint256)
    {
        bytes21 item = fr.pack();
        uint256 currentCount = getRepeatedCount(dll, fr);
        if (currentCount == 0) {
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
            dll.uniqueItems++;
        }
        dll.counter[item]++;
        dll.totalItems++;
        return dll.counter[item];
    }

    /**
     * @dev Remove or decrease the counter of already existing item. Otherwise the function reverts. O(1).
     */
    function remove(RepeatableBytes21DLL storage dll, FunctionReference memory fr)
        internal
        validFunctionReference(fr)
        returns (uint256)
    {
        uint256 currentCount = getRepeatedCount(dll, fr);
        if (currentCount == 0) {
            revert ItemDoesNotExist();
        }
        bytes21 item = fr.pack();
        if (currentCount == 1) {
            // delete the item
            // item.prev.next = item.next
            dll.next[dll.prev[item]] = dll.next[item];
            // item.next.prev = item.prev
            dll.prev[dll.next[item]] = dll.prev[item];
            delete dll.next[item];
            delete dll.prev[item];
            delete dll.counter[item];
            dll.uniqueItems--;
        } else {
            dll.counter[item]--;
        }
        dll.totalItems--;
        return dll.counter[item];
    }

    /**
     * @dev Remove all copies of already existing items. O(1).
     */
    function removeAllRepeated(RepeatableBytes21DLL storage dll, FunctionReference memory fr)
        internal
        validFunctionReference(fr)
        returns (bool)
    {
        uint256 currentCount = getRepeatedCount(dll, fr);
        if (currentCount == 0) {
            revert ItemDoesNotExist();
        }
        bytes21 item = fr.pack();
        // item.prev.next = item.next
        dll.next[dll.prev[item]] = dll.next[item];
        // item.next.prev = item.prev
        dll.prev[dll.next[item]] = dll.prev[item];
        delete dll.next[item];
        delete dll.prev[item];
        delete dll.counter[item];
        dll.uniqueItems--;
        dll.totalItems -= currentCount;
        return true;
    }

    /**
     * @dev Return paginated results and next pointer without counter information. O(n).
     *      In order to get counter information (which our current use case does not need), please call
     * getRepeatedCount.
     * @param startFR Starting item, inclusive, if start == bytes21(0), this method searches from the head.
     */
    function getPaginated(RepeatableBytes21DLL storage dll, FunctionReference memory startFR, uint256 limit)
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
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            mstore(results, count)
        }
        return (results, current.unpack());
    }

    /**
     * @dev Return all the unique items without counter information. O(n).
     *      In order to get counter information (which our current use case does not need), please call
     * getRepeatedCount.
     */
    function getAll(RepeatableBytes21DLL storage dll) internal view returns (FunctionReference[] memory results) {
        uint256 totalUniqueCount = getUniqueItems(dll);
        results = new FunctionReference[](totalUniqueCount);
        uint256 accumulatedCount = 0;
        FunctionReference memory startFR = EMPTY_FUNCTION_REFERENCE.unpack();
        for (uint256 i = 0; i < totalUniqueCount; ++i) {
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

    function getHead(RepeatableBytes21DLL storage dll) internal view returns (FunctionReference memory) {
        return dll.next[SENTINEL_BYTES21].unpack();
    }

    function getTail(RepeatableBytes21DLL storage dll) internal view returns (FunctionReference memory) {
        return dll.prev[SENTINEL_BYTES21].unpack();
    }

    function getHeadWithoutUnpack(RepeatableBytes21DLL storage dll) private view returns (bytes21) {
        return dll.next[SENTINEL_BYTES21];
    }

    function getTailWithoutUnpack(RepeatableBytes21DLL storage dll) private view returns (bytes21) {
        return dll.prev[SENTINEL_BYTES21];
    }
}
