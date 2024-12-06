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

/**
 * Utility functions helpful when making different kinds of contract calls in Solidity.
 * For inline assembly, please refer to https://docs.soliditylang.org/en/latest/assembly.html
 * For opcodes, please refer to https://ethereum.org/en/developers/docs/evm/opcodes/ and https://www.evm.codes/
 */
library ExecutionUtils {
    function call(address to, uint256 value, bytes memory data)
        internal
        returns (bool success, bytes memory returnData)
    {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            success := call(gas(), to, value, add(data, 0x20), mload(data), 0, 0)
            let len := returndatasize()
            let ptr := mload(0x40)
            mstore(0x40, add(ptr, add(len, 0x20)))
            mstore(ptr, len)
            returndatacopy(add(ptr, 0x20), 0, len)
            returnData := ptr
        }
    }

    function revertWithData(bytes memory returnData) internal pure {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            revert(add(returnData, 32), mload(returnData))
        }
    }

    function callAndRevert(address to, uint256 value, bytes memory data) internal {
        (bool success, bytes memory returnData) = call(to, value, data);
        if (!success) {
            revertWithData(returnData);
        }
    }

    function callWithReturnDataOrRevert(address to, uint256 value, bytes memory data) internal returns (bytes memory) {
        (bool success, bytes memory returnData) = call(to, value, data);
        if (!success) {
            // bubble up revert reason
            revertWithData(returnData);
        }
        return returnData;
    }

    /// @dev Return data or revert.
    function delegateCall(address to, bytes memory data) internal returns (bytes memory) {
        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returnData) = to.delegatecall(data);
        if (!success) {
            // bubble up revert reason
            revertWithData(returnData);
        }
        return returnData;
    }

    /// @dev Allocates memory for and retrieves return data from the previous external function call. The end of the
    /// allocated data may not be aligned to 32 bytes, which means the next free memory slot might fall somewhere
    /// between two 32-byte words. Therefore the memory address is aligned to the next 32-byte boundary to ensure
    /// efficient memory usage. The function also stores the size of the return data and copies the return data
    /// itself into the allocated memory.
    /// @return returnData the data returned by the last external function call.
    /// @notice The function ensures memory alignment by adding 63 (0x3f = 0x1f + 0x20) and clearing the last 5 bits,
    /// ensuring the memory is pushed to the nearest multiple of 32 bytes. This avoids unaligned memory access,
    /// which can lead to inefficiencies.
    function fetchReturnData() internal pure returns (bytes memory returnData) {
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            // allocate memory for the return data starting at the free memory pointer
            returnData := mload(0x40)
            // update the free memory pointer after adding the size of the return data and ensuring it is aligned to the
            // next 32-byte boundary
            mstore(0x40, add(returnData, and(add(returndatasize(), 0x3f), not(0x1f))))
            // store the size of the return data at the start of the allocated memory
            mstore(returnData, returndatasize())
            // copy the return data to the allocated memory space
            returndatacopy(add(returnData, 0x20), 0, returndatasize())
        }
    }
}
