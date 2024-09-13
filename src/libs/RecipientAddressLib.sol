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

import {IERC1155} from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

/**
 * @dev Decode the recipient of a token (ERC20, ERC1155 and ERC721) contract call.
 *      In order to use abi.decode to decode the data after the selector, we would need to copy each byte from
 *      the original array to the sliced array expensively because slicing bytes memory array is not as easy as
 *      slicing calldata in Solidity.
 *      Instead we use inline assembly to mload the recipient directly, which is safe because we've checked the
 *      the length of the bytes array.
 */
library RecipientAddressLib {
    bytes4 internal constant ERC721_SAFE_TRANSFER_FROM = bytes4(keccak256("safeTransferFrom(address,address,uint256)"));
    bytes4 internal constant ERC721_SAFE_TRANSFER_FROM_WITH_BYTES =
        bytes4(keccak256("safeTransferFrom(address,address,uint256,bytes)"));
    bytes4 internal constant ERC20_INCREASE_ALLOWANCE = bytes4(keccak256("increaseAllowance(address,uint256)"));
    bytes4 internal constant ERC20_DECREASE_ALLOWANCE = bytes4(keccak256("decreaseAllowance(address,uint256)"));
    uint256 internal constant TRANSFER_OR_APPROVE_MIN_LEN = 68;
    uint256 internal constant TRANSFER_FROM_MIN_LEN = 100;
    uint256 internal constant TRANSFER_FROM_WITHOUT_AMOUNT_WITH_BYTES_MIN_LEN = 164;
    uint256 internal constant TRANSFER_FROM_WITH_BYTES_MIN_LEN = 196;
    uint256 internal constant BATCH_TRANSFER_FROM_WITH_BYTES_MIN_LEN = 260;
    uint256 internal constant TRANSFER_OR_APPROVE_RECIPIENT_OFFSET = 36;
    uint256 internal constant TRANSFER_FROM_RECIPIENT_OFFSET = 68;

    /// @notice Decode the recipient of a token.
    /// @dev This only supports the following **standard** ERC20 functions:
    /// - transfer(address,uint256)
    /// - approve(address,uint256)
    /// - transferFrom(address,address,uint256)
    /// @param data The calldata of the transaction.
    /// @return The recipient of the token being sent. Zero address if the call is unsupported.
    function getERC20TokenRecipient(bytes memory data) internal pure returns (address) {
        bytes4 selector = bytes4(data);
        if (
            selector == IERC20.transfer.selector || selector == IERC20.approve.selector
                || selector == ERC20_INCREASE_ALLOWANCE || selector == ERC20_DECREASE_ALLOWANCE
        ) {
            // 68 bytes (4 selector + 32 address + 32 amount)
            if (data.length < TRANSFER_OR_APPROVE_MIN_LEN) {
                return address(0);
            }
            // Jump forward: 32 for the length field, 4 for the selector.
            return getRecipient(data, TRANSFER_OR_APPROVE_RECIPIENT_OFFSET);
        } else if (selector == IERC20.transferFrom.selector) {
            // 100 bytes (4 selector + 32 address + 32 address + 32 amount)
            if (data.length < TRANSFER_FROM_MIN_LEN) {
                return address(0);
            }
            // Jump forward: 32 for the length field, 4 for the selector, and 32 for the from address.
            return getRecipient(data, TRANSFER_FROM_RECIPIENT_OFFSET);
        }
        return address(0);
    }

    /// @notice Decode the recipient of a token.
    /// @dev This only supports the following **standard** ERC1155 functions:
    /// - setApprovalForAll(address,bool)
    /// - safeTransferFrom(address,address,uint256,uint256,bytes)
    /// - safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)
    /// @param data The calldata of the transaction.
    /// @return The recipient of the token being sent. Zero address if the call is unsupported.
    function getERC1155TokenRecipient(bytes memory data) internal pure returns (address) {
        bytes4 selector = bytes4(data);
        if (selector == IERC1155.setApprovalForAll.selector) {
            // 68 bytes (4 selector + 32 address + 32 bool)
            if (data.length < TRANSFER_OR_APPROVE_MIN_LEN) {
                return address(0);
            }
            // Jump forward: 32 for the length field, 4 for the selector.
            return getRecipient(data, TRANSFER_OR_APPROVE_RECIPIENT_OFFSET);
        } else if (selector == IERC1155.safeTransferFrom.selector) {
            // 196 bytes (4 selector + 32 address + 32 address + 32 token id + 32 amount + 32 (offset for bytes) + 32
            // (length of bytes))
            if (data.length < TRANSFER_FROM_WITH_BYTES_MIN_LEN) {
                return address(0);
            }
            // Jump forward: 32 for the length field, 4 for the selector, and 32 for the from address.
            return getRecipient(data, TRANSFER_FROM_RECIPIENT_OFFSET);
        } else if (selector == IERC1155.safeBatchTransferFrom.selector) {
            // 4 (function selector)
            // + 64 (2 addresses, padded to 32 bytes each)
            // + 2 * [32 (offset for each array) + 32 (length of each array) + (n * 32) (array data)]
            // + 32 (offset for bytes) + 32 (length of bytes) + m (padded bytes data)
            // min length 260 bytes when n == 0, m == "" (noop)
            if (data.length < BATCH_TRANSFER_FROM_WITH_BYTES_MIN_LEN) {
                return address(0);
            }
            // Jump forward: 32 for the length field, 4 for the selector, and 32 for the from address.
            return getRecipient(data, TRANSFER_FROM_RECIPIENT_OFFSET);
        }
        return address(0);
    }

    /// @notice Decode the recipient of a token.
    /// @dev This only supports the following **standard** ERC721 functions:
    /// - safeTransferFrom(address,address,uint256)
    /// - safeTransferFrom(address,address,uint256,bytes)
    /// - transferFrom(address,address,uint256)
    /// - approve(address,uint256)
    /// - setApprovalForAll(address,bool)
    /// @param data The calldata of the transaction.
    /// @return The recipient of the token being sent. Zero address if the call is unsupported.
    function getERC721TokenRecipient(bytes memory data) internal pure returns (address) {
        bytes4 selector = bytes4(data);
        if (selector == IERC721.setApprovalForAll.selector || selector == IERC721.approve.selector) {
            // 68 bytes (4 selector + 32 address + 32 bool)
            // or 68 bytes (4 selector + 32 address + 32 token id)
            if (data.length < TRANSFER_OR_APPROVE_MIN_LEN) {
                return address(0);
            }
            // Jump forward: 32 for the length field, 4 for the selector.
            return getRecipient(data, TRANSFER_OR_APPROVE_RECIPIENT_OFFSET);
        } else if (selector == ERC721_SAFE_TRANSFER_FROM || selector == IERC721.transferFrom.selector) {
            // 100 bytes (4 selector + 32 address + 32 address + 32 token id)
            if (data.length < TRANSFER_FROM_MIN_LEN) {
                return address(0);
            }
            // Jump forward: 32 for the length field, 4 for the selector, and 32 for the from address.
            return getRecipient(data, TRANSFER_FROM_RECIPIENT_OFFSET);
        } else if (selector == ERC721_SAFE_TRANSFER_FROM_WITH_BYTES) {
            // 164 bytes (4 selector + 32 address + 32 address + 32 token id + 32 (offset for bytes) + 32 (length of
            // bytes))
            if (data.length < TRANSFER_FROM_WITHOUT_AMOUNT_WITH_BYTES_MIN_LEN) {
                return address(0);
            }
            // Jump forward: 32 for the length field, 4 for the selector, and 32 for the from address.
            return getRecipient(data, TRANSFER_FROM_RECIPIENT_OFFSET);
        }
        return address(0);
    }

    /// @dev The caller must skip over the initial length prefix.
    function getRecipient(bytes memory data, uint256 recipientIndex) private pure returns (address) {
        address recipient;
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            // Jump forward to the starting index of recipient
            recipient := mload(add(data, recipientIndex))
        }
        return recipient;
    }
}
