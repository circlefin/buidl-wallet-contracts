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

import {IExecutionModule} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";

/**
 * @dev Interface for address book module.
 *      This module allows MSCA to check if the destination address is allowed to receive assets like native token,
 * ERC20 tokens, etc.
 *      The implementation could store an internal allowedRecipients that implements associated storage linked list
 *      because bundler validation rules only allow the entity to access the sender associated storage.
 *      By default the recipient is allowed to accept any tokens if it's added to the address book.
 */
interface IAddressBookModule is IValidationHookModule, IExecutionModule {
    event AllowedAddressesAdded(address indexed account, address[] recipients);
    event AllowedAddressesRemoved(address indexed account, address[] recipients);
    event AllowedAddressesNotRemoved(address indexed account);

    error FailToAddRecipient(address account, address recipient);
    error FailToRemoveRecipient(address account, address recipient);
    error UnauthorizedRecipient(address account, address recipient);
    error CallDataIsNotEmpty(address account, address target, uint256 value, bytes data);
    error InvalidTargetCodeLength(address account, address target, uint256 value, bytes data);

    /**
     * @dev Add allowed recipients. By default the recipient is allowed to accept all tokens.
     * Can only be called by the current msg.sender.
     */
    function addAllowedRecipients(address[] calldata recipients) external;

    /**
     * @dev Remove allowed recipients.
     * Can only be called by the current msg.sender.
     */
    function removeAllowedRecipients(address[] calldata recipients) external;

    /**
     * @dev Returns the allowed addresses of the current MSCA.
     */
    function getAllowedRecipients(address account) external view returns (address[] memory);
}
