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

import {IPlugin} from "../interfaces/IPlugin.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";

/**
 * @dev Default implementation of https://eips.ethereum.org/EIPS/eip-6900. MSCAs must implement this interface to
 * support open-ended execution.
 */
abstract contract BasePlugin is IPlugin, ERC165 {
    error AlreadyInitialized();
    error NotInitialized();

    /// @dev Ensure the account has initialized this plugin
    /// @param account the account to check
    modifier isNotInitialized(address account) {
        if (_isInitialized(account)) {
            revert AlreadyInitialized();
        }
        _;
    }

    /// @dev Ensure the account has not initialized this plugin
    /// @param account the account to check
    modifier isInitialized(address account) {
        if (!_isInitialized(account)) {
            revert NotInitialized();
        }
        _;
    }

    /// @dev Returns true if this contract implements the interface defined by
    /// `interfaceId`. See the corresponding
    /// https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]
    /// to learn more about how these ids are created.
    ///
    /// This function call must use less than 30,000 gas.
    ///
    /// Supporting the IPlugin interface is a requirement for plugin installation (PluginManager). This is also used
    /// by the modular account to prevent StandardExecutor functions from making calls to plugins.
    /// @param interfaceId The interface ID to check for support.
    /// @return True if the contract supports `interfaceId`.
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IPlugin).interfaceId || super.supportsInterface(interfaceId);
    }

    /// @notice Check if the account has initialized this plugin yet
    /// @dev This function should be overwritten for plugins that have state-changing onInstall's
    /// @param account The account to check
    /// @return True if the account has initialized this plugin
    // solhint-disable-next-line no-empty-blocks
    function _isInitialized(address account) internal view virtual returns (bool) {}
}
