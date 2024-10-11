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

import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";

/**
 * @dev Implements https://eips.ethereum.org/EIPS/eip-6900. Modules must implement this interface to support module
 * management and interactions with MSCAs.
 */
interface IModule is IERC165 {
    /// @notice Initialize module data for the modular account.
    /// @dev Called by the modular account during `installModule`.
    /// @param data Optional bytes array to be decoded and used by the module to setup initial module data for the
    /// modular account.
    function onInstall(bytes calldata data) external;

    /// @notice Clear module data for the modular account.
    /// @dev Called by the modular account during `uninstallModule`.
    /// @param data Optional bytes array to be decoded and used by the module to clear module data for the modular
    /// account.
    function onUninstall(bytes calldata data) external;

    /// @notice Return a unique identifier for the module.
    /// @dev This function MUST return a string in the format "vendor.module.semver". The vendor and module
    /// names MUST NOT contain a period character.
    /// @return The module ID.
    function moduleId() external view returns (string memory);
}
