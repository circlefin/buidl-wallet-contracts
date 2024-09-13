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

import {ExecutionHook} from "../common/Structs.sol";
import {ModuleEntity} from "../common/Types.sol";

/**
 * @dev Implements https://eips.ethereum.org/EIPS/eip-6900. MSCAs may implement this interface to support visibility in
 * plugin configurations on-chain.
 */
interface IAccountLoupe {
    /// @notice Get the plugin address for a selector.
    /// @dev If the selector is a native function, the plugin address will be the address of the account.
    /// @param selector The selector to get the configuration for.
    /// @return The plugin address for this selector.
    function getExecutionData(bytes4 selector) external view returns (address);

    /// @notice Get the selectors for a validation function.
    /// @param validationFunction The validation function to get the selectors for.
    /// @return The allowed selectors for this validation function.
    function getSelectors(ModuleEntity validationFunction) external view returns (bytes4[] memory);

    /// @notice Get the pre and post execution hooks for a selector.
    /// @param selector The selector to get the hooks for.
    /// @return The pre and post execution hooks for this selector.
    function getExecutionHooks(bytes4 selector) external view returns (ExecutionHook[] memory);

    /// @notice Get the permission hooks for a validation function.
    /// @param validationFunction The validation function to get the hooks for.
    /// @return The permission execution hooks for this validation function.
    function getPermissionHooks(ModuleEntity validationFunction) external view returns (ExecutionHook[] memory);

    /// @notice Get the pre user op and runtime validation hooks associated with a selector.
    /// @param validationFunction The validation function to get the hooks for.
    /// @return preValidationHooks The pre validation hooks for this selector.
    function getPreValidationHooks(ModuleEntity validationFunction) external view returns (ModuleEntity[] memory);

    /// @notice Get an array of all installed plugins.
    /// @return pluginAddresses The addresses of all installed plugins.
    function getInstalledPlugins() external view returns (address[] memory);
}
