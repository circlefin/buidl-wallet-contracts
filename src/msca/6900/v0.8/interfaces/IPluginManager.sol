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

import {ModuleEntity, ValidationConfig} from "../common/Types.sol";

/**
 * @dev Implements https://eips.ethereum.org/EIPS/eip-6900. MSCAs must implement this interface to support installing
 * and uninstalling plugins.
 */
interface IPluginManager {
    event PluginInstalled(address indexed plugin);
    event PluginUninstalled(address indexed plugin, bool indexed onUninstallSucceeded);
    event ValidationInstalled(ValidationConfig validationConfig, bytes4[] selectors);
    event ValidationUnInstalled(ModuleEntity indexed validationFunction);

    /// @notice Install a plugin to the modular account.
    /// @param plugin The plugin to install.
    /// @param pluginInstallData Optional data to be decoded and used by the plugin to setup initial plugin data
    /// for the modular account.
    function installPlugin(address plugin, bytes calldata pluginInstallData) external;

    /// @notice Uninstall a plugin from the modular account.
    /// @param plugin The plugin to uninstall.
    /// @param config An optional, implementation-specific field that accounts may use to ensure consistency
    /// guarantees.
    /// @param pluginUninstallData Optional data to be decoded and used by the plugin to clear plugin data for the
    /// modular account.
    function uninstallPlugin(address plugin, bytes calldata config, bytes calldata pluginUninstallData) external;

    /// TODO: merge permissionHooks into hooks
    /// @notice Temporary install function - pending a different user-supplied install config & manifest validation
    /// path.
    /// Installs a validation function across a set of execution selectors, and optionally mark it as a global
    /// validation.
    /// @dev This does not validate anything against the manifest - the caller must ensure validity.
    /// @param validationConfig The validation function to install, along with configuration flags.
    /// @param selectors The selectors to install the validation function for.
    /// @param installData Optional data to be decoded and used by the plugin to setup initial plugin state.
    /// @param hooks Optional hooks to install, associated with the validation function. These may be
    /// pre-validation hooks or execution hooks. The expected format is a bytes26 HookConfig, followed by the
    /// install data, if any.
    function installValidation(
        ValidationConfig validationConfig,
        bytes4[] calldata selectors,
        bytes calldata installData,
        bytes calldata hooks,
        bytes calldata permissionHooks
    ) external;

    /// TODO: merge permissionHookUninstallData into hookUninstallData
    /// @notice Uninstall a validation function from a set of execution selectors.
    /// @param validationFunction The validation function to uninstall.
    /// @param uninstallData Optional data to be decoded and used by the plugin to clear plugin data for the
    /// account.
    /// @param hookUninstallData Optional data to be used by hooks for cleanup. If any are provided, the array must
    /// be of a length equal to existing pre-validation hooks plus permission hooks. Hooks are indexed by
    /// pre-validation hook order first, then permission hooks.
    function uninstallValidation(
        ModuleEntity validationFunction,
        bytes calldata uninstallData,
        bytes calldata hookUninstallData,
        bytes calldata permissionHookUninstallData
    ) external;
}
