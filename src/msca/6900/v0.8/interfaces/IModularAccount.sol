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

import {ExecutionManifest} from "../common/ModuleManifest.sol";
import {Call} from "../common/Structs.sol";
import {ModuleEntity, ValidationConfig} from "../common/Types.sol";

/**
 * @dev Implements https://eips.ethereum.org/EIPS/eip-6900. MSCAs must implement this interface to support open-ended
 * execution.
 */
interface IModularAccount {
    event ExecutionInstalled(address indexed module, ExecutionManifest manifest);
    event ExecutionUninstalled(address indexed module, bool onUninstallSucceeded, ExecutionManifest manifest);
    event ValidationInstalled(address indexed module, uint32 indexed entityId);
    event ValidationUninstalled(address indexed module, uint32 indexed entityId, bool onUninstallSucceeded);

    /// @notice Standard execute method.
    /// @param target The target address for the account to call.
    /// @param value The value to send with the call.
    /// @param data The calldata for the call.
    /// @return The return data from the call.
    function execute(address target, uint256 value, bytes calldata data) external payable returns (bytes memory);

    /// @notice Standard executeBatch method.
    /// @dev If the target is a module, the call SHOULD revert. If any of the calls revert, the entire batch MUST
    /// revert.
    /// @param calls The array of calls.
    /// @return An array containing the return data from the calls.
    function executeBatch(Call[] calldata calls) external payable returns (bytes[] memory);

    /// @notice Execute a call using the specified runtime validation.
    /// @param data The calldata to send to the account.
    /// @param authorization The authorization data to use for the call. The first 24 bytes is a ModuleEntity which
    /// specifies which runtime validation to use, and the rest is sent as a parameter to runtime validation.
    function executeWithRuntimeValidation(bytes calldata data, bytes calldata authorization)
        external
        payable
        returns (bytes memory);

    /// @notice Install a module to the modular account.
    /// @param module The module to install.
    /// @param manifest the manifest describing functions to install.
    /// @param installData Optional data to be used by the account to handle the initial execution setup. Data
    /// encoding is implementation-specific.
    function installExecution(address module, ExecutionManifest calldata manifest, bytes calldata installData)
        external;

    /// @notice Uninstall a module from the modular account.
    /// @param module The module to uninstall.
    /// @param manifest the manifest describing functions to uninstall.
    /// @param uninstallData Optional data to be used by the account to handle the execution uninstallation. Data
    /// encoding is implementation-specific.
    function uninstallExecution(address module, ExecutionManifest calldata manifest, bytes calldata uninstallData)
        external;

    /// @notice Installs a validation function across a set of execution selectors, and optionally mark it as a
    /// global validation function.
    /// @dev This does not validate anything against the manifest - the caller must ensure validity.
    /// @param validationConfig The validation function to install, along with configuration flags.
    /// @param selectors The selectors to install the validation function for.
    /// @param installData Optional data to be used by the account to handle the initial validation setup. Data
    /// encoding is implementation-specific.
    /// @param hooks Optional hooks to install and associate with the validation function. Data encoding is
    /// implementation-specific.
    function installValidation(
        ValidationConfig validationConfig,
        bytes4[] calldata selectors,
        bytes calldata installData,
        bytes[] calldata hooks
    ) external;

    /// @notice Uninstall a validation function from a set of execution selectors.
    /// @param validationFunction The validation function to uninstall.
    /// @param uninstallData Optional data to be used by the account to handle the validation uninstallation. Data
    /// encoding is implementation-specific.
    /// @param hookUninstallData Optional data to be used by the account to handle hook uninstallation. Data
    /// encoding is implementation-specific.
    function uninstallValidation(
        ModuleEntity validationFunction,
        bytes calldata uninstallData,
        bytes[] calldata hookUninstallData
    ) external;

    /// @notice Return a unique identifier for the account implementation.
    /// @dev This function MUST return a string in the format "vendor.account.semver". The vendor and account
    /// names MUST NOT contain a period character.
    /// @return The account ID.
    function accountId() external view returns (string memory);
}
