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
import {IModule} from "./IModule.sol";

/**
 * @dev Implements https://eips.ethereum.org/EIPS/eip-6900. Modules must implement this interface to support module
 * management and interactions with MSCAs.
 */
interface IExecutionModule is IModule {
    /// @notice Describe the contents and intended configuration of the module.
    /// @dev This manifest MUST stay constant over time.
    /// @return A manifest describing the contents and intended configuration of the module.
    function executionManifest() external pure returns (ExecutionManifest memory);
}
