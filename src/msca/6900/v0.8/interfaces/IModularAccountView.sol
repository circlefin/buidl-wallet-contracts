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

import {ExecutionDataView, ValidationDataView} from "../common/Structs.sol";
import {ModuleEntity} from "../common/Types.sol";

/**
 * @dev Implements https://eips.ethereum.org/EIPS/eip-6900. MSCAs may implement this interface to support visibility in
 * module configurations on-chain.
 */
interface IModularAccountView {
    /// @notice Get the execution data for a selector.
    /// @dev If the selector is a native function, the module address will be the address of the account.
    /// @param selector The selector to get the data for.
    /// @return ExecutionData The module address for this selector.
    function getExecutionData(bytes4 selector) external view returns (ExecutionDataView memory);

    /// @notice Get the validation data for a validation.
    /// @dev If the selector is a native function, the module address will be the address of the account.
    /// @param validationFunction The validation function to get the data for.
    /// @return ValidationData The module address for this selector.
    function getValidationData(ModuleEntity validationFunction) external view returns (ValidationDataView memory);
}
