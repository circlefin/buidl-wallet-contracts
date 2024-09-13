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

import {ExecutionUtils} from "../../../../utils/ExecutionUtils.sol";
import "../common/Structs.sol";
import {IPlugin} from "../interfaces/IPlugin.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";

/**
 * @dev Default implementation of https://eips.ethereum.org/EIPS/eip-6900. MSCAs must implement this interface to
 * support open-ended execution.
 */
library StandardExecutor {
    using ExecutionUtils for address;

    error TargetIsPlugin(address plugin);

    /// @dev Refer to IStandardExecutor
    function execute(address target, uint256 value, bytes calldata data) internal returns (bytes memory returnData) {
        // reverts if the target is a plugin because modular account should be calling plugin via execution functions
        // defined in IPluginExecutor
        if (ERC165Checker.supportsInterface(target, type(IPlugin).interfaceId)) {
            revert TargetIsPlugin(target);
        }
        return target.callWithReturnDataOrRevert(value, data);
    }

    /// @dev Refer to IStandardExecutor
    function executeBatch(Call[] calldata calls) internal returns (bytes[] memory returnData) {
        returnData = new bytes[](calls.length);
        for (uint256 i = 0; i < calls.length; ++i) {
            if (ERC165Checker.supportsInterface(calls[i].target, type(IPlugin).interfaceId)) {
                revert TargetIsPlugin(calls[i].target);
            }
            returnData[i] = calls[i].target.callWithReturnDataOrRevert(calls[i].value, calls[i].data);
        }
        return returnData;
    }
}
