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

import {BaseModule} from "../../../../../src/msca/6900/v0.8/modules/BaseModule.sol";
import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";
import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";

/// @notice Inspired by 6900 reference implementation with some modifications
contract DirectCallModule is BaseModule, IExecutionHookModule {
    string public constant NAME = "Direct Call To Account Test Module";
    bytes public constant TEST_DATA = bytes("success");
    bool public preHookRan = false;
    bool public postHookRan = false;

    error PreExecHookFailed();
    error PostExecHookFailed();

    // solhint-disable-next-line no-empty-blocks
    function onInstall(bytes calldata) external override {}

    // solhint-disable-next-line no-empty-blocks
    function onUninstall(bytes calldata) external override {}

    function directCall() external returns (bytes memory) {
        // call into account, then callback into module
        return IModularAccount(msg.sender).execute(address(this), 0, abi.encodeCall(this.getData, ()));
    }

    function getData() external pure returns (bytes memory) {
        return TEST_DATA;
    }

    function preExecutionHook(uint32, address sender, uint256, bytes calldata)
        external
        override
        returns (bytes memory)
    {
        if (sender != address(this)) {
            revert PreExecHookFailed();
        }
        preHookRan = true;
        return abi.encode(keccak256(TEST_DATA));
    }

    function postExecutionHook(uint32, bytes calldata preExecHookData) external override {
        if (abi.decode(preExecHookData, (bytes32)) != keccak256(TEST_DATA)) {
            revert PostExecHookFailed();
        }
        postHookRan = true;
    }

    function moduleId() external pure returns (string memory) {
        return "circle.direct-call-test-module.2.0.0";
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(BaseModule, IERC165) returns (bool) {
        return interfaceId == type(IExecutionHookModule).interfaceId || super.supportsInterface(interfaceId);
    }
}
