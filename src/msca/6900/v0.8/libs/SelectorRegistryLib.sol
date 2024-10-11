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

import {IExecutionHookModule} from "../interfaces/IExecutionHookModule.sol";
import {IModularAccountView} from "../interfaces/IModularAccountView.sol";
import {IModule} from "../interfaces/IModule.sol";

import {IModularAccount} from "../interfaces/IModularAccount.sol";

import {IValidationHookModule} from "../interfaces/IValidationHookModule.sol";
import {IValidationModule} from "../interfaces/IValidationModule.sol";
import {IAggregator} from "@account-abstraction/contracts/interfaces/IAggregator.sol";
import {IPaymaster} from "@account-abstraction/contracts/interfaces/IPaymaster.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {IExecutionModule} from "../interfaces/IExecutionModule.sol";

import {IAccount} from "@account-abstraction/contracts/interfaces/IAccount.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

library SelectorRegistryLib {
    /**
     * @dev Check if the selector is native execution function that allows global validation.
     * @param selector the function selector.
     */
    function _isGlobalValidationAllowedNativeExecutionFunction(bytes4 selector) internal pure returns (bool) {
        return selector == IModularAccount.execute.selector || selector == IModularAccount.executeBatch.selector
            || selector == IModularAccount.installExecution.selector
            || selector == IModularAccount.uninstallExecution.selector
            || selector == UUPSUpgradeable.upgradeToAndCall.selector;
    }

    /**
     * @dev Check if the selector is native execution function.
     * @param selector the function selector.
     */
    function _isNativeExecutionFunction(bytes4 selector) internal pure returns (bool) {
        return _isGlobalValidationAllowedNativeExecutionFunction(selector)
            || selector == IModularAccount.installValidation.selector
            || selector == IModularAccount.uninstallValidation.selector;
    }

    /**
     * @dev Check if the selector is for native function.
     * @param selector the function selector.
     */
    function _isNativeFunction(bytes4 selector) internal pure returns (bool) {
        return _isNativeExecutionFunction(selector) || selector == IModularAccount.executeWithRuntimeValidation.selector
            || selector == IModularAccount.accountId.selector || selector == UUPSUpgradeable.proxiableUUID.selector
        // check against IERC165 methods
        || selector == IERC165.supportsInterface.selector
        // check against IModularAccountView methods
        || selector == IModularAccountView.getExecutionData.selector
            || selector == IModularAccountView.getValidationData.selector || selector == IAccount.validateUserOp.selector;
    }

    function _isErc4337Function(bytes4 selector) internal pure returns (bool) {
        return selector == IAggregator.validateSignatures.selector
            || selector == IAggregator.validateUserOpSignature.selector
            || selector == IAggregator.aggregateSignatures.selector
            || selector == IPaymaster.validatePaymasterUserOp.selector || selector == IPaymaster.postOp.selector;
    }

    function _isIModuleFunction(bytes4 selector) internal pure returns (bool) {
        return selector == IModule.onInstall.selector || selector == IModule.onUninstall.selector
            || selector == IModule.moduleId.selector || selector == IValidationHookModule.preUserOpValidationHook.selector
            || selector == IValidationModule.validateUserOp.selector
            || selector == IValidationModule.validateRuntime.selector
            || selector == IValidationModule.validateSignature.selector
            || selector == IValidationHookModule.preRuntimeValidationHook.selector
            || selector == IExecutionHookModule.preExecutionHook.selector
            || selector == IExecutionHookModule.postExecutionHook.selector
            || selector == IExecutionModule.executionManifest.selector;
    }
}
