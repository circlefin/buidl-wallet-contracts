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

import {IAccount} from "@account-abstraction/contracts/interfaces/IAccount.sol";
import {IAccountExecute} from "@account-abstraction/contracts/interfaces/IAccountExecute.sol";
import {IAggregator} from "@account-abstraction/contracts/interfaces/IAggregator.sol";

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {IPaymaster} from "@account-abstraction/contracts/interfaces/IPaymaster.sol";
import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";
import {IExecutionModule} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IModularAccountView} from "@erc6900/reference-implementation/interfaces/IModularAccountView.sol";
import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";

import {BaseMSCA} from "../account/BaseMSCA.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC777Recipient} from "@openzeppelin/contracts/interfaces/IERC777Recipient.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

library SelectorRegistryLib {
    /**
     * @dev Determines whether a function is a native execution function with the validateNativeFunction modifier,
     * indicating that it triggers execution hooks (if any) associated with execution selector from msg.sig.
     * @param selector the function selector.
     */
    function _isWrappedNativeExecutionFunction(bytes4 selector) internal pure returns (bool) {
        return selector == IModularAccount.execute.selector || selector == IModularAccount.executeBatch.selector
            || selector == IModularAccount.installExecution.selector
            || selector == IModularAccount.uninstallExecution.selector
            || selector == UUPSUpgradeable.upgradeToAndCall.selector
            || selector == IModularAccount.installValidation.selector
            || selector == IModularAccount.uninstallValidation.selector;
    }

    /**
     * @dev Determines whether a function is a native execution function without the validateNativeFunction modifier,
     * indicating that it triggers execution hooks (if any) associated with the validation function.
     * @param selector the function selector.
     */
    function _isNonWrappedNativeExecutionFunction(bytes4 selector) internal pure returns (bool) {
        return selector == IAccountExecute.executeUserOp.selector
            || selector == IModularAccount.executeWithRuntimeValidation.selector;
    }

    /**
     * @dev Check whether a selector is a native execution function that allows global validation.
     * @param selector the function selector.
     */
    function _isNativeExecutionFunction(bytes4 selector) internal pure returns (bool) {
        return _isWrappedNativeExecutionFunction(selector) || _isNonWrappedNativeExecutionFunction(selector);
    }

    /**
     * @dev Check whether a selector is a native view function.
     * @param selector the function selector.
     */
    function _isNativeViewFunction(bytes4 selector) internal pure returns (bool) {
        return selector == BaseMSCA.entryPoint.selector || selector == IModularAccount.accountId.selector
            || selector == UUPSUpgradeable.proxiableUUID.selector
            || selector == IModularAccountView.getExecutionData.selector
            || selector == IModularAccountView.getValidationData.selector || selector == IAccount.validateUserOp.selector
            || selector == IERC165.supportsInterface.selector || selector == IERC1271.isValidSignature.selector
            || selector == IERC1155Receiver.onERC1155BatchReceived.selector
            || selector == IERC1155Receiver.onERC1155Received.selector
            || selector == IERC721Receiver.onERC721Received.selector || selector == IERC777Recipient.tokensReceived.selector;
    }

    /**
     * @dev Check if the selector is for native function.
     * @param selector the function selector.
     */
    function _isNativeFunction(bytes4 selector) internal pure returns (bool) {
        return _isNativeExecutionFunction(selector) || _isNativeViewFunction(selector);
    }

    function _isERC4337Function(bytes4 selector) internal pure returns (bool) {
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
            || selector == IValidationHookModule.preSignatureValidationHook.selector
            || selector == IExecutionHookModule.preExecutionHook.selector
            || selector == IExecutionHookModule.postExecutionHook.selector
            || selector == IExecutionModule.executionManifest.selector;
    }
}
