/*
 * Copyright 2025 Circle Internet Group, Inc. All rights reserved.
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

import {SelectorRegistryLib} from "../../../../../src/msca/6900/v0.8/libs/SelectorRegistryLib.sol";

import {TestUtils} from "../../../../util/TestUtils.sol";
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

import {BaseMSCA} from "../../../../../src/msca/6900/v0.8/account/BaseMSCA.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC777Recipient} from "@openzeppelin/contracts/interfaces/IERC777Recipient.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

contract SelectorRegistryLibTest is TestUtils {
    function testNonWrappedNativeExecutionFunction() public pure {
        _verifyWrappedNativeExecutionFunction();
    }

    function testWrappedNativeExecutionFunction() public pure {
        _verifyWrappedNativeExecutionFunction();
    }

    function testNativeExecutionFunction() public pure {
        _verifyNativeExecutionFunction();
    }

    function testNativeViewFunction() public pure {
        _verifyNativeViewFunction();
    }

    function testNativeFunction() public pure {
        _verifyNativeExecutionFunction();
        _verifyNativeViewFunction();
    }

    function testERC4337Function() public pure {
        _verifyERC4337Function();
    }

    function testIModuleFunction() public pure {
        _verifyIModuleFunction();
    }

    function testInvalidSelector() public pure {
        bytes4 invalidSelector = bytes4(keccak256("nonExistentFunction()"));
        assertFalse(SelectorRegistryLib._isNativeFunction(invalidSelector));
        assertFalse(SelectorRegistryLib._isERC4337Function(invalidSelector));
        assertFalse(SelectorRegistryLib._isIModuleFunction(invalidSelector));
        assertFalse(SelectorRegistryLib._isNativeViewFunction(invalidSelector));
        assertFalse(SelectorRegistryLib._isWrappedNativeExecutionFunction(invalidSelector));
    }

    function testOverlappingSelectors() public pure {
        // Assuming selector overlaps are handled correctly
        bytes4 validSelector = IModularAccount.execute.selector;
        bytes4 overlappingSelector = bytes4(keccak256("execute(bytes)")); // Potential overlap
        assertTrue(SelectorRegistryLib._isNativeExecutionFunction(validSelector));
        assertFalse(SelectorRegistryLib._isNativeExecutionFunction(overlappingSelector));
    }

    function _verifyNonWrappedNativeExecutionFunction() internal pure {
        assertTrue(SelectorRegistryLib._isNonWrappedNativeExecutionFunction(IAccountExecute.executeUserOp.selector));
        assertTrue(
            SelectorRegistryLib._isNonWrappedNativeExecutionFunction(
                IModularAccount.executeWithRuntimeValidation.selector
            )
        );
    }

    function _verifyWrappedNativeExecutionFunction() internal pure {
        assertTrue(SelectorRegistryLib._isWrappedNativeExecutionFunction(IModularAccount.execute.selector));
        assertTrue(SelectorRegistryLib._isWrappedNativeExecutionFunction(IModularAccount.executeBatch.selector));
        assertTrue(SelectorRegistryLib._isWrappedNativeExecutionFunction(IModularAccount.installExecution.selector));
        assertTrue(SelectorRegistryLib._isWrappedNativeExecutionFunction(IModularAccount.uninstallExecution.selector));
        assertTrue(SelectorRegistryLib._isWrappedNativeExecutionFunction(UUPSUpgradeable.upgradeToAndCall.selector));
        assertTrue(SelectorRegistryLib._isWrappedNativeExecutionFunction(IModularAccount.installValidation.selector));
        assertTrue(SelectorRegistryLib._isWrappedNativeExecutionFunction(IModularAccount.uninstallValidation.selector));
    }

    function _verifyNativeExecutionFunction() internal pure {
        _verifyWrappedNativeExecutionFunction();
        _verifyNonWrappedNativeExecutionFunction();
    }

    function _verifyNativeViewFunction() internal pure {
        assertTrue(SelectorRegistryLib._isNativeViewFunction(BaseMSCA.entryPoint.selector));
        assertTrue(SelectorRegistryLib._isNativeViewFunction(IModularAccount.accountId.selector));
        assertTrue(SelectorRegistryLib._isNativeViewFunction(UUPSUpgradeable.proxiableUUID.selector));
        assertTrue(SelectorRegistryLib._isNativeViewFunction(IModularAccountView.getExecutionData.selector));
        assertTrue(SelectorRegistryLib._isNativeViewFunction(IModularAccountView.getValidationData.selector));
        assertTrue(SelectorRegistryLib._isNativeViewFunction(IAccount.validateUserOp.selector));
        assertTrue(SelectorRegistryLib._isNativeViewFunction(IERC1155Receiver.onERC1155BatchReceived.selector));
        assertTrue(SelectorRegistryLib._isNativeViewFunction(IERC1155Receiver.onERC1155Received.selector));
        assertTrue(SelectorRegistryLib._isNativeViewFunction(IERC1271.isValidSignature.selector));
        assertTrue(SelectorRegistryLib._isNativeViewFunction(IERC165.supportsInterface.selector));
        assertTrue(SelectorRegistryLib._isNativeViewFunction(IERC721Receiver.onERC721Received.selector));
        assertTrue(SelectorRegistryLib._isNativeViewFunction(IERC777Recipient.tokensReceived.selector));
    }

    function _verifyERC4337Function() internal pure {
        assertTrue(SelectorRegistryLib._isERC4337Function(IAggregator.validateSignatures.selector));
        assertTrue(SelectorRegistryLib._isERC4337Function(IAggregator.validateUserOpSignature.selector));
        assertTrue(SelectorRegistryLib._isERC4337Function(IAggregator.aggregateSignatures.selector));
        assertTrue(SelectorRegistryLib._isERC4337Function(IPaymaster.validatePaymasterUserOp.selector));
        assertTrue(SelectorRegistryLib._isERC4337Function(IPaymaster.postOp.selector));
    }

    function _verifyIModuleFunction() internal pure {
        assertTrue(SelectorRegistryLib._isIModuleFunction(IModule.onInstall.selector));
        assertTrue(SelectorRegistryLib._isIModuleFunction(IModule.onUninstall.selector));
        assertTrue(SelectorRegistryLib._isIModuleFunction(IModule.moduleId.selector));
        assertTrue(SelectorRegistryLib._isIModuleFunction(IValidationHookModule.preUserOpValidationHook.selector));
        assertTrue(SelectorRegistryLib._isIModuleFunction(IValidationModule.validateUserOp.selector));
        assertTrue(SelectorRegistryLib._isIModuleFunction(IValidationModule.validateRuntime.selector));
        assertTrue(SelectorRegistryLib._isIModuleFunction(IValidationModule.validateSignature.selector));
        assertTrue(SelectorRegistryLib._isIModuleFunction(IValidationHookModule.preRuntimeValidationHook.selector));
        assertTrue(SelectorRegistryLib._isIModuleFunction(IValidationHookModule.preSignatureValidationHook.selector));
        assertTrue(SelectorRegistryLib._isIModuleFunction(IExecutionHookModule.preExecutionHook.selector));
        assertTrue(SelectorRegistryLib._isIModuleFunction(IExecutionHookModule.postExecutionHook.selector));
        assertTrue(SelectorRegistryLib._isIModuleFunction(IExecutionModule.executionManifest.selector));
    }
}
