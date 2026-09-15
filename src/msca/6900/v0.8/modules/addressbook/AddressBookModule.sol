/*
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

import {SIG_VALIDATION_SUCCEEDED} from "../../../../../common/Constants.sol";

import {Unsupported} from "../../../../../common/Errors.sol";
import {CastLib} from "../../../../../libs/CastLib.sol";
import {RecipientAddressLib} from "../../../../../libs/RecipientAddressLib.sol";

import {Call} from "../../common/Structs.sol";

import {BaseModule} from "../BaseModule.sol";
import {IAddressBookModule} from "./IAddressBookModule.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {
    ExecutionManifest,
    ManifestExecutionFunction
} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";

import {IExecutionModule} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";

import {
    AssociatedLinkedListSet,
    AssociatedLinkedListSetLib
} from "@modular-account-libs/libraries/AssociatedLinkedListSetLib.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";

/**
 * @dev This module serves as an ERC-6900 hook to validate recipients of token assets in an opinionated fashion;
 *      - For erc20 tokens only the `transfer(address,uint256)`, `transferFrom(address,address,uint256)`,
 * `approve(address,uint256)`, `increaseAllowance(address,uint256)`, `decreaseAllowance(address,uint256)` methods are
 * checked.
 *      - For erc1155 tokens only the `setApprovalForAll(address,bool)`,
 * `safeTransferFrom(address,address,uint256,uint256,bytes)`,
 * `safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)` methods are checked.
 *      - For erc721 tokens only the `safeTransferFrom(address,address,uint256)`,
 * `safeTransferFrom(address,address,uint256,bytes)`, `transferFrom(address,address,uint256)`,
 * `approve(address,uint256)`, `setApprovalForAll(address,bool)` methods are checked.
 *
 *      If a call contains data and value is 0 and selector is not checked, the transaction will be allowed to continue.
 *      This module can be paired with another validation hook module to force that interactions with token contracts
 * only use selectors that are checked in this hook module.
 *
 *      Design:
 *      1. For token transfers, verify support for the function selector; if unsupported, allow bypass. This
 * validation is bypassed for native transfers.
 *      2. Extract the recipient's address from the transaction's calldata for token transfers, or from the target for
 * native transfers.
 *      3. If the recipient's address is not specified (== address(0)) within the calldata, allow bypass.
 *      4. Given a recipient is successfully parsed out of calldata intended for token contract or parsed out of native
 * transfer, validate the recipient against the on-chain address book; validate the target if value > 0 && recipient !=
 * target; unauthorized addresses result in transaction rejection.
 *      5. If the recipient is authorized, proceed with the transaction.
 *
 *      Misc:
 *      - hook entityId is ignored in this module, so this hook will treat every call from the 6900 account the same
 * way.
 */
contract AddressBookModule is IAddressBookModule, BaseModule {
    using AssociatedLinkedListSetLib for AssociatedLinkedListSet;
    using RecipientAddressLib for bytes;

    // act as a safety mechanism if a module is blocking uninstallation
    uint16 internal constant _MAX_RECIPIENTS_TO_DELETE = 5000;

    // Mapping from hook entity id to allowed recipients set by account address
    AssociatedLinkedListSet internal _allowedRecipients;

    /**
     * @dev Add allowed recipients/approved spenders.
     * Can only be called by the current msg.sender.
     */
    function addAllowedRecipients(address[] calldata recipients) external {
        _addRecipients(recipients);
        emit AllowedAddressesAdded(msg.sender, recipients);
    }

    /**
     * @dev Remove allowed recipients/approved spenders.
     * Can only be called by the current msg.sender.
     */
    function removeAllowedRecipients(address[] calldata recipients) external {
        uint256 length = recipients.length;
        for (uint256 i = 0; i < length; ++i) {
            if (!_allowedRecipients.tryRemove(msg.sender, CastLib.toSetValue(recipients[i]))) {
                revert FailToRemoveRecipient(msg.sender, recipients[i]);
            }
        }
        emit AllowedAddressesRemoved(msg.sender, recipients);
    }

    /**
     * @dev Returns the allowed recipients/approved spenders of the current MSCA.
     */
    function getAllowedRecipients(address account) external view returns (address[] memory) {
        return _getAllowedRecipients(account);
    }

    /// @inheritdoc IModule
    function onInstall(bytes calldata data) external virtual override {
        if (data.length != 0) {
            address[] memory recipients = abi.decode(data, (address[]));
            _addRecipients(recipients);
            emit AllowedAddressesAdded(msg.sender, recipients);
        }
    }

    /// @inheritdoc IModule
    function onUninstall(bytes calldata data) external override {
        (data);
        address[] memory recipients = _getAllowedRecipients(msg.sender);
        // Clearing up module storage is optional for the caller;
        // callers should call removeAllowedRecipients in batches if they
        // need to clear module storage.
        if (recipients.length < _MAX_RECIPIENTS_TO_DELETE) {
            _allowedRecipients.clear(msg.sender);
            emit AllowedAddressesRemoved(msg.sender, recipients);
        } else {
            emit AllowedAddressesNotRemoved(msg.sender);
        }
    }

    /// @inheritdoc IValidationHookModule
    function preUserOpValidationHook(uint32, PackedUserOperation calldata userOp, bytes32)
        external
        view
        override
        assertNoData(userOp.signature)
        returns (uint256 validationData)
    {
        // Extract selector used to execute uo on account and calldata from `userOp.callData`.
        (bytes4 selector, bytes memory callDataWithoutSelector) =
            _validationPhaseGetSelectorAndCalldata(userOp.callData);
        verifyAllowedTargetOrRecipient(selector, callDataWithoutSelector);
        return SIG_VALIDATION_SUCCEEDED;
    }

    /// @inheritdoc IValidationHookModule
    function preRuntimeValidationHook(uint32, address, uint256, bytes calldata data, bytes calldata)
        external
        view
        override
    {
        return verifyAllowedTargetOrRecipient(bytes4(data[:4]), data[4:]);
    }

    function preSignatureValidationHook(uint32 entityId, address sender, bytes32 hash, bytes calldata signature)
        external
        pure
        override
    {
        (entityId, sender, hash, signature);
        revert Unsupported();
    }

    function executionManifest() external pure override returns (ExecutionManifest memory) {
        ExecutionManifest memory manifest;
        manifest.executionFunctions = new ManifestExecutionFunction[](2);
        // TODO: allow global validation
        manifest.executionFunctions[0] = ManifestExecutionFunction({
            executionSelector: this.addAllowedRecipients.selector,
            skipRuntimeValidation: true,
            allowGlobalValidation: false
        });
        manifest.executionFunctions[1] = ManifestExecutionFunction({
            executionSelector: this.removeAllowedRecipients.selector,
            skipRuntimeValidation: false,
            allowGlobalValidation: true
        });
        manifest.interfaceIds = new bytes4[](1);
        manifest.interfaceIds[0] = type(IAddressBookModule).interfaceId;
        return manifest;
    }

    /// @inheritdoc IModule
    function moduleId() external pure returns (string memory) {
        return "avara.address-book-module.1.0.0";
    }

    /// @inheritdoc BaseModule
    function supportsInterface(bytes4 interfaceId) public view override(BaseModule, IERC165) returns (bool) {
        return interfaceId == type(IAddressBookModule).interfaceId
            || interfaceId == type(IValidationHookModule).interfaceId || interfaceId == type(IExecutionModule).interfaceId
            || super.supportsInterface(interfaceId);
    }

    /// @dev Verify if the target or recipient is allowed.
    /// @dev Reverts if a native or token transfer recipient is found and the target/recipient is not allowed.
    /// @param selector The selector used to execute the user operation or batch user operation.
    /// @param callDataWithoutSelector The call data without the selector.
    function verifyAllowedTargetOrRecipient(bytes4 selector, bytes memory callDataWithoutSelector) public view {
        if (selector == IModularAccount.execute.selector) {
            (address target, uint256 targetValue, bytes memory targetData) =
                abi.decode(callDataWithoutSelector, (address, uint256, bytes));
            _verifyAllowedTargetOrRecipient(target, targetValue, targetData);
            return;
        } else if (selector == IModularAccount.executeBatch.selector) {
            Call[] memory calls = abi.decode(callDataWithoutSelector, (Call[]));
            uint256 length = calls.length;
            for (uint256 i = 0; i < length; ++i) {
                _verifyAllowedTargetOrRecipient(calls[i].target, calls[i].value, calls[i].data);
            }
            return;
        }
        revert Unsupported();
    }

    function _verifyAllowedTargetOrRecipient(address target, uint256 value, bytes memory data) internal view {
        if (
            value == 0 && !data.containsERC20Methods() && !data.containsERC1155Methods()
                && !data.containsERC721Methods()
        ) {
            // No transfer of assets, so no need to verify the recipient.
            return;
        }
        // At this point we know that the calldata contains asset transfer logic.
        address recipient = _getTargetOrRecipient(target, value, data);
        if (!_allowedRecipients.contains(msg.sender, CastLib.toSetValue(recipient))) {
            revert UnauthorizedRecipient(msg.sender, recipient);
        }
    }

    /// @dev Add recipients.
    /// @param recipientsToAdd The recipients to add.
    function _addRecipients(address[] memory recipientsToAdd) internal {
        uint256 length = recipientsToAdd.length;
        for (uint256 i = 0; i < length; ++i) {
            if (!_allowedRecipients.tryAdd(msg.sender, CastLib.toSetValue(recipientsToAdd[i]))) {
                revert FailToAddRecipient(msg.sender, recipientsToAdd[i]);
            }
        }
    }

    /// @dev Get all allowed recipients for an account.
    /// @param account The account.
    /// @return The allowed recipients.
    function _getAllowedRecipients(address account) internal view returns (address[] memory) {
        return CastLib.toAddressArray(_allowedRecipients.getAll(account));
    }

    /// @dev We do not permit sending native assets to a token contract while simultaneously interacting with it.
    /// @dev Get the recipient of the token transfer (ERC20, ERC1155, ERC721) or native asset transfer.
    /// @dev Assumes the calldata contains asset transfer data.
    /// @dev Reverts if any of the found token recipients are not in the account's address book or if the recipient is
    /// address(0).
    /// @param target The target address from a call parsed out of the execute/executeBatch function call.
    /// @param value The native asset value from a call parsed out of the execute/executeBatch function call.
    /// @param data The data from a call parsed out of the execute/executeBatch function call. If the target for this
    /// call is a token contract.
    /// @return The recipient of the token transfer or native asset transfer.
    function _getTargetOrRecipient(address target, uint256 value, bytes memory data) internal view returns (address) {
        if (value != 0) {
            // For native asset transfers, we require the calldata to be empty.
            if (data.length != 0) {
                revert CallDataIsNotEmpty(msg.sender, target, value, data);
            }
            if (target == address(0)) {
                // We do not allow sending native assets to address(0).
                revert UnauthorizedRecipient(msg.sender, target);
            }
            return target;
        } else {
            // For token calls, we require that the target address contains code.
            if (target.code.length == 0) {
                revert InvalidTargetCodeLength(msg.sender, target, value, data);
            }
            // The helper function will first check if the function selector is supported.
            address recipient = data.getERC20TokenRecipient();
            if (recipient == address(0)) {
                recipient = data.getERC1155TokenRecipient();
            }
            if (recipient == address(0)) {
                recipient = data.getERC721TokenRecipient();
            }
            if (recipient == address(0)) {
                revert UnauthorizedRecipient(msg.sender, recipient);
            }
            return recipient;
        }
    }
}
