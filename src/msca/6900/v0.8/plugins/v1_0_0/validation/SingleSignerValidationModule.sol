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

import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {BasePlugin} from "../../BasePlugin.sol";
import {ISingleSignerValidationModule} from "./ISingleSignerValidationModule.sol";
import {IPlugin} from "../../../interfaces/IPlugin.sol";
import {IValidation} from "../../../interfaces/IValidation.sol";
import {UnauthorizedCaller} from "../../../../shared/common/Errors.sol";
import {PluginManifest, PluginMetadata, SelectorPermission} from "../../../common/PluginManifest.sol";
import {
    EIP1271_INVALID_SIGNATURE,
    EIP1271_VALID_SIGNATURE,
    SIG_VALIDATION_FAILED,
    SIG_VALIDATION_SUCCEEDED,
    PLUGIN_VERSION_1,
    PLUGIN_AUTHOR
} from "../../../../../../common/Constants.sol";
import {BaseERC712CompliantModule} from "../../thirdparty/erc712/BaseERC712CompliantModule.sol";

/**
 * @notice This validation module allows the MSCA to be validated by a ECDSA secp256k1 curve signature or a 1271
 * signature.
 * `entityId` is required.
 */
contract SingleSignerValidationModule is ISingleSignerValidationModule, BasePlugin, BaseERC712CompliantModule {
    using MessageHashUtils for bytes32;

    // include author and version in the name for convenience
    string public constant NAME = "Circle_Single_Signer_Validation_Module_V1";
    string internal constant _TRANSFER_SIGNER = "Transfer_Signer";
    bytes32 private constant _HASHED_NAME = keccak256(bytes(NAME));
    bytes32 private constant _HASHED_VERSION = keccak256(bytes(PLUGIN_VERSION_1));
    bytes32 private constant _PLUGIN_TYPEHASH = keccak256("SingleSignerValidationMessage(bytes message)");
    // entityId => account => signer
    // this module supports composition that other validation can rely on entity id in this validation to validate
    // the signature
    // `account` is included in the parameter of validateRuntime/validateSignature or userOp.sender of validateUserOp
    mapping(uint32 entityId => mapping(address account => address)) public mscaSigners;

    /**
     * @inheritdoc ISingleSignerValidationModule
     */
    function transferSigner(uint32 entityId, address newSigner) external {
        _transferSigner(entityId, newSigner);
    }

    /// @inheritdoc IPlugin
    function onInstall(bytes calldata data) external override {
        (uint32 entityId, address owner) = abi.decode(data, (uint32, address));
        _transferSigner(entityId, owner);
    }

    /// @inheritdoc IPlugin
    function onUninstall(bytes calldata data) external override {
        uint32 entityId = abi.decode(data, (uint32));
        _transferSigner(entityId, address(0));
    }

    /// @inheritdoc IValidation
    function validateUserOp(uint32 entityId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256 validationData)
    {
        if (
            SignatureChecker.isValidSignatureNow(
                mscaSigners[entityId][userOp.sender], userOpHash.toEthSignedMessageHash(), userOp.signature
            )
        ) {
            return SIG_VALIDATION_SUCCEEDED;
        }
        return SIG_VALIDATION_FAILED;
    }

    /// @inheritdoc IValidation
    function validateRuntime(
        address account,
        uint32 entityId,
        address sender,
        uint256 value,
        bytes calldata data,
        bytes calldata authorization
    ) external view override {
        (value, data, authorization);
        // the sender should be the signer of the account or itself
        if (sender == mscaSigners[entityId][account] || sender == account) {
            return;
        }
        revert UnauthorizedCaller();
    }

    /// @inheritdoc IValidation
    /// @notice Note that the hash is wrapped in an EIP-712 struct to prevent cross-account replay attacks. The
    /// replay-safe hash may be retrieved by calling the public function `getReplaySafeMessageHash`.
    function validateSignature(address account, uint32 entityId, address sender, bytes32 hash, bytes memory signature)
        external
        view
        override
        returns (bytes4)
    {
        (sender);
        bytes32 replaySafeHash = getReplaySafeMessageHash(account, hash);
        if (SignatureChecker.isValidSignatureNow(mscaSigners[entityId][account], replaySafeHash, signature)) {
            return EIP1271_VALID_SIGNATURE;
        }
        return EIP1271_INVALID_SIGNATURE;
    }

    /// @inheritdoc IPlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;
        return manifest;
    }

    /// @inheritdoc IPlugin
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = NAME;
        metadata.version = PLUGIN_VERSION_1;
        metadata.author = PLUGIN_AUTHOR;

        // Permission descriptions
        metadata.permissionDescriptors = new SelectorPermission[](1);
        metadata.permissionDescriptors[0] = SelectorPermission({
            functionSelector: this.transferSigner.selector,
            permissionDescription: _TRANSFER_SIGNER
        });
        return metadata;
    }

    /// @inheritdoc BasePlugin
    function supportsInterface(bytes4 interfaceId) public view override(BasePlugin, IERC165) returns (bool) {
        return interfaceId == type(ISingleSignerValidationModule).interfaceId || super.supportsInterface(interfaceId);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferSigner(uint32 entityId, address newOwner) internal {
        address oldOwner = mscaSigners[entityId][msg.sender];
        mscaSigners[entityId][msg.sender] = newOwner;
        emit SignerTransferred(msg.sender, entityId, newOwner, oldOwner);
    }

    /// @inheritdoc BaseERC712CompliantModule
    function _getModuleTypeHash() internal pure override returns (bytes32) {
        return _PLUGIN_TYPEHASH;
    }

    /// @inheritdoc BaseERC712CompliantModule
    function _getModuleName() internal pure override returns (bytes32) {
        return _HASHED_NAME;
    }

    /// @inheritdoc BaseERC712CompliantModule
    function _getModuleVersion() internal pure override returns (bytes32) {
        return _HASHED_VERSION;
    }
}
