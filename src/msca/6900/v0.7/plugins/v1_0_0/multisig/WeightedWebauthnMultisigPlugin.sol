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

import {
    EIP1271_INVALID_SIGNATURE,
    EIP1271_VALID_SIGNATURE,
    PLUGIN_AUTHOR,
    PLUGIN_VERSION_1
} from "../../../../../../common/Constants.sol";
import {BaseMSCA} from "../../../account/BaseMSCA.sol";
import {
    ManifestAssociatedFunction,
    ManifestAssociatedFunctionType,
    ManifestFunction,
    PluginManifest,
    PluginMetadata,
    SelectorPermission
} from "../../../common/PluginManifest.sol";
import {BaseWeightedMultisigPlugin} from "./BaseWeightedMultisigPlugin.sol";
import {IWeightedMultisigPlugin} from "./IWeightedMultisigPlugin.sol";

import {
    AssociatedLinkedListSet,
    AssociatedLinkedListSetLib
} from "@modular-account-libs/libraries/AssociatedLinkedListSetLib.sol";
import {SetValue} from "@modular-account-libs/libraries/Constants.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {OwnerData, PublicKey, WebAuthnSigDynamicPart} from "../../../../../../common/CommonStructs.sol";
import {AddressBytesLib} from "../../../../../../libs/AddressBytesLib.sol";
import {PublicKeyLib} from "../../../../../../libs/PublicKeyLib.sol";
import {WebAuthnLib} from "../../../../../../libs/WebAuthnLib.sol";

import {BaseERC712CompliantModule} from "../../../../shared/erc712/BaseERC712CompliantModule.sol";
import {IStandardExecutor} from "../../../interfaces/IStandardExecutor.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/// @title Weighted Multisig Plugin That Supports Additional Webauthn Authentication
/// @author Circle
/// @notice This plugin adds a weighted threshold ownership scheme to a ERC6900 smart contract account.
contract WeightedWebauthnMultisigPlugin is BaseWeightedMultisigPlugin, BaseERC712CompliantModule {
    using ECDSA for bytes32;
    using AssociatedLinkedListSetLib for AssociatedLinkedListSet;
    using PublicKeyLib for PublicKey[];
    using PublicKeyLib for PublicKey;
    using AddressBytesLib for address;

    string internal constant _NAME = "Weighted Multisig Webauthn Plugin";
    bytes32 private constant _MULTISIG_PLUGIN_TYPEHASH =
        keccak256("CircleWeightedWebauthnMultisigMessage(bytes32 hash)");

    struct CheckNSignatureData {
        // lowestOffset of signature dynamic part, must locate after the signature constant part
        // 0 means we only have EOA signer so far
        uint256 lowestSigDynamicPartOffset;
        bytes30 lastOwner;
        bytes30 currentOwner;
        bool success;
        uint256 firstFailure;
        // first32Bytes of signature constant part
        bytes32 first32Bytes;
        // second32Bytes of signature constant part
        bytes32 second32Bytes;
    }

    constructor(address entryPoint) BaseWeightedMultisigPlugin(entryPoint) {}

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    /// @inheritdoc IWeightedMultisigPlugin
    function addOwners(
        address[] calldata ownersToAdd,
        uint256[] calldata weightsToAdd,
        PublicKey[] calldata publicKeyOwnersToAdd,
        uint256[] calldata pubicKeyWeightsToAdd,
        uint256 newThresholdWeight
    ) external override isInitialized(msg.sender) {
        (bytes30[] memory _totalOwners, OwnerData[] memory _ownersData) =
            _mergeOwnersData(ownersToAdd, weightsToAdd, publicKeyOwnersToAdd, pubicKeyWeightsToAdd);
        _addOwnersAndUpdateMultisigMetadata(_totalOwners, _ownersData, newThresholdWeight);
    }

    /// @inheritdoc IWeightedMultisigPlugin
    function removeOwners(
        address[] calldata ownersToRemove,
        PublicKey[] calldata publicKeyOwnersToRemove,
        uint256 newThresholdWeight
    ) external override isInitialized(msg.sender) {
        bytes30[] memory _totalOwners = _mergeOwners(ownersToRemove, publicKeyOwnersToRemove);
        _removeOwners(_totalOwners, newThresholdWeight);
    }

    /// @inheritdoc IWeightedMultisigPlugin
    function updateMultisigWeights(
        address[] calldata ownersToUpdate,
        uint256[] calldata newWeightsToUpdate,
        PublicKey[] calldata publicKeyOwnersToUpdate,
        uint256[] calldata pubicKeyNewWeightsToUpdate,
        uint256 newThresholdWeight
    ) external override isInitialized(msg.sender) {
        (bytes30[] memory _totalOwners, OwnerData[] memory _ownersData) =
            _mergeOwnersData(ownersToUpdate, newWeightsToUpdate, publicKeyOwnersToUpdate, pubicKeyNewWeightsToUpdate);
        _updateMultisigWeights(_totalOwners, _ownersData, newThresholdWeight);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃  Execution view functions   ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IERC1271
    function isValidSignature(bytes32 digest, bytes memory signature) external view override returns (bytes4) {
        bytes32 wrappedDigest = getReplaySafeMessageHash(msg.sender, digest);
        CheckNSignatureInput memory input = CheckNSignatureInput(wrappedDigest, wrappedDigest, msg.sender, signature);
        (bool success,) = checkNSignatures(input);
        return success ? EIP1271_VALID_SIGNATURE : EIP1271_INVALID_SIGNATURE;
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @notice Initialize plugin data for the modular account.
    /// @dev Called by the modular account during `installPlugin`.
    /// Constraints:
    /// - initialOwners must be non-empty
    /// - length of ownerWeights must == length of initialOwners
    /// - each weight must be between [1, 1000000], inclusive.
    /// each owner in ownersToAdd must not be address(0) or an existing owner.
    /// thresholdWeight must be nonzero.
    /// @param data bytes array to be decoded and used by the plugin to setup initial plugin data for the modular
    /// account. Format:
    /// address[] memory initialOwners, PublicKey[] memory initialPublicKeyOwners, uint256[] memory ownerWeights,
    /// uint256[] memory publicKeyOwnerWeights, uint256 thresholdWeight
    /// @dev The owner array cannot have 0 or duplicated addresses.
    function onInstall(bytes calldata data) external override isNotInitialized(msg.sender) {
        (
            address[] memory initialOwners,
            uint256[] memory ownerWeights,
            PublicKey[] memory initialPublicKeyOwners,
            uint256[] memory publicKeyOwnerWeights,
            uint256 thresholdWeight
        ) = abi.decode(data, (address[], uint256[], PublicKey[], uint256[], uint256));
        (bytes30[] memory _totalOwners, OwnerData[] memory _ownersData) =
            _mergeOwnersData(initialOwners, ownerWeights, initialPublicKeyOwners, publicKeyOwnerWeights);
        _onInstall(_totalOwners, _ownersData, thresholdWeight);
    }

    /// @notice Describe the contents and intended configuration of the plugin.
    /// @dev The manifest MUST stay constant over time.
    /// @return A manifest describing the contents and intended configuration of the plugin.
    function pluginManifest() external pure virtual override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new bytes4[](5);
        manifest.executionFunctions[0] = this.addOwners.selector;
        manifest.executionFunctions[1] = this.removeOwners.selector;
        manifest.executionFunctions[2] = this.updateMultisigWeights.selector;
        manifest.executionFunctions[3] = this.isValidSignature.selector;
        manifest.executionFunctions[4] = this.getReplaySafeMessageHash.selector;

        ManifestFunction memory ownerUserOpValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(FunctionId.USER_OP_VALIDATION_OWNER),
            dependencyIndex: 0 // Unused.
        });

        // Update native functions to use userOpValidationFunction provided by this plugin
        // The view functions `isValidSignature` and `getReplaySafeMessageHash` are excluded from being assigned a user
        // operation validation function since they should only be called via the runtime path.
        manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](8);
        manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.addOwners.selector,
            associatedFunction: ownerUserOpValidationFunction
        });

        manifest.userOpValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: this.removeOwners.selector,
            associatedFunction: ownerUserOpValidationFunction
        });

        manifest.userOpValidationFunctions[2] = ManifestAssociatedFunction({
            executionSelector: this.updateMultisigWeights.selector,
            associatedFunction: ownerUserOpValidationFunction
        });

        manifest.userOpValidationFunctions[3] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[4] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.executeBatch.selector,
            associatedFunction: ownerUserOpValidationFunction
        });

        manifest.userOpValidationFunctions[5] = ManifestAssociatedFunction({
            executionSelector: BaseMSCA.installPlugin.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[6] = ManifestAssociatedFunction({
            executionSelector: BaseMSCA.uninstallPlugin.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[7] = ManifestAssociatedFunction({
            executionSelector: UUPSUpgradeable.upgradeToAndCall.selector,
            associatedFunction: ownerUserOpValidationFunction
        });

        ManifestFunction memory alwaysAllowFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
            functionId: 0, // Unused.
            dependencyIndex: 0 // Unused.
        });

        ManifestFunction memory alwaysRevertFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: 0,
            dependencyIndex: 0 // Unused.
        });
        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](10);

        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.isValidSignature.selector,
            associatedFunction: alwaysAllowFunction
        });
        manifest.runtimeValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: this.getReplaySafeMessageHash.selector,
            associatedFunction: alwaysAllowFunction
        });
        manifest.runtimeValidationFunctions[2] = ManifestAssociatedFunction({
            executionSelector: this.addOwners.selector,
            associatedFunction: alwaysRevertFunction
        });
        manifest.runtimeValidationFunctions[3] = ManifestAssociatedFunction({
            executionSelector: this.removeOwners.selector,
            associatedFunction: alwaysRevertFunction
        });
        manifest.runtimeValidationFunctions[4] = ManifestAssociatedFunction({
            executionSelector: this.updateMultisigWeights.selector,
            associatedFunction: alwaysRevertFunction
        });
        manifest.runtimeValidationFunctions[5] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: alwaysRevertFunction
        });
        manifest.runtimeValidationFunctions[6] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.executeBatch.selector,
            associatedFunction: alwaysRevertFunction
        });
        manifest.runtimeValidationFunctions[7] = ManifestAssociatedFunction({
            executionSelector: BaseMSCA.installPlugin.selector,
            associatedFunction: alwaysRevertFunction
        });
        manifest.runtimeValidationFunctions[8] = ManifestAssociatedFunction({
            executionSelector: BaseMSCA.uninstallPlugin.selector,
            associatedFunction: alwaysRevertFunction
        });
        manifest.runtimeValidationFunctions[9] = ManifestAssociatedFunction({
            executionSelector: UUPSUpgradeable.upgradeToAndCall.selector,
            associatedFunction: alwaysRevertFunction
        });

        return manifest;
    }

    /// @notice Describe the metadata of the plugin.
    /// @dev This metadata MUST stay constant over time.
    /// @return A metadata struct describing the plugin.
    function pluginMetadata() external pure override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = _NAME;
        metadata.version = PLUGIN_VERSION_1;
        metadata.author = PLUGIN_AUTHOR;

        // Permission descriptions
        metadata.permissionDescriptors = new SelectorPermission[](3);
        metadata.permissionDescriptors[0] = SelectorPermission({
            functionSelector: this.addOwners.selector,
            permissionDescription: ADD_OWNERS_PERMISSION
        });
        metadata.permissionDescriptors[1] = SelectorPermission({
            functionSelector: this.updateMultisigWeights.selector,
            permissionDescription: UPDATE_MULTISIG_WEIGHTS_PERMISSION
        });
        metadata.permissionDescriptors[2] = SelectorPermission({
            functionSelector: this.removeOwners.selector,
            permissionDescription: REMOVE_OWNERS_PERMISSION
        });

        return metadata;
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃   Plugin only view functions     ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IWeightedMultisigPlugin
    function checkNSignatures(CheckNSignatureInput memory input)
        public
        view
        override
        returns (bool success, uint256 firstFailure)
    {
        if (input.signatures.length < _INDIVIDUAL_SIGNATURE_BYTES_LEN) {
            revert InvalidSigLength();
        }

        uint256 thresholdWeight = _ownerMetadata[input.account].thresholdWeight;
        // (Account is not initialized)
        if (thresholdWeight == 0) {
            revert InvalidThresholdWeight();
        }

        CheckNSignatureData memory checkNSignatureData;
        uint256 accumulatedWeight;
        // lastByte of signature constant part
        uint8 sigType;
        uint256 signatureCount;
        // if the digests differ, make sure we have exactly 1 sig on the actual digest
        uint256 numSigsOnActualDigest = (input.actualDigest != input.minimalDigest) ? 1 : 0;

        // tracks whether `signatures` is a complete and valid multisig signature
        checkNSignatureData.success = true;
        while (accumulatedWeight < thresholdWeight) {
            // Fail if the next 65 bytes would exceed signature length
            // or lowest dynamic part signature offset, where next 65 bytes is defined as
            // [signatureCount  _INDIVIDUAL_SIGNATURE_BYTES_LEN, signatureCount _INDIVIDUAL_SIGNATURE_BYTES_LEN +
            // _INDIVIDUAL_SIGNATURE_BYTES_LEN)
            // exclusive
            uint256 sigConstantPartEndPos =
                signatureCount * _INDIVIDUAL_SIGNATURE_BYTES_LEN + _INDIVIDUAL_SIGNATURE_BYTES_LEN;
            // do not fail if only have EOA signer so far
            if (
                (
                    checkNSignatureData.lowestSigDynamicPartOffset != 0
                        && sigConstantPartEndPos > checkNSignatureData.lowestSigDynamicPartOffset
                ) || sigConstantPartEndPos > input.signatures.length
            ) {
                if (checkNSignatureData.success) {
                    return (false, signatureCount);
                } else {
                    return (false, checkNSignatureData.firstFailure);
                }
            }

            (sigType, checkNSignatureData.first32Bytes, checkNSignatureData.second32Bytes) =
                _signatureSplit(input.signatures, signatureCount);

            // sigType >= 32 implies it's signed over the actual digest, so we deduct it according to encoding rule
            // if sigType > 60, it will eventually fail the ecdsa recover check below
            bytes32 digest;
            if (sigType >= 32) {
                digest = input.actualDigest;
                sigType -= 32;
                // can have unchecked since we check against zero at the end
                // underflow would wrap the value to 2 ^ 256 - 1
                unchecked {
                    // we now have one sig on actual digest
                    numSigsOnActualDigest -= 1;
                }
            } else {
                digest = input.minimalDigest;
            }

            // sigType == 0 is the contract signature case
            if (sigType == 0) {
                _validateContractSignature(checkNSignatureData, input, digest, signatureCount);
            } else if (sigType == 2) {
                _validateWebauthnSignature(checkNSignatureData, input, digest, signatureCount);
            } else {
                // reverts if signature has the wrong s value, wrong v value, or if it's a bad point on the k1 curve
                _validateEOASignature(checkNSignatureData, input, digest, signatureCount, sigType);
            }

            if (
                // if the signature is out of order or duplicate
                // or is not an owner
                checkNSignatureData.currentOwner <= checkNSignatureData.lastOwner
                    || !_owners.contains(input.account, SetValue.wrap(checkNSignatureData.currentOwner))
            ) {
                if (checkNSignatureData.success) {
                    checkNSignatureData.firstFailure = signatureCount;
                    checkNSignatureData.success = false;
                }
            }

            accumulatedWeight += ownerDataPerAccount[checkNSignatureData.currentOwner][input.account].weight;
            checkNSignatureData.lastOwner = checkNSignatureData.currentOwner;
            signatureCount++;
        }

        // if we need a signature on the actual digest, and we didn't get exactly one, revert
        // we avoid reverting early to facilitate fee estimation
        if (numSigsOnActualDigest != 0) {
            revert InvalidNumSigsOnActualDigest(numSigsOnActualDigest);
        }
        return (checkNSignatureData.success, checkNSignatureData.firstFailure);
    }

    function _validateContractSignature(
        CheckNSignatureData memory checkNSignatureData,
        CheckNSignatureInput memory input,
        bytes32 digest,
        uint256 signatureCount
    ) internal view {
        // first32Bytes contains the address to perform 1271 validation on
        address contractAddress = address(uint160(uint256(checkNSignatureData.first32Bytes)));
        // make sure upper bits are clean
        if (uint256(checkNSignatureData.first32Bytes) > uint256(uint160(contractAddress))) {
            revert InvalidAddress();
        }
        checkNSignatureData.currentOwner = contractAddress.toBytes30();
        if (ownerDataPerAccount[checkNSignatureData.currentOwner][input.account].addr != contractAddress) {
            if (checkNSignatureData.success) {
                checkNSignatureData.firstFailure = signatureCount;
                checkNSignatureData.success = false;
            }
        }
        // offset of current signature dynamic part
        // second32Bytes is the memory offset containing the signature
        uint256 sigDynamicPartOffset = uint256(checkNSignatureData.second32Bytes);
        // retrieve contract signature
        bytes memory contractSignature;
        {
            // offset of current signature dynamic part
            // second32Bytes is the memory offset containing the signature
            if (
                sigDynamicPartOffset > input.signatures.length || sigDynamicPartOffset < _INDIVIDUAL_SIGNATURE_BYTES_LEN
            ) {
                revert InvalidSigOffset();
            }
            // total length of current signature dynamic part
            uint256 sigDynamicPartTotalLen;
            // 0. load the signatures from CheckNSignatureInput struct
            // 1. load contractSignature content starting from the correct memory offset
            // 2. calculate total length including the content and the prefix storing the length
            assembly ("memory-safe") {
                let signatures := mload(add(input, 0x60))
                contractSignature := add(add(signatures, sigDynamicPartOffset), 0x20)
                sigDynamicPartTotalLen := add(mload(contractSignature), 0x20)
            }
            // signature dynamic part should not exceed the total signature length
            if (sigDynamicPartOffset + sigDynamicPartTotalLen > input.signatures.length) {
                revert InvalidContractSigLength();
            }
            if (
                sigDynamicPartOffset < checkNSignatureData.lowestSigDynamicPartOffset
                    || checkNSignatureData.lowestSigDynamicPartOffset == 0
            ) {
                checkNSignatureData.lowestSigDynamicPartOffset = sigDynamicPartOffset;
            }
        }
        if (!SignatureChecker.isValidERC1271SignatureNow(contractAddress, digest, contractSignature)) {
            if (checkNSignatureData.success) {
                checkNSignatureData.firstFailure = signatureCount;
                checkNSignatureData.success = false;
            }
        }
    }

    function _validateWebauthnSignature(
        CheckNSignatureData memory checkNSignatureData,
        CheckNSignatureInput memory input,
        bytes32 digest,
        uint256 signatureCount
    ) internal view {
        bytes memory sigDynamicPartBytes;
        // first32Bytes stores public key on-chain identifier
        checkNSignatureData.currentOwner = bytes30(uint240(uint256(checkNSignatureData.first32Bytes)));
        OwnerData memory currentOwnerData = ownerDataPerAccount[checkNSignatureData.currentOwner][input.account];
        uint256 x = currentOwnerData.publicKeyX;
        uint256 y = currentOwnerData.publicKeyY;
        // retrieve sig dynamic part bytes
        WebAuthnSigDynamicPart memory sigDynamicPart;
        // second32Bytes is the memory offset containing the sigDynamicPart
        uint256 sigDynamicPartOffset = uint256(checkNSignatureData.second32Bytes);
        {
            if (
                sigDynamicPartOffset > input.signatures.length || sigDynamicPartOffset < _INDIVIDUAL_SIGNATURE_BYTES_LEN
            ) {
                revert InvalidSigOffset();
            }
            uint256 sigDynamicPartTotalLen;
            // 0. load the signatures from CheckNSignatureInput struct
            // 1. load the content starting from the correct memory offset
            // 2. calculate total length including the content and the prefix storing the length
            assembly ("memory-safe") {
                let signatures := mload(add(input, 0x60))
                sigDynamicPartBytes := add(add(signatures, sigDynamicPartOffset), 0x20)
                sigDynamicPartTotalLen := add(mload(sigDynamicPartBytes), 0x20)
            }
            if (sigDynamicPartOffset + sigDynamicPartTotalLen > input.signatures.length) {
                revert InvalidSigLength();
            }
            if (
                sigDynamicPartOffset < checkNSignatureData.lowestSigDynamicPartOffset
                    || checkNSignatureData.lowestSigDynamicPartOffset == 0
            ) {
                checkNSignatureData.lowestSigDynamicPartOffset = sigDynamicPartOffset;
            }
            sigDynamicPart = abi.decode(sigDynamicPartBytes, (WebAuthnSigDynamicPart));
        }
        if (
            !WebAuthnLib.verify({
                challenge: abi.encode(digest),
                webAuthnData: sigDynamicPart.webAuthnData,
                r: sigDynamicPart.r,
                s: sigDynamicPart.s,
                x: x,
                y: y
            })
        ) {
            if (checkNSignatureData.success) {
                checkNSignatureData.firstFailure = signatureCount;
                checkNSignatureData.success = false;
            }
        }
    }

    function _validateEOASignature(
        CheckNSignatureData memory checkNSignatureData,
        CheckNSignatureInput memory input,
        bytes32 digest,
        uint256 signatureCount,
        uint8 sigType
    ) internal view {
        // reverts if signature has the wrong s value, wrong v value, or if it's a bad point on the k1 curve
        address signer = digest.recover(sigType, checkNSignatureData.first32Bytes, checkNSignatureData.second32Bytes);
        checkNSignatureData.currentOwner = signer.toBytes30();
        if (ownerDataPerAccount[checkNSignatureData.currentOwner][input.account].addr != signer) {
            if (checkNSignatureData.success) {
                checkNSignatureData.firstFailure = signatureCount;
                checkNSignatureData.success = false;
            }
        }
    }

    /// @inheritdoc BaseERC712CompliantModule
    function _getModuleTypeHash() internal pure override returns (bytes32) {
        return _MULTISIG_PLUGIN_TYPEHASH;
    }

    /// @inheritdoc BaseERC712CompliantModule
    function _getModuleIdHash() internal pure override returns (bytes32) {
        return keccak256(abi.encodePacked(_NAME, PLUGIN_VERSION_1));
    }
}
