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

import {PublicKey} from "../../../../../common/CommonStructs.sol";
import {
    AccountMetadata,
    CheckNSignaturesRequest,
    CheckNSignaturesResponse,
    SignerMetadata,
    SignerMetadataWithId
} from "./MultisigStructs.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";

/// @title Weighted Multisig Validation Module Interface
/// @author Circle
/// @notice This module adds a weighted threshold validation module to a ERC6900 smart contract account.
interface IWeightedMultisigValidationModule is IValidationModule {
    event AccountMetadataUpdated(
        address indexed account, uint32 indexed entityId, AccountMetadata oldMetadata, AccountMetadata newMetadata
    );
    event SignersAdded(address indexed account, uint32 indexed entityId, SignerMetadataWithId[] addedSigners);
    event SignersRemoved(address indexed account, uint32 indexed entityId, SignerMetadataWithId[] removedSigners);
    event SignersUpdated(address indexed account, uint32 indexed entityId, SignerMetadataWithId[] updatedSigners);

    error InvalidSignerWeight(uint32 entityId, address account, bytes30 signerId, uint256 weight);
    error ZeroThresholdWeight(uint32 entityId, address account);
    error SignerWeightsLengthMismatch(uint32 entityId, address account);
    error ThresholdWeightExceedsTotalWeight(uint256 thresholdWeight, uint256 totalWeight);
    error TooManySigners(uint256 numSigners);
    error TooFewSigners(uint256 numSigners);
    error InvalidSignerMetadata(uint32 entityId, address account, SignerMetadata signerMetadata);
    error SignerIdAlreadyExists(uint32 entityId, address account, bytes30 signerId);
    error SignerIdDoesNotExist(uint32 entityId, address account, bytes30 signerId);
    error SignerMetadataDoesNotExist(uint32 entityId, address account, bytes30 signerId);
    error SignerMetadataAlreadyExists(uint32 entityId, address account, SignerMetadata signerMetaData);
    error AlreadyInitialized(uint32 entityId, address account);
    error Uninitialized(uint32 entityId, address account);
    error EmptyThresholdWeightAndSigners(uint32 entityId, address account);
    error InvalidSigLength(uint32 entityId, address account, uint256 length);
    error InvalidAddress(uint32 entityId, address account, address addr);
    error InvalidSigOffset(uint32 entityId, address account, uint256 offset);
    error InvalidNumSigsOnActualDigest(uint32 entityId, address account, uint256 numSigs);
    error InvalidUserOpDigest(uint32 entityId, address account);
    error UnsupportedSigType(uint32 entityId, address account, uint8 sigType);
    error InvalidAuthorizationLength(uint32 entityId, address account, uint256 length);
    error InvalidRuntimeDigest(uint32 entityId, address account);

    /// @notice Get the signer id.
    /// @param signer The signer to check.
    /// @return signer id in bytes30.
    function getSignerId(address signer) external pure returns (bytes30);

    /// @notice Get the signer id.
    /// @param signer The signer to check.
    /// @return signer id in bytes30.
    function getSignerId(PublicKey calldata signer) external pure returns (bytes30);

    /// @notice Add signers, their signers metadata for the account (msg.sender) given entity id, and
    /// optionally update
    /// threshold weight. Account metadata will be updated with the new signers and threshold weight.
    /// @dev Constraints:
    /// - msg.sender must be initialized for this module.
    /// - signersToAdd must be non-empty.
    /// - total signers after adding new signers must not exceed MAX_SIGNERS.
    /// - each weight must be between [MIN_WEIGHT, MAX_WEIGHT], inclusive.
    /// - each signer in signersToAdd must not be address(0), PublicKey(0,0) or an existing signer.
    /// - each signer in signersToAdd must be either a valid address or a valid PublicKey.
    /// - each signer in signersToAdd does not need to have signerId as it will be calculated and returned.
    /// - If newThresholdWeight is not equal to 0 or the current threshold, and signers are added successfully,
    /// the threshold weight will be updated. The threshold weight must be <= the new total weight after adding signers.
    /// @param entityId entity id for the account and signers.
    /// @param signersToAdd a list of signer information to be added. Please note that the signerId field is empty.
    /// @param newThresholdWeight new threshold weight to set as required to perform an action, or 0 to leave
    /// unmodified.
    /// @return added signers with their ids.
    function addSigners(uint32 entityId, SignerMetadata[] calldata signersToAdd, uint256 newThresholdWeight)
        external
        returns (SignerMetadataWithId[] memory);

    /// @notice Remove certain (but not all) signers and their metadata for the account (msg.sender) given their
    /// entityId and signer ids
    /// and optionally update threshold weight. Account metadata will be updated with the new signers and threshold
    /// weight.
    /// @dev Constraints:
    /// - msg.sender must be initialized for this module.
    /// - signersToRemove must be non-empty.
    /// - Removal of signers must not set total number of signers to 0.
    /// - If newThresholdWeight is not equal to 0 or the current threshold, and signers are removed successfully,
    /// the threshold weight will be updated. The threshold weight must be <= the new total weight after removing
    /// signers.
    /// @param entityId entity id for the account and signers.
    /// @param signersToRemove a list of signer ids to be removed.
    /// @param newThresholdWeight new threshold weight to set as required to perform an action, or 0 to leave
    /// unmodified.
    function removeSigners(uint32 entityId, bytes30[] calldata signersToRemove, uint256 newThresholdWeight) external;

    /// @notice Update the signers' weights for the account along with the threshold weight,
    /// or update only the threshold weight.
    /// @dev Constraints:
    /// - All signers updated must currently have non-zero weight.
    /// - each signer in non-empty signersToUpdate must have a signerId.
    /// - each signer in non-empty signersToUpdate must have a valid new weight.
    /// - each signer in signersToUpdate does not need to have addr or publicKey as signerId will be used.
    /// - All new weights must be in range [MIN_WEIGHT, MAX_WEIGHT].
    /// - If a newThresholdWeight is nonzero, the threshold weight will be updated. Updating threshold weight does not
    /// require modifying signer weight. The newThresholdWeight must be <= the new total weight.
    /// @param entityId entity id for the account and signers.
    /// @param signersToUpdate a list of signer weights to be updated given its id.
    /// @param newThresholdWeight new threshold weight to set as required to perform an action, or 0 to leave
    /// unmodified.
    function updateWeights(uint32 entityId, SignerMetadataWithId[] calldata signersToUpdate, uint256 newThresholdWeight)
        external;

    /// @notice Check if the nSignaturesInput is valid for the account.
    /// @param nSignaturesInput has the following fields:
    /// minimalDigest - digest with minimal required fields set, e.g. userOp
    /// (address sender, uint256 nonce, bytes initCode, bytes callData),
    /// and remaining fields set to default values.
    /// actualDigest - digest with all fields filled in.
    /// At least one signature must cover the actualDigest, with a v value >= 32,
    /// if it differs from the minimal digest.
    /// entityId - entity id for the account and signer.
    /// account - the account to check the signatures for.
    /// signatures - the signatures to check.
    /// @return response - success true if the signatures are valid.
    /// firstFailure if failed is true.
    /// returnError for debugging if available.
    /// (Note: if all signatures are individually valid but do not satisfy the
    /// multisig, firstFailure will be set to the last signature's index.)
    function checkNSignatures(CheckNSignaturesRequest calldata nSignaturesInput)
        external
        view
        returns (CheckNSignaturesResponse memory response);

    /// @notice Return all the signer metadata of an account.
    /// @param entityId entity id for the account and signers.
    /// @param account the account to return signerMetaData of.
    /// @return signersMetadataWithId a list of signer metadata with ids.
    function signersMetadataOf(uint32 entityId, address account)
        external
        view
        returns (SignerMetadataWithId[] memory signersMetadataWithId);

    /// @notice Get the metadata of an account, their respective number of signers, threshold weight, and total weight.
    /// @param entityId entity id for the account and signers.
    /// @param account the account to return the metadata of.
    /// @return accountMetadata account metadata.
    function accountMetadataOf(uint32 entityId, address account)
        external
        view
        returns (AccountMetadata memory accountMetadata);
}
