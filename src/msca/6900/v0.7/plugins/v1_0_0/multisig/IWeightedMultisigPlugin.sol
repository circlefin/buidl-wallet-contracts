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

import {OwnerData, OwnershipMetadata, PublicKey} from "../../../../../../common/CommonStructs.sol";

/// @title Weighted Multisig Plugin Interface
/// @author Circle
/// @notice This plugin adds a weighted threshold ownership scheme to a ERC6900 smart contract account.
/// @notice The design takes inspiration from Alchemy's [Equally Weighted Multisig
/// Plugin](https://github.com/alchemyplatform/multisig-plugin).
interface IWeightedMultisigPlugin {
    /// @notice This event is emitted when owners of the account are added.
    /// @param account account plugin is installed on
    /// @param owners list of owners added
    /// @param weights list of weights corresponding to added owners
    event OwnersAdded(address account, bytes30[] owners, OwnerData[] weights);

    /// @notice This event is emitted when owners of the account are removed.
    /// @param account account plugin is installed on
    /// @param owners list of owners removed
    /// @param totalWeightRemoved total weight removed
    event OwnersRemoved(address account, bytes30[] owners, uint256 totalWeightRemoved);

    /// @notice This event is emitted when weights of account owners updated.
    /// @param account account plugin is installed on
    /// @param owners list of owners updated
    /// @param weights list of updated weights corresponding to owners
    event OwnersUpdated(address account, bytes30[] owners, OwnerData[] weights);

    /// @notice This event is emitted when the threshold weight is updated
    /// @param account account plugin is installed on
    /// @param oldThresholdWeight the old threshold weight required to perform an action
    /// @param newThresholdWeight the new threshold weight required to perform an action
    event ThresholdUpdated(address account, uint256 oldThresholdWeight, uint256 newThresholdWeight);

    error InvalidThresholdWeight();
    error InvalidWeight(bytes30 owner, address account, uint256 weight);
    error OwnersWeightsMismatch();
    error ThresholdWeightExceedsTotalWeight(uint256 thresholdWeight, uint256 totalWeight);

    struct CheckNSignatureInput {
        bytes32 actualDigest;
        bytes32 minimalDigest;
        address account;
        bytes signatures;
    }

    /// @notice Add owners and their associated weights for the account, and optionally update threshold weight required
    /// to perform an action.
    /// @dev Constraints:
    /// - msg.sender must be initialized for this plugin
    /// - ownersToAdd must be non-empty
    /// - total owners after adding ownersToAdd must not exceed 1000.
    /// - length of weightsToAdd must be equal to length of ownersToAdd.
    /// - each weight must be between [1, 1000000], inclusive.
    /// - each owner in ownersToAdd must not be address(0) or an existing owner.
    /// - If newThresholdWeight is not equal to 0 or the current threshold, and owners are added successfully,
    /// the threshold weight will be updated. The threshold weight must be <= the new total weight after adding owners.
    /// This function is installed on the account as part of plugin installation, and should only be called from an
    /// account.
    /// @param ownersToAdd array of addresses for owners to be added, omit for secp256r1 but required for secp256k1
    /// @param weightsToAdd corresponding array of weights for owners to be added (must be same length as owners.), omit
    /// for secp256r1 but required for secp256k1,
    /// @param publicKeyOwnersToAdd owners derived from public keys, omit for secp256k1 but required for secp256r1
    /// @param pubicKeyWeightsToAdd corresponding weights for publicKeyOwnersToAdd, omit for secp256k1 but required for
    /// secp256r1
    /// @param newThresholdWeight new threshold weight to set as required to perform an action, or 0 to leave
    /// unmodified.
    function addOwners(
        address[] calldata ownersToAdd,
        uint256[] calldata weightsToAdd,
        PublicKey[] calldata publicKeyOwnersToAdd,
        uint256[] calldata pubicKeyWeightsToAdd,
        uint256 newThresholdWeight
    ) external;

    /// @notice Remove given owners and their set their associated weights to 0 for the account,
    /// and optionally update threshold weight required to perform an action.
    /// @dev Constraints:
    /// - msg.sender must be initialized for this plugin
    /// - ownersToRemove must be non-empty
    /// - Removal of owners must not set total number of owners to 0.
    /// - If newThresholdWeight is not equal to 0 or the current threshold, and owners are removed successfully,
    /// the threshold weight will be updated. The threshold weight must be <= the new total weight after removing
    /// owners.
    /// This function is installed on the account as part of plugin installation, and should
    /// only be called from an account.
    /// @param ownersToRemove array of addresses for owners to be removed, omit for secp256r1 but required for secp256k1
    /// @param publicKeyOwnersToRemove owners derived from public keys, omit for secp256k1 but required for secp256r1
    /// @param newThresholdWeight new threshold weight to set as required to perform an action, or 0 to leave,
    /// unmodified.
    function removeOwners(
        address[] calldata ownersToRemove,
        PublicKey[] calldata publicKeyOwnersToRemove,
        uint256 newThresholdWeight
    ) external;

    /// @notice Update owners' weights for the account, and/or update threshold weight required to perform an action.
    /// @dev Constraints:
    /// - all owners updated must currently have non-zero weight
    /// - all new weights must be in range [1, 1000000]
    /// - If a newThresholdWeight is nonzero, the threshold weight will be updated. Updating threshold weight does not
    /// require modifying owners.
    /// The newThresholdWeight must be <= the new total weight.
    /// This function is installed on the account as part of plugin installation, and should
    /// only be called from an account.
    /// @param ownersToUpdate array of addresses for owners to be updated (empty if updating no owners.), omit for
    /// secp256r1 but required for secp256k1
    /// @param newWeightsToUpdate corresponding array of weights for owners to updated (empty if updating no owners.)
    /// @param publicKeyOwnersToUpdate owners derived from public keys, omit for secp256k1 but required for secp256r1
    /// @param pubicKeyNewWeightsToUpdate corresponding weights for publicKeyOwnersToUpdate, omit for secp256k1 but
    /// required for secp256r1
    /// @param newThresholdWeight new threshold weight to set as required to perform an action, or 0 to leave
    /// unmodified.
    function updateMultisigWeights(
        address[] calldata ownersToUpdate,
        uint256[] calldata newWeightsToUpdate,
        PublicKey[] calldata publicKeyOwnersToUpdate,
        uint256[] calldata pubicKeyNewWeightsToUpdate,
        uint256 newThresholdWeight
    ) external;

    /// @notice Get the owner id.
    /// @param ownerToCheck The owner to check.
    /// @return (bytes30).
    function getOwnerId(address ownerToCheck) external pure returns (bytes30);

    /// @notice Get the owner id.
    /// @param pubKeyOwnerToCheck The owner to check.
    /// @return (bytes30).
    function getOwnerId(PublicKey memory pubKeyOwnerToCheck) external pure returns (bytes30);

    /// @notice Check if the signatures are valid for the account.
    /// @param input has minimalDigest Digest of user op with minimal required fields set:
    /// (address sender, uint256 nonce, bytes initCode, bytes callData), and remaining
    /// fields set to default values.
    /// actualDigest Digest of user op with all fields filled in.
    /// At least one signature must cover the actualDigest, with a v value >= 32,
    /// if it differs from the minimal digest.
    /// account The account to check the signatures for.
    /// signatures The signatures to check.
    /// @return success True if the signatures are valid.
    /// @return firstFailure first failure, if failed is true.
    /// (Note: if all signatures are individually valid but do not satisfy the
    /// multisig, firstFailure will be set to the last signature's index.)
    function checkNSignatures(CheckNSignatureInput memory input)
        external
        view
        returns (bool success, uint256 firstFailure);

    /// @notice Check if an address is an owner of `account`.
    /// @param account The account to check.
    /// @param ownerToCheck The owner to check if it is an owner of the provided account.
    /// @return (true, ownerData) if the address is an owner of the account, otherwise return (false, empty ownerData).
    function isOwnerOf(address account, address ownerToCheck) external view returns (bool, OwnerData memory);

    /// @notice Check if a public key is an owner of `account`.
    /// @param account The account to check.
    /// @param pubKeyOwnerToCheck The owner to check if it is an owner of the provided account.
    /// @return (true, ownerData) if the public key is an owner of the account, otherwise return (false, empty
    /// ownerData).
    function isOwnerOf(address account, PublicKey memory pubKeyOwnerToCheck)
        external
        view
        returns (bool, OwnerData memory);

    /// @notice Get the owners of `account`, their respective weights, and the threshold weight.
    /// @param account The account to get the owners of.
    /// @return ownerAddresses owners of the account
    /// @return ownersData data of each respective owner
    /// @return ownershipMetadata ownership metadata
    function ownershipInfoOf(address account)
        external
        view
        returns (
            bytes30[] calldata ownerAddresses,
            OwnerData[] calldata ownersData,
            OwnershipMetadata memory ownershipMetadata
        );
}
