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
import {AccountMetadata, CheckNSignaturesInput, SignerData} from "./MultisigStructs.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";

/// @title Weighted Multisig Module Interface
/// @author Circle
/// @notice This module adds a weighted threshold validation module to a ERC6900 smart contract account.
interface IWeightedMultisigValidationModule is IValidationModule {
    /// @notice This event is emitted when the threshold weight is updated
    /// @param account account module is installed on
    /// @param oldThresholdWeight the old threshold weight required to perform an action
    /// @param newThresholdWeight the new threshold weight required to perform an action
    event ThresholdUpdated(address account, uint256 oldThresholdWeight, uint256 newThresholdWeight);

    error InvalidThresholdWeight();
    error SignersWeightsMismatch();
    error ThresholdWeightExceedsTotalWeight(uint256 thresholdWeight, uint256 totalWeight);

    /// @notice Add address signers (e.g. EOA) and their associated weights for the account, and optionally update
    /// threshold weight.
    /// @dev Constraints:
    /// - msg.sender must be initialized for this module
    /// - signers must be non-empty
    /// - total signers after adding new signers must not exceed MAX_SIGNERS.
    /// - length of weights must be equal to length of signers.
    /// - each weight must be between [1, MAX_WEIGHT], inclusive.
    /// - each signer in signers must not be address(0) or an existing signer.
    /// - If newThresholdWeight is not equal to 0 or the current threshold, and signers are added successfully,
    /// the threshold weight will be updated. The threshold weight must be <= the new total weight after adding signers.
    /// @param entityIds entity ids for the account and signer
    /// @param signers array of address signers to be added
    /// @param weights corresponding array of weights for signers to be added (must be the same length as signers).
    /// @param newThresholdWeight new threshold weight to set as required to perform an action, or 0 to leave
    /// unmodified.
    function addSigners(
        uint32[] calldata entityIds,
        address[] calldata signers,
        uint256[] calldata weights,
        uint256 newThresholdWeight
    ) external;

    /// @notice Add public key signers (e.g. passkey) and their associated weights for the account, and optionally
    /// update threshold weight.
    /// @dev Constraints:
    /// - msg.sender must be initialized for this module
    /// - signers must be non-empty
    /// - total signers after adding new signers must not exceed MAX_SIGNERS.
    /// - length of weights must be equal to length of signers.
    /// - each weight must be between [1, MAX_WEIGHT], inclusive.
    /// - each signer in signers must not be (0, 0) or an existing signer.
    /// - If newThresholdWeight is not equal to 0 or the current threshold, and signers are added successfully,
    /// the threshold weight will be updated. The threshold weight must be <= the new total weight after adding signers.
    /// @param entityIds entity ids for the account and signer
    /// @param signers array of public key signers to be added
    /// @param weights corresponding array of weights for signers to be added (must be the same length as signers)
    /// @param newThresholdWeight new threshold weight to set as required to perform an action, or 0 to leave
    /// unmodified.
    function addSigners(
        uint32[] calldata entityIds,
        PublicKey[] calldata signers,
        uint256[] calldata weights,
        uint256 newThresholdWeight
    ) external;

    /// @notice Remove given address signers and set their associated weights to 0 for the account,
    /// and optionally update threshold weight.
    /// @dev Constraints:
    /// - msg.sender must be initialized for this module
    /// - signers must be non-empty
    /// - Removal of signers must not set total number of signers to 0.
    /// - If newThresholdWeight is not equal to 0 or the current threshold, and signers are removed successfully,
    /// the threshold weight will be updated. The threshold weight must be <= the new total weight after removing
    /// signers.
    /// @param entityIds entity ids for the account and signer
    /// @param signers array of address signers to be removed
    /// @param newThresholdWeight new threshold weight to set as required to perform an action, or 0 to leave
    /// unmodified.
    function removeSigners(uint32[] calldata entityIds, address[] calldata signers, uint256 newThresholdWeight)
        external;

    /// @notice Remove given public key signers and set their associated weights to 0 for the account,
    /// and optionally update threshold weight.
    /// @dev Constraints:
    /// - msg.sender must be initialized for this module
    /// - signers must be non-empty
    /// - Removal of signers must not set total number of signers to 0.
    /// - If newThresholdWeight is not equal to 0 or the current threshold, and signers are removed successfully,
    /// the threshold weight will be updated. The threshold weight must be <= the new total weight after removing
    /// signers.
    /// @param entityIds entity ids for the account and signer
    /// @param signers array of public key signers to be removed
    /// @param newThresholdWeight new threshold weight to set as required to perform an action, or 0 to leave
    /// unmodified.
    function removeSigners(uint32[] calldata entityIds, PublicKey[] calldata signers, uint256 newThresholdWeight)
        external;

    /// @notice Update address signers' weights for the account, and/or update threshold weight.
    /// @dev Constraints:
    /// - all signers updated must currently have non-zero weight
    /// - all new weights must be in range [1, MAX_WEIGHT]
    /// - If a newThresholdWeight is nonzero, the threshold weight will be updated. Updating threshold weight does not
    /// require modifying signers.
    /// The newThresholdWeight must be <= the new total weight.
    /// @param entityIds entity ids for the account and signer
    /// @param signers array of address signers to be updated
    /// @param weights corresponding array of weights for signers
    /// @param newThresholdWeight new threshold weight to set as required to perform an action, or 0 to leave
    /// unmodified.
    function updateWeights(
        uint32[] calldata entityIds,
        address[] calldata signers,
        uint256[] calldata weights,
        uint256 newThresholdWeight
    ) external;

    /// @notice Update public key signers' weights for the account, and/or update threshold weight.
    /// @dev Constraints:
    /// - all signers updated must currently have non-zero weight
    /// - all new weights must be in range [1, MAX_WEIGHT]
    /// - If a newThresholdWeight is nonzero, the threshold weight will be updated. Updating threshold weight does not
    /// require modifying signers.
    /// The newThresholdWeight must be <= the new total weight.
    /// @param entityIds entity ids for the account and signer
    /// @param signers array of public key signers to be updated
    /// @param weights corresponding array of weights for signers
    /// @param newThresholdWeight new threshold weight to set as required to perform an action, or 0 to leave
    /// unmodified.
    function updateWeights(
        uint32[] calldata entityIds,
        PublicKey[] calldata signers,
        uint256[] calldata weights,
        uint256 newThresholdWeight
    ) external;

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
    /// @return success true if the signatures are valid.
    /// @return firstFailure first failure, if failed is true.
    /// (Note: if all signatures are individually valid but do not satisfy the
    /// multisig, firstFailure will be set to the last signature's index.)
    function checkNSignatures(CheckNSignaturesInput calldata nSignaturesInput)
        external
        view
        returns (bool success, uint256 firstFailure);

    /// @notice Return signer data of an account.
    /// @param entityId entity id for the account and signer.
    /// @param account the account to get signerData of.
    /// @return signerData signersData[entityId][account].
    function signerDataOf(uint32 entityId, address account) external view returns (SignerData memory signerData);

    /// @notice Get the metadata of an account, their respective number of signers, threshold weight, and total weight.
    /// @param account the account to get the metadata of.
    /// @return accountMetadata account metadata.
    function accountMetadataOf(address account) external view returns (AccountMetadata memory accountMetadata);
}
