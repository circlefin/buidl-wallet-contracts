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

import {CredentialType, OwnerData, PublicKey} from "../../../../../common/CommonStructs.sol";

import {AddressBytesLib} from "../../../../../libs/AddressBytesLib.sol";
import {PublicKeyLib} from "../../../../../libs/PublicKeyLib.sol";
import {SetValueLib} from "../../../../../libs/SetValueLib.sol";
import {NotImplemented} from "../../../shared/common/Errors.sol";
import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";

import {BaseModule} from "../BaseModule.sol";
import {BaseMultisigModule} from "./BaseMultisigModule.sol";
import {IWeightedMultisigModule} from "./IWeightedMultisigModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";

import {
    AssociatedLinkedListSet,
    AssociatedLinkedListSetLib
} from "@modular-account-libs/libraries/AssociatedLinkedListSetLib.sol";
import {SetValue} from "@modular-account-libs/libraries/Constants.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";

/// @title Base Weighted Multisig Module
/// @author Circle
/// @notice This module adds a weighted threshold ownership scheme to a ERC6900 smart contract account.
abstract contract BaseWeightedMultisigModule is IWeightedMultisigModule, BaseMultisigModule {
    using AssociatedLinkedListSetLib for AssociatedLinkedListSet;
    using PublicKeyLib for PublicKey;
    using SetValueLib for SetValue[];
    using AddressBytesLib for address;
    using AddressBytesLib for address[];

    // TODO: move to entity id
    // Mapping of owner identifier => associated account => weight
    // ownerDataPerAccount[hash][account] is in account associated storage
    mapping(bytes30 => mapping(address => OwnerData)) public ownerDataPerAccount;

    /// Mapping of associated account => OwnershipMetadata
    mapping(address => OwnershipMetadata) internal _ownerMetadata;

    uint256 internal constant _MAX_OWNERS = 1000;
    uint256 internal constant _MAX_WEIGHT = 1000000;
    uint256 internal constant _INDIVIDUAL_SIGNATURE_BYTES_LEN = 65;
    bytes32 internal constant _TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");

    /// @notice Metadata of the ownership of an account.
    /// @param numOwners number of owners on the account
    /// @param thresholdWeight weight of signatures required to perform an action
    /// @param totalWeight total weight of signatures required to perform an action
    struct OwnershipMetadata {
        uint256 numOwners;
        uint256 thresholdWeight;
        uint256 totalWeight;
    }

    constructor(address entryPoint) BaseMultisigModule(entryPoint) {}

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    function addOwners(
        address[] calldata ownersToAdd,
        uint256[] calldata weightsToAdd,
        PublicKey[] calldata publicKeyOwnersToAdd,
        uint256[] calldata pubicKeyWeightsToAdd,
        uint256 newThresholdWeight
    ) external virtual {
        (ownersToAdd, weightsToAdd, publicKeyOwnersToAdd, pubicKeyWeightsToAdd, newThresholdWeight);
        revert NotImplemented(msg.sig, 0);
    }

    function removeOwners(
        address[] calldata ownersToRemove,
        PublicKey[] calldata publicKeyOwnersToRemove,
        uint256 newThresholdWeight
    ) external virtual {
        (ownersToRemove, publicKeyOwnersToRemove, newThresholdWeight);
        revert NotImplemented(msg.sig, 0);
    }

    function updateMultisigWeights(
        address[] calldata ownersToUpdate,
        uint256[] calldata newWeightsToUpdate,
        PublicKey[] calldata publicKeyOwnersToUpdate,
        uint256[] calldata pubicKeyNewWeightsToUpdate,
        uint256 newThresholdWeight
    ) external virtual {
        (ownersToUpdate, newWeightsToUpdate, publicKeyOwnersToUpdate, pubicKeyNewWeightsToUpdate, newThresholdWeight);
        revert NotImplemented(msg.sig, 0);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃  Execution view functions   ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IValidationModule
    function validateSignature(address account, uint32 entityId, address sender, bytes32 hash, bytes memory signature)
        external
        view
        virtual
        returns (bytes4);

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Module interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IModule
    function onUninstall(bytes calldata) external override {
        bytes30[] memory _ownersToRemove = _owners.getAll(msg.sender).toBytes30Array();
        uint256 _oldThresholdWeight = _ownerMetadata[msg.sender].thresholdWeight;

        _owners.clear(msg.sender);
        _ownerMetadata[msg.sender] = OwnershipMetadata(0, 0, 0);
        uint256 _totalWeightRemoved = _deleteWeights(_ownersToRemove);

        emit OwnersRemoved(msg.sender, _ownersToRemove, _totalWeightRemoved);
        emit ThresholdUpdated(msg.sender, _oldThresholdWeight, 0);
    }

    // ┏━━━━━━━━━━━━━━━┓
    // ┃    EIP-165    ┃
    // ┗━━━━━━━━━━━━━━━┛

    /// @inheritdoc BaseModule
    function supportsInterface(bytes4 interfaceId) public view override(BaseModule, IERC165) returns (bool) {
        return interfaceId == type(IWeightedMultisigModule).interfaceId || super.supportsInterface(interfaceId);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃   Module only view functions     ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IWeightedMultisigModule
    function getOwnerId(address ownerToCheck) external pure returns (bytes30) {
        return ownerToCheck.toBytes30();
    }

    /// @inheritdoc IWeightedMultisigModule
    function getOwnerId(PublicKey memory pubKeyOwnerToCheck) external pure returns (bytes30) {
        return pubKeyOwnerToCheck.toBytes30();
    }

    /// @inheritdoc IWeightedMultisigModule
    function isOwnerOf(address account, address ownerToCheck) external view returns (bool, OwnerData memory) {
        return _isOwnerOf(account, ownerToCheck.toBytes30());
    }

    /// @inheritdoc IWeightedMultisigModule
    function isOwnerOf(address account, PublicKey memory pubKeyOwnerToCheck)
        external
        view
        returns (bool, OwnerData memory)
    {
        return _isOwnerOf(account, pubKeyOwnerToCheck.toBytes30());
    }

    /// @inheritdoc IWeightedMultisigModule
    function ownershipInfoOf(address account)
        external
        view
        returns (bytes30[] memory ownerAddresses, OwnerData[] memory ownersData, uint256 thresholdWeight)
    {
        ownerAddresses = _owners.getAll(account).toBytes30Array();
        ownersData = _getOwnersData(ownerAddresses, account);

        return (ownerAddresses, ownersData, _ownerMetadata[account].thresholdWeight);
    }

    /// @inheritdoc IWeightedMultisigModule
    function checkNSignatures(bytes32 actualDigest, bytes32 minimalDigest, address account, bytes memory signatures)
        public
        view
        virtual
        override(BaseMultisigModule, IWeightedMultisigModule)
        returns (bool success, uint256 firstFailure);

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Internal Functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    function _addOwnersAndUpdateMultisigMetadata(
        bytes30[] memory ownersToAdd,
        OwnerData[] memory ownersDataToAdd,
        uint256 newThresholdWeight
    ) internal {
        // Add owners and weights
        OwnershipMetadata storage metadata = _ownerMetadata[msg.sender];
        (uint256 _numOwnersAdded, uint256 _totalWeightAdded) =
            _addOwners(ownersToAdd, ownersDataToAdd, metadata.numOwners);

        // Update metadata
        // Note: following two additions cannot overflow because we ensure max individual weight is 1,000,000 and max
        // number of owners is 1000.
        // But, we use default checked arithmetic for added safety.
        uint256 _newTotalWeight = metadata.totalWeight + _totalWeightAdded;
        metadata.numOwners = metadata.numOwners + _numOwnersAdded;
        metadata.totalWeight = _newTotalWeight;

        _validateAndOptionallySetThresholdWeight(newThresholdWeight, _newTotalWeight, metadata);

        // Emit events
        emit OwnersAdded(msg.sender, ownersToAdd, ownersDataToAdd);
    }

    function _removeOwners(bytes30[] memory ownersToRemove, uint256 newThresholdWeight) internal {
        uint256 toRemoveLen = ownersToRemove.length;

        if (toRemoveLen == 0) {
            revert ZeroOwnersInputNotAllowed();
        }

        // Setting number of owners to < 1 is disallowed while module installed
        OwnershipMetadata storage metadata = _ownerMetadata[msg.sender];
        uint256 _initialNumOwners = metadata.numOwners;
        if (_initialNumOwners <= toRemoveLen) {
            revert EmptyOwnersNotAllowed();
        }

        // Remove owners (and their corresponding weights)
        uint256 _totalWeightRemoved = _removeOwners(ownersToRemove);

        // Update metadata
        uint256 _initialTotalWeight = metadata.totalWeight;

        // Note: following two deletions cannot underflow because _initialTotalWeight must be >0,
        // as we have nonzero active owners (_initialNumOwners <= toRemoveLen),
        // and active owners have >= 0 weight. But, we use default checked arithmetic for added safety.
        metadata.numOwners = _initialNumOwners - toRemoveLen;
        uint256 _newTotalWeight = _initialTotalWeight - _totalWeightRemoved;
        metadata.totalWeight = _newTotalWeight;

        _validateAndOptionallySetThresholdWeight(newThresholdWeight, _newTotalWeight, metadata);

        // 4. Emit events
        emit OwnersRemoved(msg.sender, ownersToRemove, _totalWeightRemoved);
    }

    function _updateMultisigWeights(
        bytes30[] memory ownersToUpdate,
        OwnerData[] memory newOwnersData,
        uint256 newThresholdWeight
    ) internal pure {
        (ownersToUpdate, newOwnersData, newThresholdWeight);
        revert NotImplemented(msg.sig, 0);
    }

    /// @notice Adds owners, or reverts if any owner cannot be added.
    /// @dev constraints:
    /// - ownerToAdd must have nonzero length
    /// - ownersToAdd and ownerWeights length must be the same
    /// - current number of owners + length of ownersToAdd must not exceed max number of owners
    /// - each owner in ownersToAdd must not be address(0) or an existing owner
    /// - each owner in ownersToAdd must have a weight greater than 0 and less than 1,000.
    /// @param ownersToAdd owners to add for msg.sender account
    /// @param ownersData data of each corresponding owner
    /// @param currentNumOwners current number of owners
    function _addOwners(bytes30[] memory ownersToAdd, OwnerData[] memory ownersData, uint256 currentNumOwners)
        internal
        returns (uint256 numOwnersAdded, uint256 totalWeightAdded)
    {
        uint256 _numOwnersToAdd = ownersToAdd.length;
        uint256 _accumulateWeightToAdd = 0;

        if (_numOwnersToAdd == 0) {
            revert ZeroOwnersInputNotAllowed();
        }

        if (ownersData.length != _numOwnersToAdd) {
            revert OwnersWeightsMismatch();
        }

        if (currentNumOwners + _numOwnersToAdd > _MAX_OWNERS) {
            revert TooManyOwners(currentNumOwners, _numOwnersToAdd);
        }

        for (uint256 i = 0; i < _numOwnersToAdd; ++i) {
            if (!_owners.tryAdd(msg.sender, SetValue.wrap(ownersToAdd[i]))) {
                revert InvalidOwner(ownersToAdd[i]);
            }
            if (ownersData[i].weight == 0 || ownersData[i].weight > _MAX_WEIGHT) {
                revert InvalidWeight(ownersToAdd[i], msg.sender, ownersData[i].weight);
            }
            // store the ownerData
            ownerDataPerAccount[ownersToAdd[i]][msg.sender] = ownersData[i];
            _accumulateWeightToAdd += ownersData[i].weight;
        }

        return (_numOwnersToAdd, _accumulateWeightToAdd);
    }

    /// @dev Sets an owner weight, or reverts if the weight is invalid (0, or > 1000000.)
    /// @param owner signer for msg.sender account
    /// @param weight weight to set
    function _setOwnerWeight(bytes30 owner, uint256 weight) internal {
        if (weight == 0 || weight > _MAX_WEIGHT) {
            revert InvalidWeight(owner, msg.sender, weight);
        }
        ownerDataPerAccount[owner][msg.sender].weight = weight;
    }

    /// @dev remove owners and their corresponding weights.
    /// @param ownersToRemove owners to remove (must be current owner for account.)
    /// @return totalWeightRemoved total weight removed
    function _removeOwners(bytes30[] memory ownersToRemove) internal returns (uint256 totalWeightRemoved) {
        for (uint256 i = 0; i < ownersToRemove.length; ++i) {
            if (!_owners.tryRemove(msg.sender, SetValue.wrap(ownersToRemove[i]))) {
                revert OwnerDoesNotExist(ownersToRemove[i]);
            }
            totalWeightRemoved += ownerDataPerAccount[ownersToRemove[i]][msg.sender].weight;
            delete ownerDataPerAccount[ownersToRemove[i]][msg.sender];
        }
    }

    function _deleteWeights(bytes30[] memory _ownersToRemove) internal returns (uint256 _sumRemoved) {
        for (uint256 i = 0; i < _ownersToRemove.length; i++) {
            _sumRemoved += ownerDataPerAccount[_ownersToRemove[i]][msg.sender].weight;
            delete ownerDataPerAccount[_ownersToRemove[i]][msg.sender];
        }
        return _sumRemoved;
    }

    /// @notice Validates new threshold weight against new total weight.
    /// @dev This function assumes new total weight is > 0 as there is no way to set total weight to 0 while module is
    /// installed.
    /// @param newThresholdWeight new threshold weight. If zero, will attempt to leave unmodified. The new threshold
    /// weight,
    /// (or old threshold weight if _newThresholdWeight == 0), must be <= _newTotalWeight.
    /// @param newTotalWeight new total weight.
    /// @param metadata metadata to update
    function _validateAndOptionallySetThresholdWeight(
        uint256 newThresholdWeight,
        uint256 newTotalWeight,
        OwnershipMetadata storage metadata
    ) internal {
        uint256 _oldThresholdWeight = metadata.thresholdWeight;

        if (newThresholdWeight > 0) {
            if (newTotalWeight < newThresholdWeight) {
                revert ThresholdWeightExceedsTotalWeight(newThresholdWeight, newTotalWeight);
            }

            if (newThresholdWeight != _oldThresholdWeight) {
                metadata.thresholdWeight = newThresholdWeight;
                emit ThresholdUpdated(msg.sender, _oldThresholdWeight, newThresholdWeight);
            }
        } else {
            if (newTotalWeight < _oldThresholdWeight) {
                revert ThresholdWeightExceedsTotalWeight(_oldThresholdWeight, newTotalWeight);
            }
        }
    }

    function _onInstall(bytes30[] memory initialOwners, OwnerData[] memory ownersData, uint256 thresholdWeight)
        internal
    {
        if (thresholdWeight == 0) {
            revert InvalidThresholdWeight();
        }

        uint256 _totalWeight = _sum(ownersData);
        uint256 _oldThresholdWeight = 0;

        if (_totalWeight < thresholdWeight) {
            revert ThresholdWeightExceedsTotalWeight(_oldThresholdWeight, thresholdWeight);
        }

        uint256 _currentNumOwners = 0;
        _addOwners(initialOwners, ownersData, _currentNumOwners);

        _ownerMetadata[msg.sender] = OwnershipMetadata(initialOwners.length, thresholdWeight, _totalWeight);

        emit OwnersAdded(msg.sender, initialOwners, ownersData);
        emit ThresholdUpdated(msg.sender, _oldThresholdWeight, thresholdWeight);
    }

    function _isOwnerOf(address account, bytes30 ownerHash) internal view returns (bool, OwnerData memory ownerData) {
        if (_owners.contains(account, SetValue.wrap(ownerHash))) {
            return (true, ownerDataPerAccount[ownerHash][account]);
        } else {
            return (false, ownerData);
        }
    }

    function _mergeOwners(address[] memory owners, PublicKey[] memory publicKeyOwners)
        internal
        pure
        returns (bytes30[] memory totalOwners)
    {
        uint256 aLen = owners.length;
        uint256 bLen = publicKeyOwners.length;
        totalOwners = new bytes30[](aLen + bLen);
        uint256 index = 0;
        for (uint256 i = 0; i < aLen; ++i) {
            totalOwners[index] = owners[i].toBytes30();
            index++;
        }
        for (uint256 i = 0; i < bLen; ++i) {
            totalOwners[index] = publicKeyOwners[i].toBytes30();
            index++;
        }
    }

    function _mergeOwnersData(
        address[] memory owners,
        uint256[] memory weights,
        PublicKey[] memory publicKeyOwners,
        uint256[] memory pubicKeyWeights
    ) internal pure returns (bytes30[] memory totalOwners, OwnerData[] memory ownersData) {
        uint256 aLen = owners.length;
        uint256 bLen = publicKeyOwners.length;
        if (aLen != weights.length || bLen != pubicKeyWeights.length) {
            revert OwnersWeightsMismatch();
        }
        uint256 totalLen = aLen + bLen;
        totalOwners = new bytes30[](totalLen);
        ownersData = new OwnerData[](totalLen);
        uint256 index = 0;
        for (uint256 i = 0; i < aLen; ++i) {
            totalOwners[index] = owners[i].toBytes30();
            ownersData[index].weight = weights[i];
            ownersData[index].credType = CredentialType.ADDRESS;
            ownersData[index].addr = owners[i];
            index++;
        }
        for (uint256 i = 0; i < bLen; ++i) {
            totalOwners[index] = publicKeyOwners[i].toBytes30();
            ownersData[index].weight = pubicKeyWeights[i];
            ownersData[index].credType = CredentialType.PUBLIC_KEY;
            ownersData[index].publicKeyX = publicKeyOwners[i].x;
            ownersData[index].publicKeyY = publicKeyOwners[i].y;
            index++;
        }
    }

    /// @dev get owners' data
    /// @param ownerIds owner ids
    /// @param account modular smart contract account
    /// @return _ownersData data of each corresponding owner
    function _getOwnersData(bytes30[] memory ownerIds, address account)
        internal
        view
        returns (OwnerData[] memory _ownersData)
    {
        _ownersData = new OwnerData[](ownerIds.length);

        for (uint256 i = 0; i < ownerIds.length; ++i) {
            _ownersData[i] = ownerDataPerAccount[ownerIds[i]][account];
        }

        return _ownersData;
    }

    /// @dev sums values
    /// @param arr array of uint256 to sum
    /// @return result of summing arr values
    function _sum(OwnerData[] memory arr) internal pure returns (uint256 result) {
        for (uint256 i = 0; i < arr.length; ++i) {
            result += arr[i].weight;
        }
        return result;
    }
}
