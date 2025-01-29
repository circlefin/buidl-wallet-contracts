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

import {CalldataUtils} from "../../../../../utils/CalldataUtils.sol";
import {
    AccountMetadata,
    CheckNSignaturesContext,
    CheckNSignaturesRequest,
    SignerMetadata,
    SignerMetadataWithId
} from "./MultisigStructs.sol";

import {BaseERC712CompliantModule} from "../../../shared/erc712/BaseERC712CompliantModule.sol";
import {
    AssociatedLinkedListSet,
    AssociatedLinkedListSetLib
} from "@modular-account-libs/libraries/AssociatedLinkedListSetLib.sol";

import {CredentialType, PublicKey, WebAuthnSigDynamicPart} from "../../../../../common/CommonStructs.sol";

import {
    EIP1271_INVALID_SIGNATURE,
    EIP1271_VALID_SIGNATURE,
    EMPTY_HASH,
    SIG_VALIDATION_FAILED,
    SIG_VALIDATION_SUCCEEDED,
    ZERO,
    ZERO_BYTES32
} from "../../../../../common/Constants.sol";
import {BaseModule} from "../BaseModule.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";

import {IWeightedMultisigValidationModule} from "./IWeightedMultisigValidationModule.sol";
import {MAX_SIGNERS, MAX_WEIGHT, MIN_WEIGHT} from "./MultisigConstants.sol";

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {PublicKeyLib} from "../../../../../libs/PublicKeyLib.sol";
import {NotImplementedFunction} from "../../../shared/common/Errors.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

import {SetValueLib} from "../../../../../libs/SetValueLib.sol";

import {WebAuthnLib} from "../../../../../libs/WebAuthnLib.sol";
import {CalldataUtils} from "../../../../../utils/CalldataUtils.sol";
import {UserOperationLib} from "@account-abstraction/contracts/core/UserOperationLib.sol";
import {SetValue} from "@modular-account-libs/libraries/Constants.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/// @title Weighted Multisig Module.
/// @author Circle
/// @notice We support different weighting rules based on entityId. If you have a gas spending use case
/// that only requires one signature, you can assign your desired signers group to entityId(0).
/// However, if you need more than two signatures for any spending over $1000, you can assign
/// the desired signers group to a different entityId (1).
/// signerId is a unique identifier for each signer in the multisig group. If the signer is an address,
/// then signerId == bytes30(keccak256(abi.encode(CredentialType.ADDRESS, addr))). If the signer is a public key, then
/// signerId == bytes30(keccak256(abi.encode(CredentialType.PUBLIC_KEY, publicKey.x, publicKey.y))).
contract WeightedMultisigValidationModule is
    IWeightedMultisigValidationModule,
    BaseERC712CompliantModule,
    BaseModule
{
    using ECDSA for bytes32;
    using PublicKeyLib for PublicKey[];
    using PublicKeyLib for PublicKey;
    using MessageHashUtils for bytes32;
    using SetValueLib for SetValue[];
    using AssociatedLinkedListSetLib for AssociatedLinkedListSet;
    using CalldataUtils for bytes;
    using UserOperationLib for PackedUserOperation;

    // a unique identifier in the format "vendor.module.semver" for the account implementation
    string public constant MODULE_ID = "circle.weighted-multisig-module.1.0.0";
    // keccak256("CircleWeightedMultisigMessage(bytes message)")
    bytes32 private constant _MODULE_TYPEHASH = 0x77086513965446054aa0ac031b0cbbd4f343b25cbe864d787c5102e28d6b40bc;
    // keccak256("circle.weighted-multisig-module.1.0.0")
    bytes32 private constant _HASHED_MODULE_ID = 0x224dce5084de9b5d64cd245a83e348c785d73b74ff216928f9c4276e52d60a1a;
    // keccak256("1.0.0")
    bytes32 private constant _HASHED_MODULE_VERSION = 0x06c015bd22b4c69690933c1058878ebdfef31f9aaae40bbe86d8a09fe1b2972c;

    uint256 internal constant _INDIVIDUAL_SIGNATURE_BYTES_LEN = 65;

    address public immutable ENTRYPOINT;
    // AssociatedLinkedListSet has an internal mapping that goes from
    // associated account => address signer,
    // so signersPerEntityId[entityId] still remains within account associated storage
    // this stores the signers for each entity id associated with the account.
    // entityId(0) => [address(1), address(2) ...]
    mapping(uint32 entityId => AssociatedLinkedListSet signers) public signersPerEntity;
    // signersMetadataPerEntityId stores the signer metadata such as weight, optional address or public key information
    // for each entityId, signerId and account
    mapping(uint32 entityId => mapping(bytes30 signerId => mapping(address account => SignerMetadata))) public
        signersMetadataPerEntity;
    /// accountMetadata stores the metadata for each account and entity id,
    /// this allows for different weighting rules, even for the same account
    mapping(uint32 entityId => mapping(address account => AccountMetadata)) public accountMetadataPerEntity;

    constructor(address entryPoint) {
        ENTRYPOINT = entryPoint;
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    /// @inheritdoc IValidationModule
    function validateUserOp(uint32 entityId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256)
    {
        // userOp.sig format:
        // 0 to n: Constant parts of k signatures, with each constant part being 65 bytes
        // n onward: Dynamic parts of the signatures, if any
        bytes32 actualUserOpDigest = userOpHash.toEthSignedMessageHash();
        (bytes32 minimalUserOpDigest, address sender) = _getMinimalUserOpDigest(userOp);
        // actualUserOpDigest must differ from minimalUserOpDigest in userOp
        // requiredNumSigsOnActualDigest is always one for validateUserOp
        if (actualUserOpDigest == minimalUserOpDigest) {
            revert InvalidUserOpDigest(entityId, sender);
        }
        bool success;
        uint256 firstFailure;
        (success, firstFailure) = checkNSignatures(
            CheckNSignaturesRequest({
                entityId: entityId,
                actualDigest: actualUserOpDigest,
                minimalDigest: minimalUserOpDigest,
                requiredNumSigsOnActualDigest: 1,
                account: sender,
                signatures: userOp.signature
            })
        );
        return success ? SIG_VALIDATION_SUCCEEDED : SIG_VALIDATION_FAILED;
    }

    /// @inheritdoc IValidationModule
    function validateRuntime(
        address account,
        uint32 entityId,
        address sender,
        uint256 value,
        bytes calldata data,
        bytes calldata authorization
    ) external pure override {
        // TODO: implement this - the signatures can be put in the validationData field of the runtime validation
        // function
        (account, sender, value, data, authorization);
        revert NotImplementedFunction(msg.sig, entityId);
    }

    /// @inheritdoc IWeightedMultisigValidationModule
    function addSigners(uint32 entityId, SignerMetadata[] calldata signersToAdd, uint256 newThresholdWeight)
        external
        override
        returns (SignerMetadataWithId[] memory)
    {
        // data input validations
        if (signersToAdd.length == 0) {
            revert TooFewSigners(signersToAdd.length);
        }
        if (signersToAdd.length > MAX_SIGNERS) {
            revert TooManySigners(signersToAdd.length);
        }
        AccountMetadata memory currentAccountMetadata = accountMetadataPerEntity[entityId][msg.sender];
        if (_isUninitializedAccountMetadata(currentAccountMetadata)) {
            revert Uninitialized(entityId, msg.sender);
        }
        (uint256 totalWeightAdded, SignerMetadataWithId[] memory signersAdded) =
            _addSigners(msg.sender, entityId, signersToAdd);
        // update the numSigners, totalWeight and thresholdWeight
        _updateAccountMetadata({
            account: msg.sender,
            entityId: entityId,
            numSigners: currentAccountMetadata.numSigners + signersAdded.length, // existing + new signers
            totalWeight: currentAccountMetadata.totalWeight + totalWeightAdded, // existing + new total weight
            thresholdWeight: newThresholdWeight, // new threshold weight
            isUninstall: false, // not called by uninstall
            currentAccountMetadata: currentAccountMetadata
        });
        return signersAdded;
    }

    /// @inheritdoc IWeightedMultisigValidationModule
    function removeSigners(uint32 entityId, bytes30[] calldata signersToRemove, uint256 newThresholdWeight)
        external
        override
    {
        // data input validations
        if (signersToRemove.length == 0) {
            revert TooFewSigners(signersToRemove.length);
        }
        if (signersToRemove.length > MAX_SIGNERS) {
            revert TooManySigners(signersToRemove.length);
        }
        AccountMetadata memory currentAccountMetadata = accountMetadataPerEntity[entityId][msg.sender];
        if (_isUninitializedAccountMetadata(currentAccountMetadata)) {
            revert Uninitialized(entityId, msg.sender);
        }
        uint256 totalWeightRemoved = _removeSigners(msg.sender, entityId, signersToRemove);
        // update the numSigners, totalWeight and thresholdWeight
        _updateAccountMetadata({
            account: msg.sender,
            entityId: entityId,
            numSigners: currentAccountMetadata.numSigners - signersToRemove.length, // existing - deleted
            // signers
            totalWeight: currentAccountMetadata.totalWeight - totalWeightRemoved, // existing - deleted total weight
            thresholdWeight: newThresholdWeight, // keep the current threshold weight
            isUninstall: false, // not called by uninstall
            currentAccountMetadata: currentAccountMetadata
        });
    }

    /// @inheritdoc IWeightedMultisigValidationModule
    function updateWeights(uint32 entityId, SignerMetadataWithId[] calldata signersToUpdate, uint256 newThresholdWeight)
        external
        override
    {
        AccountMetadata memory currentAccountMetadata = accountMetadataPerEntity[entityId][msg.sender];
        if (_isUninitializedAccountMetadata(currentAccountMetadata)) {
            revert Uninitialized(entityId, msg.sender);
        }
        if (newThresholdWeight == 0 && signersToUpdate.length == 0) {
            revert EmptyThresholdWeightAndSigners(entityId, msg.sender);
        }
        uint256 totalWeightAdded = 0;
        uint256 totalWeightRemoved = 0;
        // update the signer weights
        if (signersToUpdate.length > 0) {
            (totalWeightAdded, totalWeightRemoved) = _updateSignerWeights(msg.sender, entityId, signersToUpdate);
        }
        // update the totalWeight and thresholdWeight
        _updateAccountMetadata({
            account: msg.sender,
            entityId: entityId,
            numSigners: currentAccountMetadata.numSigners,
            totalWeight: currentAccountMetadata.totalWeight + totalWeightAdded - totalWeightRemoved, // existing + delta
                // of updated total weight
            thresholdWeight: newThresholdWeight, // new threshold weight
            isUninstall: false, // not called by uninstall
            currentAccountMetadata: currentAccountMetadata
        });
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃  Execution view functions   ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IValidationModule
    function validateSignature(address account, uint32 entityId, address sender, bytes32 hash, bytes memory signature)
        external
        view
        override
        returns (bytes4)
    {
        (sender);
        bytes32 replaySafeHash = getReplaySafeMessageHash(account, hash);
        bool success;
        uint256 firstFailure;
        (success, firstFailure) = checkNSignatures(
            CheckNSignaturesRequest({
                entityId: entityId,
                actualDigest: replaySafeHash,
                minimalDigest: replaySafeHash,
                requiredNumSigsOnActualDigest: 0,
                account: account,
                signatures: signature
            })
        );
        return success ? EIP1271_VALID_SIGNATURE : EIP1271_INVALID_SIGNATURE;
    }

    /// @inheritdoc IWeightedMultisigValidationModule
    function checkNSignatures(CheckNSignaturesRequest memory request)
        public
        view
        override
        returns (bool success, uint256 firstFailure)
    {
        if (request.signatures.length < _INDIVIDUAL_SIGNATURE_BYTES_LEN) {
            revert InvalidSigLength(request.entityId, request.account, request.signatures.length);
        }
        AccountMetadata memory currentAccountMetadata = accountMetadataPerEntity[request.entityId][request.account];
        if (_isUninitializedAccountMetadata(currentAccountMetadata)) {
            revert Uninitialized(request.entityId, request.account);
        }
        // `thresholdWeight` represents the minimum weight needed to perform an action and must not be zero, as verified
        // in `_updateAccountMetadata`
        uint256 thresholdWeight = currentAccountMetadata.thresholdWeight;
        CheckNSignaturesContext memory context;
        uint256 accumulatedWeight;
        // located in the lastByte of signature constant part
        uint8 sigType;
        uint256 signatureCount;
        // tracks whether `signatures` is a complete and valid multisig signature
        context.success = true;
        uint256 currentWeight;
        while (accumulatedWeight < thresholdWeight) {
            // check signature constant part length
            _checkNextSigConstantPartLength(context, signatureCount, request.signatures.length);
            if (context.success == false) {
                return (false, context.firstFailure);
            }

            (sigType, context.first32Bytes, context.second32Bytes) =
                _splitSigConstantPart(request.signatures, signatureCount);
            bytes32 digest;
            // sigType is normalized for actualDigest
            (digest, sigType) = _getDigestAndNormalizeSigType(sigType, request);
            // verify each signature
            if (sigType == 0) {
                currentWeight = _validateContractSignature(context, request, digest, signatureCount);
            } else if (sigType == 2) {
                currentWeight = _validateWebauthnSignature(context, request, digest, signatureCount);
            } else {
                // reverts if signature has the wrong s value, wrong v value, or if it's a bad point on the k1 curve
                currentWeight = _validateEOASignature(context, request, digest, signatureCount, sigType);
            }
            if (
                // fail if the signature is out of order or duplicate or is from an unknown signer
                context.currentSigner <= context.lastSigner
                    || !signersPerEntity[request.entityId].contains(request.account, SetValue.wrap(context.currentSigner))
            ) {
                if (context.success) {
                    context.firstFailure = signatureCount;
                    context.success = false;
                }
            }

            accumulatedWeight += currentWeight;
            context.lastSigner = context.currentSigner;
            signatureCount++;
        }

        // if we need a signature on the actual digest, and we didn't get exactly one, revert,
        // we avoid reverting early to facilitate fee estimation
        if (request.requiredNumSigsOnActualDigest != 0) {
            revert InvalidNumSigsOnActualDigest(
                request.entityId, request.account, request.requiredNumSigsOnActualDigest
            );
        }
        return (context.success, context.firstFailure);
    }

    /// @inheritdoc IWeightedMultisigValidationModule
    function getSignerId(address signer) external pure returns (bytes30) {
        return _getSignerId(signer);
    }

    /// @inheritdoc IWeightedMultisigValidationModule
    function getSignerId(PublicKey calldata signer) external pure returns (bytes30) {
        return _getSignerId(signer);
    }

    /// @inheritdoc IWeightedMultisigValidationModule
    function signersMetadataOf(uint32 entityId, address account)
        external
        view
        override
        returns (SignerMetadataWithId[] memory signersMetadataWithId)
    {
        // return the most recent signer first
        bytes30[] memory signerIds = signersPerEntity[entityId].getAll(account).toBytes30Array();
        signersMetadataWithId = new SignerMetadataWithId[](signerIds.length);
        for (uint256 i = 0; i < signerIds.length; ++i) {
            signersMetadataWithId[signerIds.length - i - 1].signerMetadata =
                signersMetadataPerEntity[entityId][signerIds[i]][account];
            signersMetadataWithId[signerIds.length - i - 1].signerId = signerIds[i];
        }
        return signersMetadataWithId;
    }

    /// @inheritdoc IWeightedMultisigValidationModule
    function accountMetadataOf(uint32 entityId, address account)
        external
        view
        override
        returns (AccountMetadata memory)
    {
        return accountMetadataPerEntity[entityId][account];
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Module interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IModule
    function onInstall(bytes calldata data) external override {
        if (data.length == 0) {
            // the caller already checks before calling into onInstall, this is just a safety check
            return;
        }
        (uint32 entityId, SignerMetadata[] memory signersToAdd, uint256 thresholdWeight) =
            abi.decode(data, (uint32, SignerMetadata[], uint256));
        // data input validations
        if (thresholdWeight == 0) {
            revert ZeroThresholdWeight(entityId, msg.sender);
        }
        if (signersToAdd.length == 0) {
            revert TooFewSigners(signersToAdd.length);
        }
        if (signersToAdd.length > MAX_SIGNERS) {
            revert TooManySigners(signersToAdd.length);
        }
        AccountMetadata memory currentAccountMetadata = accountMetadataPerEntity[entityId][msg.sender];
        if (!_isUninitializedAccountMetadata(currentAccountMetadata)) {
            revert AlreadyInitialized(entityId, msg.sender);
        }
        // add signers metadata
        // onInstall does not return any values for now, so the caller need to call the view functions getSignerId() to
        // return the signerId
        (uint256 totalWeightAdded,) = _addSigners(msg.sender, entityId, signersToAdd);
        // add the numSigners, totalWeight and thresholdWeight
        _updateAccountMetadata({
            account: msg.sender,
            entityId: entityId,
            numSigners: signersToAdd.length,
            totalWeight: totalWeightAdded,
            thresholdWeight: thresholdWeight,
            isUninstall: false, // not called by uninstall
            currentAccountMetadata: currentAccountMetadata
        });
    }

    /// @inheritdoc IModule
    function onUninstall(bytes calldata data) external override {
        if (data.length == 0) {
            // the caller already checks before calling into it, this is just a safety check
            return;
        }
        uint32 entityId = abi.decode(data, (uint32));
        AccountMetadata memory currentAccountMetadata = accountMetadataPerEntity[entityId][msg.sender];
        if (_isUninitializedAccountMetadata(currentAccountMetadata)) {
            revert Uninitialized(entityId, msg.sender);
        }
        // delete the numSigners, totalWeight and thresholdWeight
        _updateAccountMetadata({
            account: msg.sender,
            entityId: entityId,
            numSigners: 0,
            totalWeight: 0,
            thresholdWeight: 0,
            isUninstall: true, // called by uninstall, we do not require any signers after uninstallation
            currentAccountMetadata: currentAccountMetadata
        });
        // remove all signers
        _removeAllSigners(msg.sender, entityId);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃   Module only view functions     ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    /// @inheritdoc IModule
    function moduleId() external pure returns (string memory) {
        return MODULE_ID;
    }

    /// @inheritdoc BaseERC712CompliantModule
    function _getModuleTypeHash() internal pure override returns (bytes32) {
        return _MODULE_TYPEHASH;
    }

    /// @inheritdoc BaseERC712CompliantModule
    function _getModuleNameHash() internal pure override returns (bytes32) {
        return _HASHED_MODULE_ID;
    }

    /// @inheritdoc BaseERC712CompliantModule
    function _getModuleVersionHash() internal pure override returns (bytes32) {
        return _HASHED_MODULE_VERSION;
    }

    // ┏━━━━━━━━━━━━━━━┓
    // ┃    EIP-165    ┃
    // ┗━━━━━━━━━━━━━━━┛
    /// @inheritdoc BaseModule
    function supportsInterface(bytes4 interfaceId) public view override(BaseModule, IERC165) returns (bool) {
        return interfaceId == type(IValidationModule).interfaceId
            || interfaceId == type(IWeightedMultisigValidationModule).interfaceId || super.supportsInterface(interfaceId);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Internal Functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    /// @notice Adds signer metadata (weight, address or publicKey) for an account and entity
    /// id, or reverts if any of them cannot be added.
    /// @param account account to add signers and metadata to.
    /// @param entityId entity id for the account.
    /// @param signersMetadata a list of signer metadata.
    /// @return total weight added and a list of signer metadata updated with id.
    function _addSigners(address account, uint32 entityId, SignerMetadata[] memory signersMetadata)
        internal
        returns (uint256, SignerMetadataWithId[] memory)
    {
        uint256 totalWeightAdded = 0;
        SignerMetadataWithId[] memory signersMetadataWithId = new SignerMetadataWithId[](signersMetadata.length);
        for (uint256 i = 0; i < signersMetadata.length; ++i) {
            signersMetadataWithId[i].signerId = _addSignerMetadata(account, entityId, signersMetadata[i]);
            signersMetadataWithId[i].signerMetadata = signersMetadata[i];
            totalWeightAdded += signersMetadata[i].weight;
            // store the signerId, revert if it's already added
            if (!signersPerEntity[entityId].tryAdd(account, SetValue.wrap(signersMetadataWithId[i].signerId))) {
                // shouldn't happen because SignerMetadataAlreadyExists reverts first
                revert SignerIdAlreadyExists(entityId, account, signersMetadataWithId[i].signerId);
            }
        }
        // emit event
        emit SignersAdded(account, entityId, signersMetadataWithId);
        return (totalWeightAdded, signersMetadataWithId);
    }

    /// @notice Removes signers and their metadata for an account, entity id.
    /// @param account account to remove signers and metadata from.
    /// @param entityId entity id for the account and signers.
    /// @param signersToRemove a list of signer ids to be removed.
    function _removeSigners(address account, uint32 entityId, bytes30[] calldata signersToRemove)
        internal
        returns (uint256 totalWeightRemoved)
    {
        // remove signers metadata
        SignerMetadataWithId[] memory deletedSignersMetadata = new SignerMetadataWithId[](signersToRemove.length);
        for (uint256 i = 0; i < signersToRemove.length; ++i) {
            // this is O(n) operation for the time being
            if (!signersPerEntity[entityId].tryRemove(account, SetValue.wrap(signersToRemove[i]))) {
                revert SignerIdDoesNotExist(entityId, account, signersToRemove[i]);
            }
            deletedSignersMetadata[i].signerMetadata = signersMetadataPerEntity[entityId][signersToRemove[i]][account];
            deletedSignersMetadata[i].signerId = signersToRemove[i];
            totalWeightRemoved += deletedSignersMetadata[i].signerMetadata.weight;
            delete signersMetadataPerEntity[entityId][signersToRemove[i]][account];
        }
        emit SignersRemoved(account, entityId, deletedSignersMetadata);
        return totalWeightRemoved;
    }

    /// @notice Removes all signers and their metadata for an account and entity id.
    /// @param account account to remove signers and metadata from.
    /// @param entityId entity id for the account and signers.
    function _removeAllSigners(address account, uint32 entityId) internal {
        bytes30[] memory signerIds = signersPerEntity[entityId].getAll(account).toBytes30Array();
        signersPerEntity[entityId].clear(account);
        SignerMetadataWithId[] memory deletedSignersMetadata = new SignerMetadataWithId[](signerIds.length);
        for (uint256 i = 0; i < signerIds.length; ++i) {
            deletedSignersMetadata[i].signerMetadata = signersMetadataPerEntity[entityId][signerIds[i]][account];
            deletedSignersMetadata[i].signerId = signerIds[i];
            delete signersMetadataPerEntity[entityId][signerIds[i]][account];
        }
        // emit event
        emit SignersRemoved(account, entityId, deletedSignersMetadata);
    }

    /// @notice Updates signer weights for an account, entity id and a list of signers.
    /// @param account account to update weight from.
    /// @param entityId entity id for the account and signers.
    /// @param signersToUpdate a list of signer weights to be updated given its id.
    /// @return total weight added and total weight removed.
    function _updateSignerWeights(address account, uint32 entityId, SignerMetadataWithId[] calldata signersToUpdate)
        internal
        returns (uint256, uint256)
    {
        uint256 totalWeightAdded = 0;
        uint256 totalWeightRemoved = 0;
        uint256 currentWeight = 0;
        uint256 newWeight = 0;
        // we don't need to check (signersToUpdate.length == 0)
        // because the caller already checks before calling into it,
        // also signersToUpdate.length == 0 is allowed in the caller
        // update signer weights based on the signer ids
        for (uint256 i = 0; i < signersToUpdate.length; ++i) {
            _validateWeight(account, entityId, signersToUpdate[i].signerId, signersToUpdate[i].signerMetadata.weight);
            // `currentWeight` will never be zero because zero weights are not allowed during writes.
            // If the signerId is not found, it will revert as well.
            currentWeight = signersMetadataPerEntity[entityId][signersToUpdate[i].signerId][account].weight;
            if (currentWeight == 0) {
                revert SignerMetadataDoesNotExist(entityId, account, signersToUpdate[i].signerId);
            }
            newWeight = signersToUpdate[i].signerMetadata.weight;
            if (newWeight > currentWeight) {
                totalWeightAdded += newWeight - currentWeight;
                signersMetadataPerEntity[entityId][signersToUpdate[i].signerId][account].weight = newWeight;
            } else if (newWeight < currentWeight) {
                totalWeightRemoved += currentWeight - newWeight;
                signersMetadataPerEntity[entityId][signersToUpdate[i].signerId][account].weight = newWeight;
            }
            // no update if currentWeight == signersToUpdate[i].weight
        }
        emit SignersUpdated(account, entityId, signersToUpdate);
        return (totalWeightAdded, totalWeightRemoved);
    }

    /// @notice Updates account metadata (numSigners, totalWeight and thresholdWeight), or reverts if any of them cannot
    /// be added.
    /// @param account account to update account metadata for.
    /// @param entityId entity id for the account and signers.
    /// @param numSigners new num of signers.
    /// @param totalWeight new total weight of the signers.
    /// @param thresholdWeight new threshold weight for the account and entityId, 0 to leave unmodified for
    /// non-uninstall cases.
    /// @param isUninstall is called by uninstall function.
    /// @param currentAccountMetadata current account metadata before update.
    function _updateAccountMetadata(
        address account,
        uint32 entityId,
        uint256 numSigners,
        uint256 totalWeight,
        uint256 thresholdWeight,
        bool isUninstall,
        AccountMetadata memory currentAccountMetadata
    ) internal {
        if (numSigners > MAX_SIGNERS) {
            revert TooManySigners(numSigners);
        }
        // we don't allow 0 signers for non-uninstall cases
        if (!isUninstall && numSigners == 0) {
            revert TooFewSigners(numSigners);
        }
        // update account metadata only if there is a change
        if (numSigners != currentAccountMetadata.numSigners) {
            accountMetadataPerEntity[entityId][account].numSigners = numSigners;
        }
        if (totalWeight != currentAccountMetadata.totalWeight) {
            accountMetadataPerEntity[entityId][account].totalWeight = totalWeight;
        }
        if (isUninstall) {
            accountMetadataPerEntity[entityId][account].thresholdWeight = 0;
        } else {
            // for non-uninstall cases, 0 means unmodified, so we don't update the threshold weight,
            // we set to the new threshold weight if it's different from the current value and non-zero (modified)
            if (thresholdWeight != 0 && thresholdWeight != currentAccountMetadata.thresholdWeight) {
                accountMetadataPerEntity[entityId][account].thresholdWeight = thresholdWeight;
            }
        }
        // ensure that the updated threshold weight (if modified) does not exceed the total weight
        if (
            accountMetadataPerEntity[entityId][account].totalWeight
                < accountMetadataPerEntity[entityId][account].thresholdWeight
        ) {
            revert ThresholdWeightExceedsTotalWeight(
                accountMetadataPerEntity[entityId][account].thresholdWeight,
                accountMetadataPerEntity[entityId][account].totalWeight
            );
        }
        emit AccountMetadataUpdated(
            account, entityId, currentAccountMetadata, accountMetadataPerEntity[entityId][account]
        );
    }

    /// @notice Add signer metadata. Revert if the signer metadata is invalid or already added.
    /// @param account account to add signer metadata to
    /// @param entityId entity id for the account and signer
    /// @param signerMetadata signer metadata
    /// @return the signer id
    function _addSignerMetadata(address account, uint32 entityId, SignerMetadata memory signerMetadata)
        internal
        returns (bytes30)
    {
        // we only allow either the address or public key to be set in the same input
        if (
            (signerMetadata.addr == address(0) && signerMetadata.publicKey.isValidPublicKey())
                || (signerMetadata.addr != address(0) && !signerMetadata.publicKey.isValidPublicKey())
        ) {
            // check if the signer metadata is already added
            bytes30 signerId;
            // only an address or public key is permitted, and it has already been validated
            if (signerMetadata.addr != address(0)) {
                signerId = _getSignerId(signerMetadata.addr);
            } else {
                signerId = _getSignerId(signerMetadata.publicKey);
            }
            _validateWeight(account, entityId, signerId, signerMetadata.weight);
            SignerMetadata memory existingSignerMetadata = signersMetadataPerEntity[entityId][signerId][account];
            if (
                existingSignerMetadata.addr != address(0) || existingSignerMetadata.publicKey.isValidPublicKey()
                    || existingSignerMetadata.weight != 0
            ) {
                revert SignerMetadataAlreadyExists(entityId, account, existingSignerMetadata);
            }
            signersMetadataPerEntity[entityId][signerId][account].weight = signerMetadata.weight;
            if (signerMetadata.addr != address(0)) {
                signersMetadataPerEntity[entityId][signerId][account].addr = signerMetadata.addr;
            } else {
                signersMetadataPerEntity[entityId][signerId][account].publicKey = signerMetadata.publicKey;
            }
            return signerId;
        } else {
            revert InvalidSignerMetadata(entityId, account, signerMetadata);
        }
    }

    function _validateWeight(address account, uint32 entityId, bytes30 signerId, uint256 weight) internal pure {
        if (weight < MIN_WEIGHT || weight > MAX_WEIGHT) {
            revert InvalidSignerWeight(entityId, account, signerId, weight);
        }
    }

    function _getSignerId(address signer) internal pure returns (bytes30) {
        return bytes30(keccak256(abi.encode(CredentialType.ADDRESS, signer)));
    }

    function _getSignerId(PublicKey memory signer) internal pure returns (bytes30) {
        return bytes30(keccak256(abi.encode(CredentialType.PUBLIC_KEY, signer.x, signer.y)));
    }

    function _isUninitializedAccountMetadata(AccountMetadata memory acctMetadata) internal pure returns (bool) {
        return acctMetadata.numSigners == 0;
    }

    function _checkNextSigConstantPartLength(
        CheckNSignaturesContext memory context,
        uint256 signatureCount,
        uint256 sigLength
    ) internal pure {
        // Fail if the next 65 bytes would exceed signature length
        // or lowest dynamic part signature offset, where next 65 bytes is defined as
        // [signatureCount * _INDIVIDUAL_SIGNATURE_BYTES_LEN, signatureCount * _INDIVIDUAL_SIGNATURE_BYTES_LEN +
        // _INDIVIDUAL_SIGNATURE_BYTES_LEN)
        // exclusive
        uint256 sigConstantPartEndPos =
            signatureCount * _INDIVIDUAL_SIGNATURE_BYTES_LEN + _INDIVIDUAL_SIGNATURE_BYTES_LEN;
        if (
            // do not fail if we only have EOA signer so far
            (context.lowestSigDynamicPartOffset != 0 && sigConstantPartEndPos > context.lowestSigDynamicPartOffset)
                || sigConstantPartEndPos > sigLength
        ) {
            if (context.success) {
                // 1st failure
                context.firstFailure = signatureCount;
                context.success = false;
            }
        }
    }

    /// @dev Helper function to get a 65 byte signature constant part from a multi-signature
    /// @dev Functions using this must make sure signatures is long enough to contain
    /// the signature (65 * pos + 65 bytes.)
    /// @param signatures signatures to split
    /// @param pos position in signatures
    function _splitSigConstantPart(bytes memory signatures, uint256 pos)
        internal
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            let signaturePos := mul(0x41, pos)
            r := mload(add(signatures, add(signaturePos, 0x20)))
            s := mload(add(signatures, add(signaturePos, 0x40)))
            v := byte(0, mload(add(signatures, add(signaturePos, 0x60))))
        }
    }

    function _getDigestAndNormalizeSigType(uint8 sigType, CheckNSignaturesRequest memory input)
        internal
        pure
        returns (bytes32, uint8)
    {
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
                input.requiredNumSigsOnActualDigest -= 1;
            }
        } else {
            digest = input.minimalDigest;
        }
        return (digest, sigType);
    }

    /// @dev Helper function to get the dynamic part of a signature. This function works for sigType == 0 and sigType ==
    /// 2.
    ///      Please check the signature encoding scheme before using this function.
    function _getSigDynamicPart(CheckNSignaturesContext memory context, CheckNSignaturesRequest memory request)
        internal
        pure
        returns (bytes memory sigDynamicPartBytes)
    {
        // offset of current signature dynamic part
        // second32Bytes is the memory offset containing the signature
        uint256 sigDynamicPartOffset = uint256(context.second32Bytes);
        if (sigDynamicPartOffset > request.signatures.length || sigDynamicPartOffset < _INDIVIDUAL_SIGNATURE_BYTES_LEN)
        {
            revert InvalidSigOffset(request.entityId, request.account, sigDynamicPartOffset);
        }
        // total length of current signature dynamic part
        uint256 sigDynamicPartTotalLen;
        // 0. load the signatures from CheckNSignaturesRequest struct
        // 1. load contractSignature content starting from the correct memory offset
        // 2. calculate total length including the content and the prefix storing the length
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            let signatures := mload(add(request, 0xa0))
            sigDynamicPartBytes := add(add(signatures, sigDynamicPartOffset), 0x20)
            sigDynamicPartTotalLen := add(mload(sigDynamicPartBytes), 0x20)
        }
        // signature dynamic part should not exceed the total signature length
        if (sigDynamicPartOffset + sigDynamicPartTotalLen > request.signatures.length) {
            revert InvalidSigLength(request.entityId, request.account, (sigDynamicPartOffset + sigDynamicPartTotalLen));
        }
        // Signer 1 appends its signature's dynamic part after signer 2's.
        // The recommended encoding format is: constant part 1, constant part 2, dynamic part 1, dynamic part 2.
        // However, encoding as: constant part 1, constant part 2, dynamic part 2, dynamic part 1 is also valid,
        // since the dynamic part of the signature is indexed by its offset.
        if (sigDynamicPartOffset < context.lowestSigDynamicPartOffset || context.lowestSigDynamicPartOffset == 0) {
            context.lowestSigDynamicPartOffset = sigDynamicPartOffset;
        }
        return sigDynamicPartBytes;
    }

    function _validateContractSignature(
        CheckNSignaturesContext memory context,
        CheckNSignaturesRequest memory request,
        bytes32 digest,
        uint256 signatureCount
    ) internal view returns (uint256) {
        // first32Bytes contains the address to perform 1271 validation on
        address contractAddress = address(uint160(uint256(context.first32Bytes)));
        // make sure upper bits are clean
        if (uint256(context.first32Bytes) > uint256(uint160(contractAddress))) {
            revert InvalidAddress(request.entityId, request.account, contractAddress);
        }
        context.currentSigner = _getSignerId(contractAddress);
        SignerMetadata memory currentSignerMetadata =
            signersMetadataPerEntity[request.entityId][context.currentSigner][request.account];
        if (currentSignerMetadata.addr != contractAddress) {
            if (context.success) {
                context.firstFailure = signatureCount;
                context.success = false;
            }
        }
        // retrieve contract signature
        bytes memory sigDynamicPartBytes = _getSigDynamicPart(context, request);
        if (!SignatureChecker.isValidERC1271SignatureNow(contractAddress, digest, sigDynamicPartBytes)) {
            if (context.success) {
                context.firstFailure = signatureCount;
                context.success = false;
            }
        }
        return currentSignerMetadata.weight;
    }

    function _validateWebauthnSignature(
        CheckNSignaturesContext memory context,
        CheckNSignaturesRequest memory request,
        bytes32 digest,
        uint256 signatureCount
    ) internal view returns (uint256) {
        // first32Bytes stores public key on-chain identifier
        context.currentSigner = bytes30(uint240(uint256(context.first32Bytes)));
        SignerMetadata memory currentSignerMetadata =
            signersMetadataPerEntity[request.entityId][context.currentSigner][request.account];
        // retrieve sig dynamic part bytes
        bytes memory sigDynamicPartBytes = _getSigDynamicPart(context, request);
        WebAuthnSigDynamicPart memory sigDynamicPart = abi.decode(sigDynamicPartBytes, (WebAuthnSigDynamicPart));
        if (
            !WebAuthnLib.verify({
                challenge: abi.encode(digest),
                webAuthnData: sigDynamicPart.webAuthnData,
                r: sigDynamicPart.r,
                s: sigDynamicPart.s,
                x: currentSignerMetadata.publicKey.x,
                y: currentSignerMetadata.publicKey.y
            })
        ) {
            if (context.success) {
                context.firstFailure = signatureCount;
                context.success = false;
            }
        }
        return currentSignerMetadata.weight;
    }

    function _validateEOASignature(
        CheckNSignaturesContext memory context,
        CheckNSignaturesRequest memory request,
        bytes32 digest,
        uint256 signatureCount,
        uint8 sigType
    ) internal view returns (uint256) {
        // reverts if signature has the wrong s value, wrong v value, or if it's a bad point on the k1 curve
        address signer = digest.recover(sigType, context.first32Bytes, context.second32Bytes);
        context.currentSigner = _getSignerId(signer);
        SignerMetadata memory currentSignerMetadata =
            signersMetadataPerEntity[request.entityId][context.currentSigner][request.account];
        if (currentSignerMetadata.addr != signer) {
            if (context.success) {
                context.firstFailure = signatureCount;
                context.success = false;
            }
        }
        return currentSignerMetadata.weight;
    }

    /// @dev Get the minimal user op digest with user op hash with gas fields or paymasterAndData set to default values.
    /// @param userOp the user operation
    /// @return minimal user op hash and sender
    function _getMinimalUserOpDigest(PackedUserOperation calldata userOp) internal view returns (bytes32, address) {
        address sender = userOp.getSender();
        uint256 nonce = userOp.nonce;
        bytes32 hashInitCode = userOp.initCode.calldataKeccak();
        bytes32 hashCallData = userOp.callData.calldataKeccak();
        bytes32 userOpHash = keccak256(
            abi.encode(
                sender,
                nonce,
                hashInitCode,
                hashCallData,
                ZERO_BYTES32, // accountGasLimits
                ZERO, // preVerificationGas = 0
                ZERO_BYTES32, // gasFees
                EMPTY_HASH // paymasterAndData = keccak256('')
            )
        );
        // include chainid to prevent replay across chains
        return (keccak256(abi.encode(userOpHash, ENTRYPOINT, block.chainid)).toEthSignedMessageHash(), sender);
    }
}
