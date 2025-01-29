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

/// @notice We either store public key or address but not both for the convenience of lookup.
/// @param weight, weightage on each signer
/// @param addr, signer address
/// @param publicKey, x and y coordinate of public key
struct SignerMetadata {
    uint256 weight;
    address addr;
    // OR
    PublicKey publicKey;
}

/// @notice Return the id along with the signer metadata. This struct is not persisted in storage.
/// @param signerMetadata, metadata of the signer
/// @param signer id, unique identifier for the signer
struct SignerMetadataWithId {
    SignerMetadata signerMetadata;
    bytes30 signerId;
}

/// @notice Metadata of an account.
/// @param numSigners number of signers on the account
/// @param thresholdWeight weight of signatures required to perform an action
/// @param totalWeight total weight of signatures required to perform an action
struct AccountMetadata {
    uint256 numSigners;
    uint256 thresholdWeight;
    uint256 totalWeight;
}

/// @notice Request data for verifying signatures.
/// @param entityId entity id for the account and signer
/// @param actualDigest actual digest signed
/// @param minimalDigest minimal digest signed
/// @param requiredNumSigsOnActualDigest number of signatures required on actual digest, if the actual and minimal
/// digests differ, make sure we have exactly 1 sig on the actual digest
/// @param account account address
/// @param signatures encoded signatures
struct CheckNSignaturesRequest {
    uint32 entityId;
    bytes32 actualDigest;
    bytes32 minimalDigest;
    uint256 requiredNumSigsOnActualDigest;
    address account;
    bytes signatures;
}

/// @notice Context for checkNSignatures.
struct CheckNSignaturesContext {
    // lowestOffset of signature dynamic part, must locate after the signature constant part
    // 0 means we only have EOA signer so far
    uint256 lowestSigDynamicPartOffset;
    bytes30 lastSigner;
    bytes30 currentSigner;
    bool success;
    uint256 firstFailure;
    // first32Bytes of signature constant part
    bytes32 first32Bytes;
    // second32Bytes of signature constant part
    bytes32 second32Bytes;
}
