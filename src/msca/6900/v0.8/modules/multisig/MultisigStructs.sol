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

/// @notice For credential, we either store public key or address but not both.
/// @param addr, signer address
/// @param weight, weightage on each signer
/// @param publicKeyX, x coordinate of public key
/// @param publicKeyY, y coordinate of public key
struct SignerData {
    uint256 weight;
    address addr;
    PublicKey publicKey;
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

/// @notice Data for verifying signatures.
/// @param entityId entity id for the account and signer
/// @param actualDigest actual digest signed
/// @param minimalDigest minimal digest signed
/// @param account account address
/// @param signatures encoded signatures
struct CheckNSignaturesInput {
    uint32 entityId;
    bytes32 actualDigest;
    bytes32 minimalDigest;
    address account;
    bytes signatures;
}
