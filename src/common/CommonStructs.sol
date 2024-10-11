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

struct PublicKey {
    uint256 x;
    uint256 y;
}

/// @dev WebAuthn related data.
struct WebAuthnData {
    /// @dev The WebAuthn authenticator data.
    ///      See https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-authenticatordata.
    bytes authenticatorData;
    /// @dev The WebAuthn client data JSON.
    ///      See https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson.
    string clientDataJSON;
    /// @dev The index at which "challenge":"..." occurs in `clientDataJSON`.
    uint256 challengeIndex;
    /// @dev The index at which "type":"..." occurs in `clientDataJSON`.
    uint256 typeIndex;
    /// @dev Checks that the authenticator enforced user verification. User verification should be required if, and only
    /// if, options.userVerification is set to required in the request.
    bool requireUserVerification;
}

/// @dev Follow "Smart Contract Signatures Encoding".
struct WebAuthnSigDynamicPart {
    /// @dev Webauthn related data
    WebAuthnData webAuthnData;
    /// @dev The r value of secp256r1 signature
    uint256 r;
    /// @dev The s value of secp256r1 signature
    uint256 s;
}

enum CredentialType {
    PUBLIC_KEY,
    ADDRESS
}

/// @notice For public credential, we either store public key or address but not both.
/// @param weight required, weightage on each owner
/// @param credType required, public credential type
/// @param publicKeyX optional, x coordinate of public key
/// @param publicKeyY optional, y coordinate of public key
/// @param addr optional, owner address
struct OwnerData {
    uint256 weight;
    CredentialType credType; // 1 byte, fit in the same slot as addr (if used) or its own slot
    address addr; // 20 bytes if used, fit in the same slot as credType
    uint256 publicKeyX; // 32 bytes if used
    uint256 publicKeyY; // 32 bytes if used
}

/// @notice Metadata of the ownership of an account.
/// @param numOwners number of owners on the account
/// @param thresholdWeight weight of signatures required to perform an action
/// @param totalWeight total weight of signatures required to perform an action
struct OwnershipMetadata {
    uint256 numOwners;
    uint256 thresholdWeight;
    uint256 totalWeight;
}
