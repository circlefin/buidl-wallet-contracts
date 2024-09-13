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

import {FCL_ecdsa} from "@fcl/FCL_ecdsa.sol";
import {FCL_Elliptic_ZZ} from "@fcl/FCL_elliptic.sol";
import {WebAuthnData} from "../common/CommonStructs.sol";

/// @title WebAuthn
///
/// @notice A library for verifying WebAuthn Authentication Assertions, built off the work
///         of Coinbase and Daimo.
///
/// @dev Attempts to use the RIP-7212 precompile for signature verification.
///      If precompile verification fails, it falls back to FreshCryptoLib.
/// @dev We use SigType (one byte) to differentiate between signature types.
///      If SigType == 0, then it's a contract signature (EIP-1271).
///      If SigType == 1, then it's pre-validated signature that we don't support.
///      If SigType == 2, then it's a secp256r1 signature.
///      If SigType > 26 && SigType < 31, then it's secp256k1 signature.
///      If SigType > 30, then it's eth_sign signature that we don't support.
///      If SigType >= 32, then it's a multisig signature authenticating an actual digest.
///      For more details, please refer to "Smart Contract Signatures Encoding" doc.
/// @dev “secp256r1” ECDSA signatures consist of v, r, and s components. While the v value makes it possible to
/// recover the public key of the signer,
///      most signers do not generate the v component of the signature since r and s are sufficient for
/// verification. In order to provide an exact and more compatible implementation, verification is preferred over
/// recovery for the precompile.
/// Existing P256 implementations verify (x, y, r, s) directly. Note that many implementations use (0, 0) as the
/// reference point at infinity, which is not on the curve and should therefore be rejected.
///
/// @author Circle
/// @author Coinbase (https://github.com/base-org/webauthn-sol)
/// @author Daimo (https://github.com/daimo-eth/p256-verifier/blob/master/src/WebAuthn.sol)
library WebAuthnLib {
    /// @dev Bit 0 of the authenticator data struct, corresponding to the "User Present" bit.
    ///      See https://www.w3.org/TR/webauthn-2/#flags.
    bytes1 private constant _AUTH_DATA_FLAGS_UP = 0x01;

    /// @dev Bit 2 of the authenticator data struct, corresponding to the "User Verified" bit.
    ///      See https://www.w3.org/TR/webauthn-2/#flags.
    bytes1 private constant _AUTH_DATA_FLAGS_UV = 0x04;

    /// @dev Secp256r1 curve order / 2 used as guard to prevent signature malleability issue.
    uint256 private constant _P256_N_DIV_2 = FCL_Elliptic_ZZ.n / 2;

    /// @dev The precompiled contract address to use for signature verification in the “secp256r1” elliptic curve.
    ///      See https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7212.md.
    address private constant _VERIFIER = address(0x100);

    /// @dev The expected type (hash) in the client data JSON when verifying assertion signatures.
    ///      See https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-type
    // solhint-disable-next-line quotes
    bytes32 private constant _EXPECTED_TYPE_HASH = keccak256('"type":"webauthn.get"');

    string internal constant _TABLE_URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    ///
    /// @notice Verifies a Webauthn Authentication Assertion as described
    /// in https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion.
    ///
    /// @dev We do not verify all the steps as described in the specification, only ones relevant to our context.
    ///      Please carefully read through this list before usage.
    ///
    ///      Specifically, we do verify the following:
    ///         - Verify that authenticatorData (which comes from the authenticator, such as iCloud Keychain) indicates
    ///           a well-formed assertion with the user present bit set. If `requireUserVerification` is set, checks
    /// that the
    /// authenticator
    ///           enforced user verification. User verification should be required if, and only if,
    /// options.userVerification
    ///           is set to required in the request.
    ///         - Verifies that the client JSON is of type "webauthn.get", i.e. the client was responding to a request
    /// to
    ///           assert authentication.
    ///         - Verifies that the client JSON contains the requested challenge.
    ///         - Verifies that (r, s) constitute a valid signature over both the authenticatorData and client JSON, for
    /// public
    ///            key (x, y).
    ///
    ///      We make some assumptions about the particular use case of this verifier, so we do NOT verify the following:
    ///         - Does NOT verify that the origin in the `clientDataJSON` matches the Relying Party's origin: tt is
    /// considered
    ///           the authenticator's responsibility to ensure that the user is interacting with the correct RP. This is
    ///           enforced by most high quality authenticators properly, particularly the iCloud Keychain and Google
    /// Password
    ///           Manager were tested.
    ///         - Does NOT verify That `topOrigin` in `clientDataJSON` is well-formed: We assume it would never be
    /// present, i.e.
    ///           the credentials are never used in a cross-origin/iframe context. The website/app set up should
    /// disallow
    ///           cross-origin usage of the credentials. This is the default behaviour for created credentials in common
    /// settings.
    ///         - Does NOT verify that the `rpIdHash` in `authenticatorData` is the SHA-256 hash of the RP ID expected
    /// by the Relying
    ///           Party: this means that we rely on the authenticator to properly enforce credentials to be used only by
    /// the correct RP.
    ///           This is generally enforced with features like Apple App Site Association and Google Asset Links. To
    /// protect from
    ///           edge cases in which a previously-linked RP ID is removed from the authorised RP IDs, we recommend that
    /// messages
    ///           signed by the authenticator include some expiry mechanism.
    ///         - Does NOT verify the credential backup state: this assumes the credential backup state is NOT used as
    /// part of Relying
    ///           Party business logic or policy.
    ///         - Does NOT verify the values of the client extension outputs: this assumes that the Relying Party does
    /// not use client
    ///           extension outputs.
    ///         - Does NOT verify the signature counter: signature counters are intended to enable risk scoring for the
    /// Relying Party.
    ///           This assumes risk scoring is not used as part of Relying Party business logic or policy.
    ///         - Does NOT verify the attestation object: this assumes that response.attestationObject is NOT present in
    /// the response,
    ///           i.e. the RP does not intend to verify an attestation.
    ///
    /// @param challenge    The challenge that was provided by the relying party.
    /// @param webAuthnData The `WebAuthnData` struct.
    /// @param r            The r value of secp256r1 signature.
    /// @param s            The s value of secp256r1 signature
    /// @param x            The x coordinate of the public key.
    /// @param y            The y coordinate of the public key.
    ///
    /// @return `true` if the authentication assertion passed validation, else `false`.
    function verify(
        bytes memory challenge,
        WebAuthnData memory webAuthnData,
        uint256 r,
        uint256 s,
        uint256 x,
        uint256 y
    ) internal view returns (bool) {
        if (s > _P256_N_DIV_2) {
            // guard against signature malleability
            return false;
        }

        // 11. Verify that the value of C.type is the string webauthn.get.
        //     bytes("type":"webauthn.get").length = 21
        string memory _type = _slice(webAuthnData.clientDataJSON, webAuthnData.typeIndex, webAuthnData.typeIndex + 21);
        if (keccak256(bytes(_type)) != _EXPECTED_TYPE_HASH) {
            return false;
        }

        // 12. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
        // solhint-disable-next-line quotes
        bytes memory expectedChallenge = bytes(string.concat('"challenge":"', encodeURL(challenge), '"'));
        string memory actualChallenge = _slice(
            webAuthnData.clientDataJSON,
            webAuthnData.challengeIndex,
            webAuthnData.challengeIndex + expectedChallenge.length
        );
        if (keccak256(bytes(actualChallenge)) != keccak256(expectedChallenge)) {
            return false;
        }

        // Skip 13., 14., 15.

        // 16. Verify that the UP bit of the flags in authData is set.
        if (webAuthnData.authenticatorData[32] & _AUTH_DATA_FLAGS_UP != _AUTH_DATA_FLAGS_UP) {
            return false;
        }

        // 17. If user verification is required for this assertion, verify that the User Verified bit of the flags in
        //     authData is set.
        if (
            webAuthnData.requireUserVerification
                && (webAuthnData.authenticatorData[32] & _AUTH_DATA_FLAGS_UV) != _AUTH_DATA_FLAGS_UV
        ) {
            return false;
        }

        // skip 18.

        // 19. Let hash be the result of computing a hash over the cData using SHA-256.
        bytes32 clientDataJSONHash = sha256(bytes(webAuthnData.clientDataJSON));

        // 20. Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of authData
        //     and hash.
        bytes32 messageHash = sha256(abi.encodePacked(webAuthnData.authenticatorData, clientDataJSONHash));
        bytes memory args = abi.encode(messageHash, r, s, x, y);
        // try the RIP-7212 precompile address
        (bool success, bytes memory ret) = _VERIFIER.staticcall(args);
        // staticcall will not revert if address has no code
        // check return length
        // note that even if precompile exists, ret.length is 0 when verification returns false
        // so an invalid signature will be checked twice: once by the precompile and once by FCL.
        // Ideally this signature failure is simulated offchain and no one actually pay this gas.
        bool valid = ret.length > 0;
        if (success && valid) return abi.decode(ret, (uint256)) == 1;

        return FCL_ecdsa.ecdsa_verify(messageHash, r, s, x, y);
    }

    /// @dev Fork from Solady without introducing the dependency with whole LibString
    ///      as other functions are failing the security scans.
    function _slice(string memory subject, uint256 start, uint256 end) internal pure returns (string memory result) {
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            let subjectLength := mload(subject)
            if iszero(gt(subjectLength, end)) { end := subjectLength }
            if iszero(gt(subjectLength, start)) { start := subjectLength }
            if lt(start, end) {
                result := mload(0x40)
                let resultLength := sub(end, start)
                mstore(result, resultLength)
                subject := add(subject, start)
                let w := not(0x1f)
                // Copy the `subject` one word at a time, backwards.
                for { let o := and(add(resultLength, 0x1f), w) } 1 {} {
                    mstore(add(result, o), mload(add(subject, o)))
                    o := add(o, w) // `sub(o, 0x20)`.
                    if iszero(o) { break }
                }
                // Zeroize the slot after the string.
                mstore(add(add(result, 0x20), resultLength), 0)
                // Allocate memory for the length and the bytes,
                // rounded up to a multiple of 32.
                mstore(0x40, add(result, and(add(resultLength, 0x3f), w)))
            }
        }
    }

    /**
     * @notice Forked from OZ 5. Please remove this function after library upgrade.
     * @dev Converts a `bytes` to its Bytes64Url `string` representation.
     */
    function encodeURL(bytes memory data) internal pure returns (string memory) {
        return _encode(data, _TABLE_URL, false);
    }

    /**
     * @dev Internal table-agnostic conversion
     */
    function _encode(bytes memory data, string memory table, bool withPadding) private pure returns (string memory) {
        /**
         * Inspired by Brecht Devos (Brechtpd) implementation - MIT licence
         * https://github.com/Brechtpd/base64/blob/e78d9fd951e7b0977ddca77d92dc85183770daf4/base64.sol
         */
        if (data.length == 0) return "";

        // If padding is enabled, the final length should be `bytes` data length divided by 3 rounded up and then
        // multiplied by 4 so that it leaves room for padding the last chunk
        // - `data.length + 2`  -> Round up
        // - `/ 3`              -> Number of 3-bytes chunks
        // - `4 *`              -> 4 characters for each chunk
        // If padding is disabled, the final length should be `bytes` data length multiplied by 4/3 rounded up as
        // opposed to when padding is required to fill the last chunk.
        // - `4 *`              -> 4 characters for each chunk
        // - `data.length + 2`  -> Round up
        // - `/ 3`              -> Number of 3-bytes chunks
        uint256 resultLength = withPadding ? 4 * ((data.length + 2) / 3) : (4 * data.length + 2) / 3;

        string memory result = new string(resultLength);

        /// @solidity memory-safe-assembly
        // solhint-disable-next-line no-inline-assembly
        assembly {
            // Prepare the lookup table (skip the first "length" byte)
            let tablePtr := add(table, 1)

            // Prepare result pointer, jump over length
            let resultPtr := add(result, 0x20)
            let dataPtr := data
            let endPtr := add(data, mload(data))

            // In some cases, the last iteration will read bytes after the end of the data. We cache the value, and
            // set it to zero to make sure no dirty bytes are read in that section.
            let afterPtr := add(endPtr, 0x20)
            let afterCache := mload(afterPtr)
            mstore(afterPtr, 0x00)

            // Run over the input, 3 bytes at a time
            for {} lt(dataPtr, endPtr) {} {
                // Advance 3 bytes
                dataPtr := add(dataPtr, 3)
                let input := mload(dataPtr)

                // To write each character, shift the 3 byte (24 bits) chunk
                // 4 times in blocks of 6 bits for each character (18, 12, 6, 0)
                // and apply logical AND with 0x3F to bitmask the least significant 6 bits.
                // Use this as an index into the lookup table, mload an entire word
                // so the desired character is in the least significant byte, and
                // mstore8 this least significant byte into the result and continue.

                mstore8(resultPtr, mload(add(tablePtr, and(shr(18, input), 0x3F))))
                resultPtr := add(resultPtr, 1) // Advance

                mstore8(resultPtr, mload(add(tablePtr, and(shr(12, input), 0x3F))))
                resultPtr := add(resultPtr, 1) // Advance

                mstore8(resultPtr, mload(add(tablePtr, and(shr(6, input), 0x3F))))
                resultPtr := add(resultPtr, 1) // Advance

                mstore8(resultPtr, mload(add(tablePtr, and(input, 0x3F))))
                resultPtr := add(resultPtr, 1) // Advance
            }

            // Reset the value that was cached
            mstore(afterPtr, afterCache)

            if withPadding {
                // When data `bytes` is not exactly 3 bytes long
                // it is padded with `=` characters at the end
                switch mod(mload(data), 3)
                case 1 {
                    mstore8(sub(resultPtr, 1), 0x3d)
                    mstore8(sub(resultPtr, 2), 0x3d)
                }
                case 2 { mstore8(sub(resultPtr, 1), 0x3d) }
            }
        }

        return result;
    }
}
