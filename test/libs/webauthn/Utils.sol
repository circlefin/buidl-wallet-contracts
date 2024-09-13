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

import {FCL_Elliptic_ZZ} from "FreshCryptoLib/FCL_elliptic.sol";
import {Base64Url} from "FreshCryptoLib/utils/Base64Url.sol";

struct WebAuthnInfo {
    bytes authenticatorData;
    string clientDataJSON;
    bytes32 messageHash;
}

library Utils {
    uint256 internal constant P256_N_DIV_2 = FCL_Elliptic_ZZ.n / 2;

    function getWebAuthnStruct(bytes32 challenge) public pure returns (WebAuthnInfo memory) {
        string memory challengeb64url = Base64Url.encode(abi.encode(challenge));
        string memory clientDataJSON = string(
            abi.encodePacked(
                // solhint-disable-next-line quotes
                '{"type":"webauthn.get","challenge":"',
                challengeb64url,
                // solhint-disable-next-line quotes
                '","origin":"https://sign.coinbase.com","crossOrigin":false}'
            )
        );

        // Authenticator data for Chrome Profile touchID signature
        bytes memory authenticatorData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000";

        bytes32 clientDataJSONHash = sha256(bytes(clientDataJSON));
        bytes32 messageHash = sha256(abi.encodePacked(authenticatorData, clientDataJSONHash));

        return WebAuthnInfo(authenticatorData, clientDataJSON, messageHash);
    }

    /// @dev normalizes the s value from a p256r1 signature so that
    /// it will pass malleability checks.
    function normalizeS(uint256 s) public pure returns (uint256) {
        if (s > P256_N_DIV_2) {
            return FCL_Elliptic_ZZ.n - s;
        }

        return s;
    }
}
