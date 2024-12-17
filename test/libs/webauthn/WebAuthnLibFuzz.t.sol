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

import {TestUtils} from "../.../../../util/TestUtils.sol";

import {WebAuthnData} from "../../../src/common/CommonStructs.sol";
import {WebAuthnLib} from "../../../src/libs/WebAuthnLib.sol";
import {Utils} from "./Utils.sol";
import {FCL_ecdsa} from "@fcl/FCL_ecdsa.sol";
import {stdJson} from "forge-std/src/StdJson.sol";
import {console} from "forge-std/src/console.sol";

contract WebAuthnFuzzTest is TestUtils {
    using stdJson for string;

    string internal constant TEST_FILE = "/test/fixtures/assertions_fixture.json";

    /// @dev `WebAuthn.verify` should return `false` when `s` is above P256_N_DIV_2.
    function testVerify_ShouldReturnFalse_WhenSAboveP256_N_DIV_2() public view {
        string memory rootPath = vm.projectRoot();
        string memory path = string.concat(rootPath, TEST_FILE);
        string memory json = vm.readFile(path);
        uint256 count = abi.decode(json.parseRaw(".count"), (uint256));

        for (uint256 i; i < count; i++) {
            (
                string memory jsonCaseSelector,
                bytes memory challenge,
                bool uv,
                WebAuthnData memory webAuthnData,
                uint256 r,
                uint256 s,
                uint256 x,
                uint256 y
            ) = _parseJson({json: json, caseIndex: i});

            console.log("Verifying", jsonCaseSelector);

            // Only interested in s > P256_N_DIV_2 cases.
            if (s <= Utils.P256_N_DIV_2) {
                s = FCL_ecdsa.n - s;
            }

            webAuthnData.requireUserVerification = uv;
            bool res = WebAuthnLib.verify({challenge: challenge, webAuthnData: webAuthnData, r: r, s: s, x: x, y: y});

            // Assert the verification failed to guard against signature malleability.
            assertEq(res, false, string.concat("Failed on ", jsonCaseSelector));

            console.log("------------------------------------");
        }
    }

    /// @dev `WebAuthn.verify` should return `false` when the `up` flag is not set.
    function testVerify_ShouldReturnFalse_WhenTheUpFlagIsNotSet() public view {
        string memory rootPath = vm.projectRoot();
        string memory path = string.concat(rootPath, TEST_FILE);
        string memory json = vm.readFile(path);
        uint256 count = abi.decode(json.parseRaw(".count"), (uint256));

        for (uint256 i; i < count; i++) {
            (
                string memory jsonCaseSelector,
                bytes memory challenge,
                bool uv,
                WebAuthnData memory webAuthnData,
                uint256 r,
                uint256 s,
                uint256 x,
                uint256 y
            ) = _parseJson({json: json, caseIndex: i});

            console.log("Verifying", jsonCaseSelector);

            s = Utils.normalizeS(s);

            // Unset the `up` flag.
            webAuthnData.authenticatorData[32] = webAuthnData.authenticatorData[32] & bytes1(0xfe);

            webAuthnData.requireUserVerification = uv;
            bool res = WebAuthnLib.verify({challenge: challenge, webAuthnData: webAuthnData, r: r, s: s, x: x, y: y});

            // Assert the verification failed because the `up` flag was not set.
            assertEq(res, false, string.concat("Failed on ", jsonCaseSelector));

            console.log("------------------------------------");
        }
    }

    /// @dev `WebAuthn.verify` should return `false` when `requireUV` is `true` but the
    ///       authenticator did not set the `uv` flag.
    function testVerify_ShouldReturnFalse_WhenUserVerificationIsRequiredButTestWasNotPerformed() public view {
        string memory rootPath = vm.projectRoot();
        string memory path = string.concat(rootPath, TEST_FILE);
        string memory json = vm.readFile(path);
        uint256 count = abi.decode(json.parseRaw(".count"), (uint256));

        for (uint256 i; i < count; i++) {
            (
                string memory jsonCaseSelector,
                bytes memory challenge,
                bool uv,
                WebAuthnData memory webAuthnData,
                uint256 r,
                uint256 s,
                uint256 x,
                uint256 y
            ) = _parseJson({json: json, caseIndex: i});

            console.log("Verifying", jsonCaseSelector);

            // Only interested in s > P256_N_DIV_2 cases with uv not performed.
            if (uv == true) {
                continue;
            }

            s = Utils.normalizeS(s);

            // Set UV to required to ensure false is returned
            webAuthnData.requireUserVerification = true;
            bool res = WebAuthnLib.verify({challenge: challenge, webAuthnData: webAuthnData, r: r, s: s, x: x, y: y});

            // Assert the verification failed because user verification was required but not performed by the
            // authenticator.
            assertEq(res, false, string.concat("Failed on ", jsonCaseSelector));
            console.log("------------------------------------");
        }
    }

    /// @dev `WebAuthn.verify` should return `true` when `s` is below `P256_N_DIV_2` and `requireUserVerification`
    ///       "matches" with the `uv` flag set by the authenticator.
    function testVerify_ShouldReturnTrue_WhenSBelowP256_N_DIV_2() public view {
        string memory rootPath = vm.projectRoot();
        string memory path = string.concat(rootPath, TEST_FILE);
        string memory json = vm.readFile(path);

        uint256 count = abi.decode(json.parseRaw(".count"), (uint256));

        for (uint256 i; i < count; i++) {
            (
                string memory jsonCaseSelector,
                bytes memory challenge,
                bool uv,
                WebAuthnData memory webAuthnData,
                uint256 r,
                uint256 s,
                uint256 x,
                uint256 y
            ) = _parseJson({json: json, caseIndex: i});

            console.log("Verifying", jsonCaseSelector);

            s = Utils.normalizeS(s);

            webAuthnData.requireUserVerification = uv;
            bool res = WebAuthnLib.verify({challenge: challenge, webAuthnData: webAuthnData, r: r, s: s, x: x, y: y});

            // Assert the verification succeeded.
            assertEq(res, true, string.concat("Failed on ", jsonCaseSelector));
            console.log("------------------------------------");
        }
    }

    /// @dev Helper function to parse a test case from the given json string.
    /// @param json The json string to parse.
    /// @param caseIndex The test case index to parse.
    function _parseJson(string memory json, uint256 caseIndex)
        private
        pure
        returns (
            string memory jsonCaseSelector,
            bytes memory challenge,
            bool uv,
            WebAuthnData memory webAuthnData,
            uint256 r,
            uint256 s,
            uint256 x,
            uint256 y
        )
    {
        jsonCaseSelector = string.concat(".cases.[", string.concat(vm.toString(caseIndex), "]"));
        challenge = abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".challenge")), (bytes));
        uv = abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".uv")), (bool));

        webAuthnData.authenticatorData =
            abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".authenticator_data")), (bytes));
        webAuthnData.clientDataJSON =
            abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".client_data_json.json")), (string));
        webAuthnData.challengeIndex =
            abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".client_data_json.challenge_index")), (uint256));
        webAuthnData.typeIndex =
            abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".client_data_json.type_index")), (uint256));

        r = abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".r")), (uint256));
        s = abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".s")), (uint256));
        x = abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".x")), (uint256));
        y = abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".y")), (uint256));
    }
}
