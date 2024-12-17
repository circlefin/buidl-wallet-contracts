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
import {Base64Url} from "@fcl/utils/Base64Url.sol";

contract WebAuthnTest is TestUtils {
    bytes private challenge = abi.encode(0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf);

    function testSafari() public view {
        uint256 x = 28573233055232466711029625910063034642429572463461595413086259353299906450061;
        uint256 y = 39367742072897599771788408398752356480431855827262528811857788332151452825281;
        WebAuthnData memory auth = WebAuthnData({
            authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000101",
            clientDataJSON: string.concat(
                // solhint-disable-next-line quotes
                '{"type":"webauthn.get","challenge":"',
                Base64Url.encode(challenge),
                // solhint-disable-next-line quotes
                '","origin":"http://localhost:3005"}'
            ),
            challengeIndex: 23,
            typeIndex: 1,
            requireUserVerification: false
        });
        uint256 r = 43684192885701841787131392247364253107519555363555461570655060745499568693242;
        uint256 s = 22655632649588629308599201066602670461698485748654492451178007896016452673579;
        assertTrue(WebAuthnLib.verify(challenge, auth, r, s, x, y));
    }

    function testChrome() public view {
        uint256 x = 28573233055232466711029625910063034642429572463461595413086259353299906450061;
        uint256 y = 39367742072897599771788408398752356480431855827262528811857788332151452825281;
        WebAuthnData memory auth = WebAuthnData({
            authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763050000010a",
            clientDataJSON: string.concat(
                // solhint-disable-next-line quotes
                '{"type":"webauthn.get","challenge":"',
                Base64Url.encode(challenge),
                // solhint-disable-next-line quotes
                '","origin":"http://localhost:3005","crossOrigin":false}'
            ),
            challengeIndex: 23,
            typeIndex: 1,
            requireUserVerification: false
        });
        uint256 r = 29739767516584490820047863506833955097567272713519339793744591468032609909569;
        uint256 s = 45947455641742997809691064512762075989493430661170736817032030660832793108102;
        assertTrue(WebAuthnLib.verify(challenge, auth, r, s, x, y));
    }
}
