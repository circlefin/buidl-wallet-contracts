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

import "../src/paymaster/v1/permissioned/SponsorPaymaster.sol";

import "./util/TestUtils.sol";

import "@account-abstraction/contracts/core/EntryPoint.sol";
import "@account-abstraction/contracts/interfaces/IPaymaster.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract SponsorPaymasterTest is TestUtils {
    using UserOperationLib for PackedUserOperation;
    using MessageHashUtils for bytes32;

    event Upgraded(address indexed implementation);

    // proxy
    SponsorPaymaster public sponsorPaymaster;
    IEntryPoint internal entryPoint = new EntryPoint();
    uint256 internal verifyingSigner1PrivateKey = 0xabc;
    uint256 internal verifyingSigner2PrivateKey = 0xdef;
    address internal verifyingSigner1;
    address internal verifyingSigner2;
    uint48 internal MOCK_VALID_UNTIL = 1691493273;
    uint48 internal MOCK_VALID_AFTER = 1681493273;
    bytes internal MOCK_OFFCHAIN_SIG = "0x123456";
    uint128 internal MOCK_PAYMASTER_VERIFICATION_GAS_LIMIT = 1500;
    uint128 internal MOCK_PAYMASTER_POST_OP_GAS_LIMIT = 3000;

    function setUp() public {
        verifyingSigner1 = vm.addr(verifyingSigner1PrivateKey);
        verifyingSigner2 = vm.addr(verifyingSigner2PrivateKey);
        address[] memory verifyingSigners = new address[](2);
        verifyingSigners[0] = verifyingSigner1;
        verifyingSigners[1] = verifyingSigner2;
        SponsorPaymaster sponsorPaymasterImpl = new SponsorPaymaster(entryPoint);
        address ownerAddr = vm.addr(111);
        sponsorPaymaster = SponsorPaymaster(
            payable(
                new ERC1967Proxy(
                    address(sponsorPaymasterImpl),
                    abi.encodeCall(SponsorPaymaster.initialize, (ownerAddr, verifyingSigners))
                )
            )
        );
    }

    function testAddVerifyingSigner() public {
        vm.startPrank(sponsorPaymaster.owner());
        uint256 newVerifyingSignerPrivateKey = 0xbcd;
        address newVerifyingSigner = vm.addr(newVerifyingSignerPrivateKey);
        address[] memory verifyingSigners = new address[](1);
        verifyingSigners[0] = newVerifyingSigner;
        sponsorPaymaster.addVerifyingSigners(verifyingSigners);
        vm.stopPrank();

        address[] memory actualVerifyingSigners = sponsorPaymaster.getAllSigners();
        assertEq(actualVerifyingSigners.length, 3);
    }

    function testAddVerifyingSigner_alreadyExist() public {
        vm.startPrank(sponsorPaymaster.owner());
        uint256 newVerifyingSignerPrivateKey = 0xabc;
        address newVerifyingSigner = vm.addr(newVerifyingSignerPrivateKey);
        address[] memory alreadyExistingVerifyingSigners = new address[](1);
        alreadyExistingVerifyingSigners[0] = newVerifyingSigner;
        vm.expectRevert(
            abi.encodeWithSelector(SponsorPaymaster.VerifyingSignerAlreadyExists.selector, newVerifyingSigner)
        );
        sponsorPaymaster.addVerifyingSigners(alreadyExistingVerifyingSigners);
        vm.stopPrank();

        address[] memory actualVerifyingSigners = sponsorPaymaster.getAllSigners();
        assertEq(actualVerifyingSigners.length, 2);
    }

    function testRemoveVerifyingSigner() public {
        vm.startPrank(sponsorPaymaster.owner());
        address[] memory verifyingSigners = new address[](1);
        verifyingSigners[0] = verifyingSigner1;
        sponsorPaymaster.removeVerifyingSigners(verifyingSigners);
        vm.stopPrank();

        address[] memory actualVerifyingSigners = sponsorPaymaster.getAllSigners();
        assertEq(actualVerifyingSigners.length, 1);
    }

    function testRemoveVerifyingSigner_nonExist() public {
        vm.startPrank(sponsorPaymaster.owner());
        address[] memory nonExistingVerifyingSigners = new address[](1);
        uint256 nonExistingVerifyingSignersPrivateKey = 0x123;
        nonExistingVerifyingSigners[0] = vm.addr(nonExistingVerifyingSignersPrivateKey);
        vm.expectRevert(
            abi.encodeWithSelector(
                SponsorPaymaster.VerifyingSignerDoesNotExist.selector, nonExistingVerifyingSigners[0]
            )
        );
        sponsorPaymaster.removeVerifyingSigners(nonExistingVerifyingSigners);
        vm.stopPrank();

        address[] memory actualVerifyingSigners = sponsorPaymaster.getAllSigners();
        assertEq(actualVerifyingSigners.length, 2);
    }

    function testParsePaymasterAndData_validData() public view {
        bytes memory paymasterAndData = abi.encodePacked(
            address(sponsorPaymaster),
            MOCK_PAYMASTER_VERIFICATION_GAS_LIMIT,
            MOCK_PAYMASTER_POST_OP_GAS_LIMIT,
            abi.encode(MOCK_VALID_UNTIL, MOCK_VALID_AFTER),
            MOCK_OFFCHAIN_SIG
        );
        (
            uint128 paymasterVerificationGasLimit,
            uint128 paymasterPostOpGasLimit,
            uint48 validUntil,
            uint48 validAfter,
            bytes memory signature
        ) = sponsorPaymaster.parsePaymasterAndData(paymasterAndData);
        assertEq(paymasterVerificationGasLimit, MOCK_PAYMASTER_VERIFICATION_GAS_LIMIT);
        assertEq(paymasterPostOpGasLimit, MOCK_PAYMASTER_POST_OP_GAS_LIMIT);
        assertEq(validUntil, MOCK_VALID_UNTIL);
        assertEq(validAfter, MOCK_VALID_AFTER);
        assertEq(signature, MOCK_OFFCHAIN_SIG);
    }

    function testValidatePaymasterUserOp_invalidSig() public {
        address sender = vm.parseAddress("0x15Ba972e507B6c5acCBE50D6f4Ed899E6aaB8c19");
        PackedUserOperation memory userOp = buildPartialUserOp(
            sender,
            28,
            "0x",
            "0xb61d27f600000000000000000000000007865c6e87b9f70255377e024ace6630c1eaa37f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000044a9059cbb0000000000000000000000009005be081b8ec2a31258878409e88675cd79137600000000000000000000000000000000000000000000000000000000001e848000000000000000000000000000000000000000000000000000000000",
            83353,
            102865,
            45484,
            516219199704,
            1130000000,
            // fake
            "0xef6d11758ed59849431fa0995186371167ab70b9e3a07441b2936101464c1fd6c35a4504b955e033096f87960bacb2576dc8db3e0000000000000000000000000000000000000000000000000000000064d223990000000000000000000000000000000000000000000000000000000064398d193078313233343536"
        );

        bytes32 userOpHash = vm.parseBytes32("0x9ba9b6abf4c22ac5ff8353ef5e548cc71790a9cdf71fca735460615ae213acad");
        vm.startPrank(address(entryPoint));
        (bytes memory context, uint256 validationData) =
            sponsorPaymaster.validatePaymasterUserOp(userOp, userOpHash, 41216566026689742);
        // sigFailed
        uint256 expectedValidationData = _packValidationData(true, MOCK_VALID_UNTIL, MOCK_VALID_AFTER);
        assertEq(validationData, expectedValidationData);
        assertEq(context, vm.parseBytes("0x"));
        vm.stopPrank();
    }

    function testValidatePaymasterUserOp_validSigInvalidSigner() public {
        address sender = vm.parseAddress("0x15Ba972e507B6c5acCBE50D6f4Ed899E6aaB8c19");
        PackedUserOperation memory userOp = buildPartialUserOp(
            sender,
            28,
            "0x",
            "0xb61d27f600000000000000000000000007865c6e87b9f70255377e024ace6630c1eaa37f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000044a9059cbb0000000000000000000000009005be081b8ec2a31258878409e88675cd79137600000000000000000000000000000000000000000000000000000000001e848000000000000000000000000000000000000000000000000000000000",
            83353,
            102865,
            45484,
            516219199704,
            1130000000,
            // fake and overwritten later
            "0xef6d11758ed59849431fa0995186371167ab70b9e3a07441b2936101464c1fd6c35a4504b955e033096f87960bacb2576dc8db3e0000000000000000000000000000000000000000000000000000000064d223990000000000000000000000000000000000000000000000000000000064398d193078313233343536"
        );
        bytes32 paymasterHash = sponsorPaymaster.getHash(
            userOp,
            MOCK_PAYMASTER_VERIFICATION_GAS_LIMIT,
            MOCK_PAYMASTER_POST_OP_GAS_LIMIT,
            MOCK_VALID_UNTIL,
            MOCK_VALID_AFTER
        ).toEthSignedMessageHash();

        // invalid verifyingSigner signature
        uint256 invalidVerifyingSignerPrivateKey = 0x456;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(invalidVerifyingSignerPrivateKey, paymasterHash);
        bytes memory paymasterSig = abi.encodePacked(r, s, v);
        bytes memory actualPaymasterAndData = abi.encodePacked(
            address(sponsorPaymaster),
            MOCK_PAYMASTER_VERIFICATION_GAS_LIMIT,
            MOCK_PAYMASTER_POST_OP_GAS_LIMIT,
            abi.encode(MOCK_VALID_UNTIL, MOCK_VALID_AFTER),
            paymasterSig
        );
        userOp.paymasterAndData = actualPaymasterAndData;

        bytes32 userOpHash = vm.parseBytes32("0x958df3886f2f9889defaf96ce0d44e2dc5f91c0753d0569a776f9261cfc5be32");
        vm.startPrank(address(entryPoint));
        (bytes memory context, uint256 validationData) =
            sponsorPaymaster.validatePaymasterUserOp(userOp, userOpHash, 41216566026689742);
        // sigFailed
        uint256 expectedValidationData = _packValidationData(true, MOCK_VALID_UNTIL, MOCK_VALID_AFTER);
        assertEq(validationData, expectedValidationData);
        // no context is passed to postOp
        assertEq(context, vm.parseBytes("0x"));
        vm.stopPrank();
    }

    function testValidatePaymasterUserOp_validSig() public {
        address sender = vm.parseAddress("0x15Ba972e507B6c5acCBE50D6f4Ed899E6aaB8c19");
        PackedUserOperation memory userOp = buildPartialUserOp(
            sender,
            28,
            "0x",
            "0xb61d27f600000000000000000000000007865c6e87b9f70255377e024ace6630c1eaa37f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000044a9059cbb0000000000000000000000009005be081b8ec2a31258878409e88675cd79137600000000000000000000000000000000000000000000000000000000001e848000000000000000000000000000000000000000000000000000000000",
            83353,
            102865,
            45484,
            516219199704,
            1130000000,
            // fake and overwritten later
            "0xef6d11758ed59849431fa0995186371167ab70b9e3a07441b2936101464c1fd6c35a4504b955e033096f87960bacb2576dc8db3e0000000000000000000000000000000000000000000000000000000064d223990000000000000000000000000000000000000000000000000000000064398d193078313233343536"
        );
        bytes32 paymasterHash = sponsorPaymaster.getHash(
            userOp,
            MOCK_PAYMASTER_VERIFICATION_GAS_LIMIT,
            MOCK_PAYMASTER_POST_OP_GAS_LIMIT,
            MOCK_VALID_UNTIL,
            MOCK_VALID_AFTER
        ).toEthSignedMessageHash();

        // verifyingSigner1 signature
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(verifyingSigner1PrivateKey, paymasterHash);
        bytes memory paymasterSig = abi.encodePacked(r, s, v);
        bytes memory actualPaymasterAndData = abi.encodePacked(
            address(sponsorPaymaster),
            MOCK_PAYMASTER_VERIFICATION_GAS_LIMIT,
            MOCK_PAYMASTER_POST_OP_GAS_LIMIT,
            abi.encode(MOCK_VALID_UNTIL, MOCK_VALID_AFTER),
            paymasterSig
        );
        userOp.paymasterAndData = actualPaymasterAndData;

        bytes32 userOpHash = vm.parseBytes32("0x958df3886f2f9889defaf96ce0d44e2dc5f91c0753d0569a776f9261cfc5be32");
        vm.startPrank(address(entryPoint));
        (bytes memory context, uint256 validationData) =
            sponsorPaymaster.validatePaymasterUserOp(userOp, userOpHash, 41216566026689742);
        // sigPassed
        uint256 expectedValidationData = _packValidationData(false, MOCK_VALID_UNTIL, MOCK_VALID_AFTER);
        assertEq(validationData, expectedValidationData);
        // no context is passed to postOp
        assertEq(context, "");

        // verifyingSigner2 signature
        (v, r, s) = vm.sign(verifyingSigner2PrivateKey, paymasterHash);
        bytes memory actualPaymasterAndData2 = abi.encodePacked(
            address(sponsorPaymaster),
            MOCK_PAYMASTER_VERIFICATION_GAS_LIMIT,
            MOCK_PAYMASTER_POST_OP_GAS_LIMIT,
            abi.encode(MOCK_VALID_UNTIL, MOCK_VALID_AFTER),
            paymasterSig
        );
        userOp.paymasterAndData = actualPaymasterAndData2;
        (context, validationData) = sponsorPaymaster.validatePaymasterUserOp(userOp, userOpHash, 41216566026689742);
        // sigPassed
        expectedValidationData = _packValidationData(false, MOCK_VALID_UNTIL, MOCK_VALID_AFTER);
        assertEq(validationData, expectedValidationData);
        // no context is passed to postOp
        assertEq(context, "");

        // should fail if we run again with the same message due to replay protection
        userOp.nonce = 29; // 28 + 1
        (bytes memory context2ndRound, uint256 validationData2ndRound) =
            sponsorPaymaster.validatePaymasterUserOp(userOp, userOpHash, 41216566026689742);
        // sigFailed
        expectedValidationData = _packValidationData(true, MOCK_VALID_UNTIL, MOCK_VALID_AFTER);
        assertEq(validationData2ndRound, expectedValidationData);
        assertEq(context2ndRound, vm.parseBytes("0x"));
        vm.stopPrank();
    }

    function testPauseAndUnpauseContract() public {
        (address randomAddr) = makeAddr("randomAccount");
        vm.startPrank(randomAddr);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, randomAddr));
        sponsorPaymaster.pause();
        vm.stopPrank();

        vm.startPrank(sponsorPaymaster.owner());
        sponsorPaymaster.pause();
        assertEq(true, sponsorPaymaster.paused());
        // should fail if we pause the paused contract
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        sponsorPaymaster.pause();
        // try to call method in paused state
        address sender = vm.parseAddress("0x15Ba972e507B6c5acCBE50D6f4Ed899E6aaB8c19");
        PackedUserOperation memory userOp = buildPartialUserOp(
            sender,
            28,
            "0x",
            "0xb61d27f600000000000000000000000007865c6e87b9f70255377e024ace6630c1eaa37f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000044a9059cbb0000000000000000000000009005be081b8ec2a31258878409e88675cd79137600000000000000000000000000000000000000000000000000000000001e848000000000000000000000000000000000000000000000000000000000",
            83353,
            102865,
            45484,
            516219199704,
            1130000000,
            "0x79cbffe6dd3c3cb46aab6ef51f1a4accb5567f4e0000000000000000000000000000000000000000000000000000000064d223990000000000000000000000000000000000000000000000000000000064398d19"
        );
        bytes32 paymasterHash = sponsorPaymaster.getHash(
            userOp,
            MOCK_PAYMASTER_VERIFICATION_GAS_LIMIT,
            MOCK_PAYMASTER_POST_OP_GAS_LIMIT,
            MOCK_VALID_UNTIL,
            MOCK_VALID_AFTER
        ).toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(verifyingSigner1PrivateKey, paymasterHash);
        bytes memory paymasterSig = abi.encodePacked(r, s, v);
        bytes memory actualPaymasterAndData =
            abi.encodePacked(address(sponsorPaymaster), abi.encode(MOCK_VALID_UNTIL, MOCK_VALID_AFTER), paymasterSig);
        userOp.paymasterAndData = actualPaymasterAndData;
        bytes32 userOpHash = vm.parseBytes32("0x8FF4A88D25B1E70C6D23440F76CD1D0B0FCA957717B9B2084FDF2430653618DA");
        vm.startPrank(address(entryPoint));
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        // should fail because of paused contract
        sponsorPaymaster.validatePaymasterUserOp(userOp, userOpHash, 41216566026689742);
        // now unpause
        vm.startPrank(sponsorPaymaster.owner());
        sponsorPaymaster.unpause();
        assertEq(false, sponsorPaymaster.paused());
        vm.stopPrank();
    }

    /// entry point is updated
    function testUpgradeToNewEntryPoint() public {
        address ownerAddr = vm.addr(111);
        IEntryPoint newEntryPoint = IEntryPoint(address(vm.addr(999)));
        SponsorPaymaster v2Impl = new SponsorPaymaster(newEntryPoint);
        address v2ImplAddr = address(v2Impl);
        // only upgradable through owner
        vm.startPrank(ownerAddr);
        // verify Upgraded event
        vm.expectEmit(true, false, false, false);
        emit Upgraded(v2ImplAddr);
        sponsorPaymaster.upgradeToAndCall(v2ImplAddr, "");
        vm.stopPrank();
    }

    function testReceive() public {
        (address randomAddr) = makeAddr("randomAccount");
        uint256 amountToSend = 1 ether;

        vm.startPrank(randomAddr);
        vm.deal(randomAddr, amountToSend);
        (bool sent,) = address(sponsorPaymaster).call{value: amountToSend}("");
        assertEq(true, sent);
        vm.stopPrank();
        assertEq(sponsorPaymaster.getDeposit(), amountToSend);

        vm.startPrank(sponsorPaymaster.owner());
        sponsorPaymaster.pause();
        vm.stopPrank();
        vm.startPrank(randomAddr);
        vm.deal(randomAddr, 1 ether);
        // should not be able to send ether when paused
        vm.expectRevert("Failed to send Ether");
        (sent,) = address(sponsorPaymaster).call{value: 1 ether}("");
        assertEq(false, sent);
        vm.stopPrank();
    }
}
