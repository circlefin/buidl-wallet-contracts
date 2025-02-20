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

import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

import {FCL_Elliptic_ZZ} from "@fcl/FCL_elliptic.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Test} from "forge-std/src/Test.sol";
import {Vm} from "forge-std/src/Vm.sol";

contract TestUtils is Test {
    using MessageHashUtils for bytes32;

    /// @dev Secp256r1 curve order / 2 used as guard to prevent signature malleability issue.
    uint256 internal constant _P256_N_DIV_2 = FCL_Elliptic_ZZ.n / 2;

    function buildPartialUserOp(
        address sender,
        uint256 nonce,
        string memory initCode,
        string memory callData,
        uint256 callGasLimit,
        uint256 verificationGasLimit,
        uint256 preVerificationGas,
        uint256 maxFeePerGas,
        uint256 maxPriorityFeePerGas,
        string memory paymasterAndData
    ) public pure returns (PackedUserOperation memory userOp) {
        userOp.sender = sender;
        userOp.nonce = nonce;
        userOp.initCode = vm.parseBytes(initCode);
        userOp.callData = vm.parseBytes(callData);
        userOp.accountGasLimits = bytes32(abi.encodePacked(uint128(verificationGasLimit), uint128(callGasLimit)));
        userOp.preVerificationGas = preVerificationGas;
        userOp.gasFees = bytes32(abi.encodePacked(uint128(maxPriorityFeePerGas), uint128(maxFeePerGas)));
        userOp.paymasterAndData = vm.parseBytes(paymasterAndData);
    }

    // userOp.signature
    function signUserOpHash(IEntryPoint entryPoint, Vm vm, uint256 key, PackedUserOperation memory userOp)
        public
        view
        returns (bytes memory signature)
    {
        bytes32 hash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, hash.toEthSignedMessageHash());
        signature = abi.encodePacked(r, s, v);
    }

    function signMessage(Vm vm, uint256 key, bytes32 hash) public pure returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, hash);
        signature = abi.encodePacked(r, s, v);
    }

    function signP256Message(Vm vm, uint256 key, bytes32 hash) public pure returns (uint256 r, uint256 s) {
        (bytes32 br, bytes32 bs) = vm.signP256(key, hash);
        r = uint256(br);
        s = uint256(bs);
        if (s > _P256_N_DIV_2) {
            s = FCL_Elliptic_ZZ.n - s;
        }
    }

    function addressToBytes32(address addr) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(addr)));
    }

    function _encodeGasLimit(uint256 gasLimit) internal pure returns (bytes32) {
        return bytes32(uint256(gasLimit));
    }

    function _encodeGasFees(uint128 maxFeePerGas, uint128 maxPriorityFeePerGas) internal pure returns (bytes32) {
        return bytes32(uint256(maxPriorityFeePerGas) << 128 | uint256(maxFeePerGas));
    }

    // I was trying to use this lib to generate public key but getting "Yul exception:Cannot swap Variable expr_16 with
    // Variable expr_mpos_8: too deep in the stack by 6 slots in"
    // need to investigate this a bit further
    //    function derivePublicKey(uint256 privateKey) public view returns (uint256, uint256) {
    //        return FCL_ecdsa_utils.ecdsa_derivKpub(privateKey);
    //    }
}
