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
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {console} from "forge-std/src/console.sol";
import {TestUtils} from "../util/TestUtils.sol";

abstract contract PluginGasProfileBaseTest is TestUtils {
    uint256 constant OV_PER_ZERO_BYTE = 4;
    uint256 constant OV_PER_NONZERO_BYTE = 16;
    IEntryPoint public entryPoint = new EntryPoint();
    address payable public beneficiary = payable(address(makeAddr("bundler")));
    string jsonObj;
    uint256 sum;
    bool public writeGasProfileToFile;

    function testBenchmarkAll() external virtual;

    function testBenchmarkPluginInstall() internal virtual;

    function testBenchmarkPluginUninstall() internal virtual;

    function buildPartialUserOp(address sender, uint256 nonce, string memory callData)
        public
        pure
        returns (PackedUserOperation memory userOp)
    {
        userOp.sender = sender;
        userOp.nonce = nonce;
        userOp.initCode = vm.parseBytes("0x");
        userOp.callData = vm.parseBytes(callData);
        userOp.accountGasLimits = bytes32(abi.encodePacked(uint128(1500000), uint128(1000000)));
        userOp.preVerificationGas = 21000;
        userOp.gasFees = bytes32(abi.encodePacked(uint128(1), uint128(1)));
        userOp.paymasterAndData = vm.parseBytes("0x");
    }

    function setUp() public virtual {
        writeGasProfileToFile = vm.envOr("WRITE_GAS_PROFILE_TO_FILE", false);
    }

    function writeTestResult(string memory accountAndPluginType) internal {
        string memory res = vm.serializeUint(jsonObj, "ffff_sum", sum);
        if (writeGasProfileToFile) {
            vm.writeJson(res, string.concat("./gas/results/", accountAndPluginType, ".json"));
        } else {
            console.log("case - %s", accountAndPluginType);
            console.log(res);
        }
    }

    function executeUserOp(address msca, PackedUserOperation memory op, string memory testName, uint256 value)
        internal
    {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        uint256 ethBefore = entryPoint.balanceOf(msca) + msca.balance;
        entryPoint.handleOps(ops, beneficiary);
        uint256 ethAfter = entryPoint.balanceOf(msca) + msca.balance + value;
        uint256 gasUsed = ethBefore - ethAfter;
        console.log("case - %s", testName);
        console.log("  gasUsed       : ", gasUsed);
        console.log("  calldatacost  : ", calldataCost(pack(op)));
        vm.serializeUint(jsonObj, testName, gasUsed);
        sum += gasUsed;
    }

    function pack(PackedUserOperation memory _op) internal pure returns (bytes memory) {
        bytes memory packed = abi.encode(
            _op.sender,
            _op.nonce,
            _op.initCode,
            _op.callData,
            _op.accountGasLimits,
            _op.preVerificationGas,
            _op.gasFees,
            _op.paymasterAndData,
            _op.signature
        );
        return packed;
    }

    function calldataCost(bytes memory packed) internal pure returns (uint256) {
        uint256 cost = 0;
        for (uint256 i = 0; i < packed.length; i++) {
            if (packed[i] == 0) {
                cost += OV_PER_ZERO_BYTE;
            } else {
                cost += OV_PER_NONZERO_BYTE;
            }
        }
        return cost;
    }
}
