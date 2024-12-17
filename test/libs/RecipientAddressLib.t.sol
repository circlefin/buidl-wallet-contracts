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

import {RecipientAddressLib} from "../../src/libs/RecipientAddressLib.sol";
import {TestERC1155} from "../util/TestERC1155.sol";
import {TestERC721} from "../util/TestERC721.sol";
import {TestLiquidityPool} from "../util/TestLiquidityPool.sol";
import {TestUtils} from "../util/TestUtils.sol";

import {RecipientAddressLibWrapper} from "./RecipientAddressLibWrapper.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {console} from "forge-std/src/console.sol";

contract RecipientAddressLibTest is TestUtils {
    bytes4 internal constant ERC20_INCREASE_ALLOWANCE = bytes4(keccak256("increaseAllowance(address,uint256)"));
    bytes4 internal constant ERC20_DECREASE_ALLOWANCE = bytes4(keccak256("decreaseAllowance(address,uint256)"));

    // upgrade
    event Upgraded(address indexed newImplementation);
    // erc721
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    // erc1155
    event TransferSingle(address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value);
    event TransferBatch(
        address indexed operator, address indexed from, address indexed to, uint256[] ids, uint256[] values
    );
    event ApprovalForAll(address indexed _owner, address indexed _operator, bool _approved);
    // 4337
    event UserOperationEvent(
        bytes32 indexed userOpHash,
        address indexed sender,
        address indexed paymaster,
        uint256 nonce,
        bool success,
        uint256 actualGasCost,
        uint256 actualGasUsed
    );

    error FailedOp(uint256 opIndex, string reason);

    event UserOperationRevertReason(
        bytes32 indexed userOpHash, address indexed sender, uint256 nonce, bytes revertReason
    );

    // MSCA
    error WalletStorageIsInitialized();

    IEntryPoint private entryPoint = new EntryPoint();
    address payable private beneficiary; // e.g. bundler
    TestERC1155 private testERC1155;
    TestERC721 private testERC721;
    TestLiquidityPool private testERC20;
    RecipientAddressLibWrapper private recipientAddressLib = new RecipientAddressLibWrapper();

    function setUp() public {
        beneficiary = payable(address(makeAddr("bundler")));
        testERC1155 = new TestERC1155("1155");
        testERC721 = new TestERC721("721", "$$$");
        testERC20 = new TestLiquidityPool("20", "$$$");
    }

    function testFuzz_getERC20TokenRecipientForTransfer(address expectedRecipient, uint256 amount) public view {
        bytes memory data = abi.encodeCall(testERC20.transfer, (expectedRecipient, amount));
        address recipient = recipientAddressLib.getERC20TokenRecipient(data);
        assertEq(recipient, expectedRecipient);
    }

    function testFuzz_getERC20TokenRecipientForApprove(address expectedRecipient, uint256 amount) public view {
        bytes memory data = abi.encodeCall(testERC20.approve, (expectedRecipient, amount));
        address recipient = recipientAddressLib.getERC20TokenRecipient(data);
        assertEq(recipient, expectedRecipient);
    }

    function testFuzz_getERC20TokenRecipientForTransferFrom(address expectedRecipient, address from, uint256 amount)
        public
        view
    {
        bytes memory data = abi.encodeCall(testERC20.transferFrom, (from, expectedRecipient, amount));
        address recipient = recipientAddressLib.getERC20TokenRecipient(data);
        assertEq(recipient, expectedRecipient);
    }

    function testFuzz_getERC20TokenRecipientForIncreaseAllowance(address expectedRecipient, uint256 amount)
        public
        view
    {
        bytes memory data = abi.encodeWithSelector(ERC20_INCREASE_ALLOWANCE, expectedRecipient, amount);
        address recipient = recipientAddressLib.getERC20TokenRecipient(data);
        assertEq(recipient, expectedRecipient);
    }

    function testFuzz_getERC20TokenRecipientForDecreaseAllowance(address expectedRecipient, uint256 amount)
        public
        view
    {
        bytes memory data = abi.encodeWithSelector(ERC20_DECREASE_ALLOWANCE, expectedRecipient, amount);
        address recipient = recipientAddressLib.getERC20TokenRecipient(data);
        assertEq(recipient, expectedRecipient);
    }

    function testFuzz_getERC20TokenRecipientForUnknownSelector(address expectedRecipient, uint256 amount) public view {
        bytes memory data = abi.encodeCall(testERC20.mint, (expectedRecipient, amount));
        address recipient = recipientAddressLib.getERC20TokenRecipient(data);
        assertEq(recipient, address(0));
    }

    function testFuzz_getERC1155TokenRecipientForSafeApproval(address expectedRecipient, bool approved) public view {
        bytes memory data = abi.encodeCall(testERC1155.setApprovalForAll, (expectedRecipient, approved));
        address recipient = recipientAddressLib.getERC1155TokenRecipient(data);
        assertEq(recipient, expectedRecipient);
    }

    function testFuzz_getERC1155TokenRecipientForSafeTransferFrom(
        address expectedRecipient,
        address from,
        uint256 tokenId,
        uint256 amount,
        bytes memory callData
    ) public view {
        bytes memory data =
            abi.encodeCall(testERC1155.safeTransferFrom, (from, expectedRecipient, tokenId, amount, callData));
        address recipient = recipientAddressLib.getERC1155TokenRecipient(data);
        assertEq(recipient, expectedRecipient);
    }

    function testFuzz_getERC1155TokenRecipientForSafeBatchTransferFrom(
        address expectedRecipient,
        address from,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory callData
    ) public view {
        bytes memory data =
            abi.encodeCall(testERC1155.safeBatchTransferFrom, (from, expectedRecipient, ids, amounts, callData));
        address recipient = recipientAddressLib.getERC1155TokenRecipient(data);
        assertEq(recipient, expectedRecipient);
    }

    function testFuzz_getERC1155TokenRecipientForUnknownSelector(
        address expectedRecipient,
        uint256 tokenId,
        uint256 amount,
        bytes memory callData
    ) public view {
        bytes memory data = abi.encodeCall(testERC1155.mint, (expectedRecipient, tokenId, amount, callData));
        address recipient = recipientAddressLib.getERC1155TokenRecipient(data);
        assertEq(recipient, address(0));
    }

    function testFuzz_getERC721TokenRecipientForSafeApproval(address expectedRecipient, bool approved) public view {
        bytes memory data = abi.encodeCall(testERC721.setApprovalForAll, (expectedRecipient, approved));
        address recipient = recipientAddressLib.getERC721TokenRecipient(data);
        assertEq(recipient, expectedRecipient);
    }

    function testFuzz_getERC721TokenRecipientForApproval(address expectedRecipient, uint256 tokenId) public view {
        bytes memory data = abi.encodeCall(testERC721.approve, (expectedRecipient, tokenId));
        address recipient = recipientAddressLib.getERC721TokenRecipient(data);
        assertEq(recipient, expectedRecipient);
    }

    function testFuzz_getERC721TokenRecipientForSafeTransferFrom(
        address expectedRecipient,
        address from,
        uint256 tokenId
    ) public view {
        bytes memory data =
            abi.encodeWithSignature("safeTransferFrom(address,address,uint256)", from, expectedRecipient, tokenId);
        address recipient = recipientAddressLib.getERC721TokenRecipient(data);
        assertEq(recipient, expectedRecipient);

        data = abi.encodeCall(testERC721.transferFrom, (from, expectedRecipient, tokenId));
        recipient = recipientAddressLib.getERC721TokenRecipient(data);
        assertEq(recipient, expectedRecipient);
    }

    function testFuzz_getERC721TokenRecipientForSafeTransferFromWithBytes(
        address expectedRecipient,
        address from,
        uint256 tokenId,
        bytes memory callData
    ) public view {
        bytes memory data = abi.encodeWithSignature(
            "safeTransferFrom(address,address,uint256,bytes)", from, expectedRecipient, tokenId, callData
        );
        address recipient = recipientAddressLib.getERC721TokenRecipient(data);
        assertEq(recipient, expectedRecipient);
    }

    function testFuzz_getERC721TokenRecipientForUnknownSelector(address expectedRecipient, uint256 tokenId)
        public
        view
    {
        bytes memory data = abi.encodeWithSignature("safeMint(address,uint256)", expectedRecipient, tokenId);
        address recipient = recipientAddressLib.getERC721TokenRecipient(data);
        assertEq(recipient, address(0));
    }

    function testFuzz_getERC20TokenRecipientForTransferWithRandomBytes(bytes memory randomBytes) public view {
        // 4 accounts for function selector
        vm.assume(randomBytes.length < (RecipientAddressLib.TRANSFER_OR_APPROVE_MIN_LEN - 4) && randomBytes.length > 0);
        bytes memory data = abi.encodePacked(testERC20.transfer.selector, randomBytes);
        address recipient = recipientAddressLib.getERC20TokenRecipient(data);
        assertEq(recipient, address(0));
    }

    function testFuzz_getERC20TokenRecipientForApproveWithRandomBytes(bytes memory randomBytes) public view {
        // 4 accounts for function selector
        vm.assume(randomBytes.length < (RecipientAddressLib.TRANSFER_OR_APPROVE_MIN_LEN - 4) && randomBytes.length > 0);
        bytes memory data = abi.encodePacked(testERC20.approve.selector, randomBytes);
        address recipient = recipientAddressLib.getERC20TokenRecipient(data);
        assertEq(recipient, address(0));
    }

    function testFuzz_getERC20TokenRecipientForIncreaseAllowanceWithRandomBytes(bytes memory randomBytes) public view {
        // 4 accounts for function selector
        vm.assume(randomBytes.length < (RecipientAddressLib.TRANSFER_OR_APPROVE_MIN_LEN - 4) && randomBytes.length > 0);
        bytes memory data = abi.encodePacked(ERC20_INCREASE_ALLOWANCE, randomBytes);
        address recipient = recipientAddressLib.getERC20TokenRecipient(data);
        assertEq(recipient, address(0));
    }

    function testFuzz_getERC20TokenRecipientForDecreaseAllowanceWithRandomBytes(bytes memory randomBytes) public view {
        // 4 accounts for function selector
        vm.assume(randomBytes.length < (RecipientAddressLib.TRANSFER_OR_APPROVE_MIN_LEN - 4) && randomBytes.length > 0);
        bytes memory data = abi.encodePacked(ERC20_DECREASE_ALLOWANCE, randomBytes);
        address recipient = recipientAddressLib.getERC20TokenRecipient(data);
        assertEq(recipient, address(0));
    }

    function testFuzz_getERC20TokenRecipientForTransferFromWithRandomBytes(bytes memory randomBytes) public view {
        // 4 accounts for function selector
        vm.assume(randomBytes.length < (RecipientAddressLib.TRANSFER_FROM_MIN_LEN - 4) && randomBytes.length > 0);
        bytes memory data = abi.encodePacked(testERC20.transferFrom.selector, randomBytes);
        address recipient = recipientAddressLib.getERC20TokenRecipient(data);
        assertEq(recipient, address(0));
    }

    function testFuzz_getERC1155TokenRecipientForSafeApprovalWithRandomBytes(bytes memory randomBytes) public view {
        // 4 accounts for function selector
        vm.assume(randomBytes.length < (RecipientAddressLib.TRANSFER_OR_APPROVE_MIN_LEN - 4) && randomBytes.length > 0);
        bytes memory data = abi.encodePacked(testERC1155.setApprovalForAll.selector, randomBytes);
        address recipient = recipientAddressLib.getERC1155TokenRecipient(data);
        assertEq(recipient, address(0));
    }

    function testFuzz_getERC1155TokenRecipientForSafeTransferFromWithRandomBytes(bytes memory randomBytes)
        public
        view
    {
        // 4 accounts for function selector
        vm.assume(
            randomBytes.length < (RecipientAddressLib.TRANSFER_FROM_WITH_BYTES_MIN_LEN - 4) && randomBytes.length > 0
        );
        bytes memory data = abi.encodePacked(testERC1155.safeTransferFrom.selector, randomBytes);
        address recipient = recipientAddressLib.getERC1155TokenRecipient(data);
        assertEq(recipient, address(0));
    }

    function testFuzz_getERC1155TokenRecipientForSafeBatchTransferFromWithRandomBytes(bytes memory randomBytes)
        public
        view
    {
        // 4 accounts for function selector
        vm.assume(
            randomBytes.length < (RecipientAddressLib.BATCH_TRANSFER_FROM_WITH_BYTES_MIN_LEN - 4)
                && randomBytes.length > 0
        );
        bytes memory data = abi.encodePacked(testERC1155.safeBatchTransferFrom.selector, randomBytes);
        address recipient = recipientAddressLib.getERC1155TokenRecipient(data);
        assertEq(recipient, address(0));
    }

    function testFuzz_getERC721TokenRecipientForSafeApprovalWithRandomBytes(bytes memory randomBytes) public view {
        // 4 accounts for function selector
        vm.assume(randomBytes.length < (RecipientAddressLib.TRANSFER_OR_APPROVE_MIN_LEN - 4) && randomBytes.length > 0);
        bytes memory data = abi.encodePacked(testERC721.setApprovalForAll.selector, randomBytes);
        address recipient = recipientAddressLib.getERC721TokenRecipient(data);
        assertEq(recipient, address(0));
    }

    function testFuzz_getERC721TokenRecipientForApprovalWithRandomBytes(bytes memory randomBytes) public view {
        // 4 accounts for function selector
        vm.assume(randomBytes.length < (RecipientAddressLib.TRANSFER_OR_APPROVE_MIN_LEN - 4) && randomBytes.length > 0);
        bytes memory data = abi.encodePacked(testERC721.approve.selector, randomBytes);
        address recipient = recipientAddressLib.getERC721TokenRecipient(data);
        assertEq(recipient, address(0));
    }

    function testFuzz_getERC721TokenRecipientForSafeTransferFrom1WithRandomBytes(bytes memory randomBytes)
        public
        view
    {
        // 4 accounts for function selector
        vm.assume(randomBytes.length < (RecipientAddressLib.TRANSFER_FROM_MIN_LEN - 4) && randomBytes.length > 0);
        bytes memory data =
            abi.encodePacked(bytes4(keccak256("safeTransferFrom(address,address,uint256)")), randomBytes);
        address recipient = recipientAddressLib.getERC721TokenRecipient(data);
        assertEq(recipient, address(0));

        data = abi.encodePacked(testERC721.transferFrom.selector, randomBytes);
        recipient = recipientAddressLib.getERC721TokenRecipient(data);
        assertEq(recipient, address(0));
    }

    function testFuzz_getERC721TokenRecipientForSafeTransferFrom2WithRandomBytes(bytes memory randomBytes)
        public
        view
    {
        // 4 accounts for function selector
        vm.assume(
            randomBytes.length < (RecipientAddressLib.TRANSFER_FROM_WITHOUT_AMOUNT_WITH_BYTES_MIN_LEN - 4)
                && randomBytes.length > 0
        );
        bytes memory data =
            abi.encodePacked(bytes4(keccak256("safeTransferFrom(address,address,uint256,bytes)")), randomBytes);
        address recipient = recipientAddressLib.getERC721TokenRecipient(data);
        assertEq(recipient, address(0));
    }

    function testMinLengthsForERC20() public view {
        address expectedRecipient = vm.addr(123);
        uint256 amount = 1;
        address from = vm.addr(456);

        bytes memory data = abi.encodeCall(testERC20.transfer, (expectedRecipient, amount));
        console.log("ERC20.transfer MIN LEN", data.length);
        assertEq(data.length, RecipientAddressLib.TRANSFER_OR_APPROVE_MIN_LEN);

        data = abi.encodeCall(testERC20.approve, (expectedRecipient, amount));
        console.log("ERC20.approve MIN LEN", data.length);
        assertEq(data.length, RecipientAddressLib.TRANSFER_OR_APPROVE_MIN_LEN);

        data = abi.encodeCall(testERC20.transferFrom, (from, expectedRecipient, amount));
        console.log("ERC20.transferFrom MIN LEN", data.length);
        assertEq(data.length, RecipientAddressLib.TRANSFER_FROM_MIN_LEN);
    }

    function testMinLengthsForERC721() public view {
        address expectedRecipient = vm.addr(123);
        address from = vm.addr(456);
        uint256 tokenId = 0;
        bool approved;

        bytes memory data = abi.encodeCall(testERC721.setApprovalForAll, (expectedRecipient, approved));
        console.log("ERC721.setApprovalForAll MIN LEN", data.length);
        assertEq(data.length, RecipientAddressLib.TRANSFER_OR_APPROVE_MIN_LEN);

        data = abi.encodeCall(testERC721.approve, (expectedRecipient, tokenId));
        console.log("ERC721.approve MIN LEN", data.length);
        assertEq(data.length, RecipientAddressLib.TRANSFER_OR_APPROVE_MIN_LEN);

        data = abi.encodeCall(testERC721.transferFrom, (from, expectedRecipient, tokenId));
        console.log("ERC721.transferFrom MIN LEN", data.length);
        assertEq(data.length, RecipientAddressLib.TRANSFER_FROM_MIN_LEN);
    }

    function testMinLengthsForERC1155() public view {
        address expectedRecipient = vm.addr(123);
        uint256 amount = 1;
        address from = vm.addr(456);
        uint256 tokenId = 0;
        uint256[] memory ids;
        uint256[] memory amounts;
        bytes memory callData;
        bool approved;

        bytes memory data = abi.encodeCall(testERC1155.setApprovalForAll, (expectedRecipient, approved));
        console.log("ERC1155.setApprovalForAll MIN LEN", data.length);
        assertEq(data.length, RecipientAddressLib.TRANSFER_OR_APPROVE_MIN_LEN);

        data = abi.encodeCall(testERC1155.safeTransferFrom, (from, expectedRecipient, tokenId, amount, callData));
        console.log("ERC1155.safeTransferFrom MIN LEN", data.length);
        assertEq(data.length, RecipientAddressLib.TRANSFER_FROM_WITH_BYTES_MIN_LEN);

        data = abi.encodeCall(testERC1155.safeBatchTransferFrom, (from, expectedRecipient, ids, amounts, callData));
        console.log("ERC1155.safeBatchTransferFrom MIN LEN", data.length);
        assertEq(data.length, RecipientAddressLib.BATCH_TRANSFER_FROM_WITH_BYTES_MIN_LEN);
    }

    function testMinLengthsForSafeTransferFrom() public pure {
        address expectedRecipient = vm.addr(123);
        address from = vm.addr(456);
        uint256 tokenId = 0;
        bytes memory callData;

        bytes memory data =
            abi.encodeWithSignature("safeTransferFrom(address,address,uint256)", from, expectedRecipient, tokenId);
        console.log("safeTransferFrom(address,address,uint256) MIN LEN", data.length);
        assertEq(data.length, RecipientAddressLib.TRANSFER_FROM_MIN_LEN);

        data = abi.encodeWithSignature(
            "safeTransferFrom(address,address,uint256,bytes)", from, expectedRecipient, tokenId, callData
        );
        console.log("safeTransferFrom(address,address,uint256,bytes) MIN LEN", data.length);
        assertEq(data.length, RecipientAddressLib.TRANSFER_FROM_WITHOUT_AMOUNT_WITH_BYTES_MIN_LEN);
    }
}
