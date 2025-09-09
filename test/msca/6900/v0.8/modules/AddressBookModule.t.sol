/*
 * Copyright 2024 Circle Internet Group, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
pragma solidity 0.8.24;

import {SIG_VALIDATION_SUCCEEDED} from "../../../../../src/common/Constants.sol";
import {Unsupported} from "../../../../../src/common/Errors.sol";
import {UnexpectedDataPassed} from "../../../../../src/msca/6900/shared/common/Errors.sol";

import {Call} from "../../../../../src/msca/6900/v0.8/common/Structs.sol";
import {AddressBookModule} from "../../../../../src/msca/6900/v0.8/modules/addressbook/AddressBookModule.sol";
import {IAddressBookModule} from "../../../../../src/msca/6900/v0.8/modules/addressbook/IAddressBookModule.sol";

import {TestERC1155} from "../../../../util/TestERC1155.sol";
import {TestERC721} from "../../../../util/TestERC721.sol";
import {TestLiquidityPool} from "../../../../util/TestLiquidityPool.sol";
import {TestUtils} from "../../../../util/TestUtils.sol";

import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

import {IExecutionModule} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {ExecutionManifest} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";

import {IERC1155} from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

contract AddressBookModuleTest is TestUtils {
    AddressBookModule private addressBookModule;
    TestERC1155 private testERC1155;
    TestERC721 private testERC721;
    TestLiquidityPool private testERC20;
    TestLiquidityPool private testERC20_2;

    address private account1;
    address private account2;
    address private recipient1;
    address private recipient2;
    address private recipient3;

    // Events from IAddressBookModule
    event AllowedAddressesAdded(address indexed account, address[] recipients);
    event AllowedAddressesRemoved(address indexed account, address[] recipients);
    event AllowedAddressesNotRemoved(address indexed account);

    function setUp() public {
        addressBookModule = new AddressBookModule();
        testERC1155 = new TestERC1155("Test1155");
        testERC721 = new TestERC721("Test721", "T721");
        testERC20 = new TestLiquidityPool("TestERC20", "T20");
        testERC20_2 = new TestLiquidityPool("TestERC20_2", "T20_2");

        account1 = makeAddr("account1");
        account2 = makeAddr("account2");
        recipient1 = makeAddr("recipient1");
        recipient2 = makeAddr("recipient2");
        recipient3 = makeAddr("recipient3");

        // Deploy some test token contracts
        vm.deal(address(testERC20), 1 ether);
        vm.deal(address(testERC721), 1 ether);
        vm.deal(address(testERC1155), 1 ether);
        vm.deal(recipient1, 1 ether);
        vm.deal(recipient2, 1 ether);
        vm.deal(recipient3, 1 ether);
    }

    // ==================== Basic Functionality Tests ====================

    function test_addAllowedRecipients_Success() public {
        address[] memory recipients = new address[](3);
        recipients[0] = recipient1;
        recipients[1] = recipient2;
        recipients[2] = recipient3;

        vm.prank(account1);
        vm.expectEmit(true, false, false, true);
        emit AllowedAddressesAdded(account1, recipients);
        addressBookModule.addAllowedRecipients(recipients);

        address[] memory allowedRecipients = addressBookModule.getAllowedRecipients(account1);
        assertEq(allowedRecipients.length, 3);
        // the order of the recipients is in reverse (linked list set is ordered LIFO)
        assertEq(allowedRecipients[2], recipient1);
        assertEq(allowedRecipients[1], recipient2);
        assertEq(allowedRecipients[0], recipient3);
    }

    function test_addZeroAddressRecipient() public {
        address[] memory recipients = new address[](1);
        recipients[0] = address(0);
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.FailToAddRecipient.selector, account1, address(0)));
        addressBookModule.addAllowedRecipients(recipients);
    }

    function test_addAllowedRecipients_EmptyArray() public {
        address[] memory recipients = new address[](0);

        vm.prank(account1);
        vm.expectEmit(true, false, false, true);
        emit AllowedAddressesAdded(account1, recipients);
        addressBookModule.addAllowedRecipients(recipients);

        address[] memory allowedRecipients = addressBookModule.getAllowedRecipients(account1);
        assertEq(allowedRecipients.length, 0);
    }

    function test_addAllowedRecipients_DuplicateRecipient() public {
        address[] memory recipients = new address[](1);
        recipients[0] = recipient1;

        // Add recipient first time
        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Try to add same recipient again - should revert
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.FailToAddRecipient.selector, account1, recipient1));
        addressBookModule.addAllowedRecipients(recipients);
    }

    function test_removeAllowedRecipients_Success() public {
        // First add recipients
        address[] memory recipients = new address[](2);
        recipients[0] = recipient1;
        recipients[1] = recipient2;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Remove one recipient
        address[] memory toRemove = new address[](1);
        toRemove[0] = recipient1;

        vm.prank(account1);
        vm.expectEmit(true, false, false, true);
        emit AllowedAddressesRemoved(account1, toRemove);
        addressBookModule.removeAllowedRecipients(toRemove);

        address[] memory allowedRecipients = addressBookModule.getAllowedRecipients(account1);
        assertEq(allowedRecipients.length, 1);
        assertEq(allowedRecipients[0], recipient2);
    }

    function test_removeAllowedRecipients_NonExistentRecipient() public {
        address[] memory recipients = new address[](1);
        recipients[0] = recipient1;

        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.FailToRemoveRecipient.selector, account1, recipient1));
        addressBookModule.removeAllowedRecipients(recipients);
    }

    function test_getAllowedRecipients_MultipleAccounts() public {
        address[] memory recipients1 = new address[](1);
        recipients1[0] = recipient1;

        address[] memory recipients2 = new address[](1);
        recipients2[0] = recipient2;

        // Add recipients for account1
        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients1);

        // Add recipients for account2
        vm.prank(account2);
        addressBookModule.addAllowedRecipients(recipients2);

        // Check each account has their own recipients
        address[] memory account1Recipients = addressBookModule.getAllowedRecipients(account1);
        address[] memory account2Recipients = addressBookModule.getAllowedRecipients(account2);

        assertEq(account1Recipients.length, 1);
        assertEq(account1Recipients[0], recipient1);

        assertEq(account2Recipients.length, 1);
        assertEq(account2Recipients[0], recipient2);
    }

    // ==================== Module Lifecycle Tests ====================

    function test_onInstall_WithRecipients() public {
        address[] memory recipients = new address[](2);
        recipients[0] = recipient1;
        recipients[1] = recipient2;

        bytes memory installData = abi.encode(recipients);

        vm.prank(account1);
        vm.expectEmit(true, false, false, true);
        emit AllowedAddressesAdded(account1, recipients);
        addressBookModule.onInstall(installData);

        address[] memory allowedRecipients = addressBookModule.getAllowedRecipients(account1);
        assertEq(allowedRecipients.length, 2);
        // the order of the recipients is in reverse (linked list set is ordered LIFO)
        assertEq(allowedRecipients[1], recipient1);
        assertEq(allowedRecipients[0], recipient2);
    }

    function test_onInstall_WithoutRecipients() public {
        bytes memory installData = "";

        vm.prank(account1);
        // Should not emit any events
        addressBookModule.onInstall(installData);

        address[] memory allowedRecipients = addressBookModule.getAllowedRecipients(account1);
        assertEq(allowedRecipients.length, 0);
    }

    function test_onUninstall_FewRecipients() public {
        // Add a few recipients (less than MAX_RECIPIENTS_TO_DELETE)
        address[] memory recipients = new address[](3);
        recipients[0] = recipient1;
        recipients[1] = recipient2;
        recipients[2] = recipient3;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Get the actual order that will be returned (LIFO order)
        address[] memory actualOrder = addressBookModule.getAllowedRecipients(account1);

        // Uninstall should clear all recipients
        vm.prank(account1);
        vm.expectEmit(true, false, false, true);
        emit AllowedAddressesRemoved(account1, actualOrder);
        addressBookModule.onUninstall("");

        address[] memory allowedRecipients = addressBookModule.getAllowedRecipients(account1);
        assertEq(allowedRecipients.length, 0);
    }

    // ==================== Token Validation Tests ====================

    function test_verifyAllowedTargetOrRecipient_ERC20_Methods_Allowed() public {
        // Add recipient to allowlist
        address[] memory recipients = new address[](1);
        recipients[0] = recipient1;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Create ERC20 transfer calldata
        bytes memory transferData = abi.encodeCall(IERC20.transfer, (recipient1, 100));
        bytes memory executeTransferData = abi.encode(address(testERC20), 0, transferData);
        vm.prank(account1);
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeTransferData);

        // Create ERC20 transferFrom calldata
        bytes memory transferFromData = abi.encodeCall(IERC20.transferFrom, (account1, recipient1, 100));
        bytes memory executeTransferFromData = abi.encode(address(testERC20), 0, transferFromData);
        vm.prank(account1);
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeTransferFromData);

        // Create ERC20 approve calldata
        bytes memory approveData = abi.encodeCall(IERC20.approve, (recipient1, 100));
        bytes memory executeApproveData = abi.encode(address(testERC20), 0, approveData);
        vm.prank(account1);
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeApproveData);

        // Create ERC20 increaseAllowance calldata
        bytes memory increaseAllowanceData =
            abi.encodeWithSignature("increaseAllowance(address,uint256)", recipient1, 100);
        bytes memory executeIncreaseAllowanceData = abi.encode(address(testERC20), 0, increaseAllowanceData);
        vm.prank(account1);
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeIncreaseAllowanceData);

        // Create ERC20 decreaseAllowance calldata
        bytes memory decreaseAllowanceData =
            abi.encodeWithSignature("decreaseAllowance(address,uint256)", recipient1, 100);
        bytes memory executeDecreaseAllowanceData = abi.encode(address(testERC20), 0, decreaseAllowanceData);
        vm.prank(account1);
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeDecreaseAllowanceData);
    }

    function test_verifyAllowedTargetOrRecipient_ERC20_Methods_Unauthorized() public {
        // Don't add recipient to allowlist
        bytes memory transferData = abi.encodeCall(IERC20.transfer, (recipient1, 100));
        bytes memory executeTransferData = abi.encode(address(testERC20), 0, transferData);
        // Should revert with UnauthorizedRecipient because no recipient is added to allowlist
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, recipient1));
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeTransferData);

        // Add recipient to allowlist and try again
        address[] memory recipients = new address[](1);
        recipients[0] = recipient1;
        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);
    }

    function test_verifyAllowedTargetOrRecipient_ERC20_Methods_Unchecked() public {
        // Create ERC20 allowance calldata which would be considered to contain an erc20 method
        bytes memory allowanceData = abi.encodeWithSignature("allowance(address,address)", account1, recipient1);
        bytes memory executeAllowanceData = abi.encode(address(testERC20), 0, allowanceData);
        vm.prank(account1);
        // Should not revert
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeAllowanceData);
    }

    function test_verifyAllowedTargetOrRecipient_ERC721_Methods_Allowed() public {
        address[] memory recipients = new address[](1);
        recipients[0] = recipient1;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Create ERC721 transfer calldata
        bytes memory transferData = abi.encodeCall(IERC721.transferFrom, (account1, recipient1, 1));
        bytes memory executeTransferFromData = abi.encode(address(testERC721), 0, transferData);
        vm.prank(account1);
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeTransferFromData);

        // Create ERC721 safeTransferFrom  with bytes calldata
        bytes memory safeTransferFromData =
            abi.encodeWithSignature("safeTransferFrom(address,address,uint256,bytes)", account1, recipient1, 1, "");
        bytes memory executeSafeTransferFromData = abi.encode(address(testERC721), 0, safeTransferFromData);
        vm.prank(account1);
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeSafeTransferFromData);

        // Create ERC721 approve calldata
        bytes memory approveData = abi.encodeCall(IERC721.approve, (recipient1, 1));
        bytes memory executeApproveData = abi.encode(address(testERC721), 0, approveData);
        vm.prank(account1);
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeApproveData);

        // Create ERC721 setApprovalForAll calldata
        bytes memory setApprovalForAllData = abi.encodeCall(IERC721.setApprovalForAll, (recipient1, true));
        bytes memory executeSetApprovalForAllData = abi.encode(address(testERC721), 0, setApprovalForAllData);
        vm.prank(account1);
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeSetApprovalForAllData);
    }

    function test_verifyAllowedTargetOrRecipient_ERC1155_Methods_Allowed() public {
        address[] memory recipients = new address[](1);
        recipients[0] = recipient1;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Create ERC1155 transfer calldata
        bytes memory transferData = abi.encodeCall(IERC1155.safeTransferFrom, (account1, recipient1, 1, 100, ""));
        bytes memory executeSafeTransferFromData = abi.encode(address(testERC1155), 0, transferData);
        vm.prank(account1);
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeSafeTransferFromData);

        // Create ERC1155 safeBatchTransferFrom calldata
        uint256[] memory ids = new uint256[](1);
        ids[0] = 1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 100;
        bytes memory safeBatchTransferFromData =
            abi.encodeCall(IERC1155.safeBatchTransferFrom, (account1, recipient1, ids, amounts, ""));
        bytes memory executeSafeBatchTransferFromData = abi.encode(address(testERC1155), 0, safeBatchTransferFromData);
        vm.prank(account1);
        addressBookModule.verifyAllowedTargetOrRecipient(
            IModularAccount.execute.selector, executeSafeBatchTransferFromData
        );

        // Create ERC1155 setApprovalForAll calldata
        bytes memory setApprovalForAllData = abi.encodeCall(IERC1155.setApprovalForAll, (recipient1, true));
        bytes memory executeSetApprovalForAllData = abi.encode(address(testERC1155), 0, setApprovalForAllData);
        vm.prank(account1);
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeSetApprovalForAllData);
    }

    function test_verifyAllowedTargetOrRecipient_BatchExecute_Allowed() public {
        address[] memory recipients = new address[](2);
        recipients[0] = recipient1;
        recipients[1] = recipient2;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        Call[] memory calls = new Call[](2);
        calls[0] =
            Call({target: address(testERC20), value: 0, data: abi.encodeCall(IERC20.transfer, (recipient1, 100))});
        calls[1] =
            Call({target: address(testERC20), value: 0, data: abi.encodeCall(IERC20.transfer, (recipient2, 200))});

        bytes memory batchCalldata = abi.encode(calls);

        vm.prank(account1);
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.executeBatch.selector, batchCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_BatchExecute_OneUnauthorized() public {
        // Add only one recipient to allowlist
        address[] memory recipients = new address[](1);
        recipients[0] = recipient1;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Create batch calls with one unauthorized recipient
        Call[] memory calls = new Call[](2);
        calls[0] =
            Call({target: address(testERC20), value: 0, data: abi.encodeCall(IERC20.transfer, (recipient1, 100))});
        calls[1] = Call({
            target: address(testERC20),
            value: 0,
            data: abi.encodeCall(IERC20.transfer, (recipient2, 200)) // recipient2 not in allowlist
        });

        bytes memory batchCalldata = abi.encode(calls);

        // Should revert with UnauthorizedRecipient for recipient2
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, recipient2));
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.executeBatch.selector, batchCalldata);
    }

    // ==================== Zero Address Recipient Tests ====================

    function test_verifyAllowedTargetOrRecipient_ERC20Transfer_ZeroRecipient() public {
        // Create ERC20 transfer calldata with zero address recipient
        bytes memory transferData = abi.encodeCall(IERC20.transfer, (address(0), 100));
        bytes memory executeCalldata = abi.encode(address(testERC20), 0, transferData);

        // Should revert with UnauthorizedRecipient for address(0)
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, address(0)));
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_ERC20Transfer_ZeroRecipient_Batch() public {
        // Create ERC20 transfer calldata with zero address recipient
        Call[] memory calls = new Call[](1);
        calls[0] =
            Call({target: address(testERC20), value: 0, data: abi.encodeCall(IERC20.transfer, (address(0), 100))});
        bytes memory batchCalldata = abi.encode(calls);

        // Should revert with UnauthorizedRecipient for address(0)
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, address(0)));
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.executeBatch.selector, batchCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_ERC20TransferFrom_ZeroRecipient() public {
        // Create ERC20 transferFrom calldata with zero address recipient
        bytes memory transferData = abi.encodeCall(IERC20.transferFrom, (account1, address(0), 100));
        bytes memory executeCalldata = abi.encode(address(testERC20), 0, transferData);

        // Should revert with UnauthorizedRecipient for address(0)
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, address(0)));
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_ERC20TransferFrom_ZeroRecipient_Batch() public {
        // Create ERC20 transferFrom calldata with zero address recipient
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(testERC20),
            value: 0,
            data: abi.encodeCall(IERC20.transferFrom, (account1, address(0), 100))
        });
        bytes memory batchCalldata = abi.encode(calls);

        // Should revert with UnauthorizedRecipient for address(0)
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, address(0)));
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.executeBatch.selector, batchCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_ERC20Approve_ZeroRecipient() public {
        // Create ERC20 approve calldata with zero address recipient (spender)
        bytes memory approveData = abi.encodeCall(IERC20.approve, (address(0), 100));
        bytes memory executeCalldata = abi.encode(address(testERC20), 0, approveData);

        // Should revert with UnauthorizedRecipient for address(0)
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, address(0)));
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_ERC20Approve_ZeroRecipient_Batch() public {
        // Create ERC20 approve calldata with zero address recipient (spender)
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(testERC20), value: 0, data: abi.encodeCall(IERC20.approve, (address(0), 100))});
        bytes memory batchCalldata = abi.encode(calls);

        // Should revert with UnauthorizedRecipient for address(0)
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, address(0)));
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.executeBatch.selector, batchCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_ERC721Transfer_ZeroRecipient() public {
        // Create ERC721 transfer calldata with zero address recipient
        bytes memory transferData = abi.encodeCall(IERC721.transferFrom, (account1, address(0), 1));
        bytes memory executeCalldata = abi.encode(address(testERC721), 0, transferData);

        // Should revert with UnauthorizedRecipient for address(0)
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, address(0)));
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_ERC721Transfer_ZeroRecipient_Batch() public {
        // Create ERC721 transfer calldata with zero address recipient
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(testERC721),
            value: 0,
            data: abi.encodeCall(IERC721.transferFrom, (account1, address(0), 1))
        });
        bytes memory batchCalldata = abi.encode(calls);

        // Should revert with UnauthorizedRecipient for address(0)
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, address(0)));
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.executeBatch.selector, batchCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_ERC721SafeTransferFrom_ZeroRecipient() public {
        // Create ERC721 safeTransferFrom calldata with zero address recipient
        bytes memory transferData =
            abi.encodeWithSignature("safeTransferFrom(address,address,uint256)", account1, address(0), 1);
        bytes memory executeCalldata = abi.encode(address(testERC721), 0, transferData);

        // Should revert with UnauthorizedRecipient for address(0)
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, address(0)));
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_ERC721SafeTransferFrom_ZeroRecipient_Batch() public {
        // Create ERC721 safeTransferFrom calldata with zero address recipient
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(testERC721),
            value: 0,
            data: abi.encodeWithSignature("safeTransferFrom(address,address,uint256)", account1, address(0), 1)
        });
        bytes memory batchCalldata = abi.encode(calls);

        // Should revert with UnauthorizedRecipient for address(0)
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, address(0)));
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.executeBatch.selector, batchCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_ERC721Approve_ZeroRecipient() public {
        // Create ERC721 approve calldata with zero address recipient (spender)
        bytes memory approveData = abi.encodeCall(IERC721.approve, (address(0), 1));
        bytes memory executeCalldata = abi.encode(address(testERC721), 0, approveData);

        // Should revert with UnauthorizedRecipient for address(0)
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, address(0)));
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_ERC721Approve_ZeroRecipient_Batch() public {
        // Create ERC721 approve calldata with zero address recipient (spender)
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(testERC721), value: 0, data: abi.encodeCall(IERC721.approve, (address(0), 1))});
        bytes memory batchCalldata = abi.encode(calls);

        // Should revert with UnauthorizedRecipient for address(0)
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, address(0)));
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.executeBatch.selector, batchCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_ERC721SetApprovalForAll_ZeroRecipient() public {
        // Create ERC721 setApprovalForAll calldata with zero address recipient (operator)
        bytes memory approveData = abi.encodeCall(IERC721.setApprovalForAll, (address(0), true));
        bytes memory executeCalldata = abi.encode(address(testERC721), 0, approveData);

        // Should revert with UnauthorizedRecipient for address(0)
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, address(0)));
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_ERC721SetApprovalForAll_ZeroRecipient_Batch() public {
        // Create ERC721 setApprovalForAll calldata with zero address recipient (operator)
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(testERC721),
            value: 0,
            data: abi.encodeCall(IERC721.setApprovalForAll, (address(0), true))
        });
        bytes memory batchCalldata = abi.encode(calls);

        // Should revert with UnauthorizedRecipient for address(0)
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, address(0)));
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.executeBatch.selector, batchCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_ERC1155SafeTransferFrom_ZeroRecipient() public {
        // Create ERC1155 safeTransferFrom calldata with zero address recipient
        bytes memory transferData = abi.encodeCall(IERC1155.safeTransferFrom, (account1, address(0), 1, 100, ""));
        bytes memory executeCalldata = abi.encode(address(testERC1155), 0, transferData);

        // Should revert with UnauthorizedRecipient for address(0)
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, address(0)));
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_ERC1155SafeTransferFrom_ZeroRecipient_Batch() public {
        // Create ERC1155 safeTransferFrom calldata with zero address recipient
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(testERC1155),
            value: 0,
            data: abi.encodeCall(IERC1155.safeTransferFrom, (account1, address(0), 1, 100, ""))
        });
        bytes memory batchCalldata = abi.encode(calls);

        // Should revert with UnauthorizedRecipient for address(0)
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, address(0)));
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.executeBatch.selector, batchCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_ERC1155SafeBatchTransferFrom_ZeroRecipient() public {
        uint256[] memory ids = new uint256[](1);
        ids[0] = 1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 100;

        // Create ERC1155 safeBatchTransferFrom calldata with zero address recipient
        bytes memory transferData =
            abi.encodeCall(IERC1155.safeBatchTransferFrom, (account1, address(0), ids, amounts, ""));
        bytes memory executeCalldata = abi.encode(address(testERC1155), 0, transferData);

        // Should revert with UnauthorizedRecipient for address(0)
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, address(0)));
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_ERC1155SafeBatchTransferFrom_ZeroRecipient_Batch() public {
        // Create ERC1155 safeBatchTransferFrom calldata with zero address recipient
        Call[] memory calls = new Call[](1);
        uint256[] memory ids = new uint256[](1);
        ids[0] = 1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 100;
        calls[0] = Call({
            target: address(testERC1155),
            value: 0,
            data: abi.encodeCall(IERC1155.safeBatchTransferFrom, (account1, address(0), ids, amounts, ""))
        });
        bytes memory batchCalldata = abi.encode(calls);

        // Should revert with UnauthorizedRecipient for address(0)
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, address(0)));
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.executeBatch.selector, batchCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_ERC1155SetApprovalForAll_ZeroRecipient() public {
        // Create ERC1155 setApprovalForAll calldata with zero address recipient (operator)
        bytes memory approveData = abi.encodeCall(IERC1155.setApprovalForAll, (address(0), true));
        bytes memory executeCalldata = abi.encode(address(testERC1155), 0, approveData);

        // Should revert with UnauthorizedRecipient for address(0)
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, address(0)));
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_ERC1155SetApprovalForAll_ZeroRecipient_Batch() public {
        // Create ERC1155 setApprovalForAll calldata with zero address recipient (operator)
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(testERC1155),
            value: 0,
            data: abi.encodeCall(IERC1155.setApprovalForAll, (address(0), true))
        });
        bytes memory batchCalldata = abi.encode(calls);

        // Should revert with UnauthorizedRecipient for address(0)
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, address(0)));
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.executeBatch.selector, batchCalldata);
    }

    // ==================== Native Transfer Tests ====================

    function test_verifyAllowedTargetOrRecipient_NativeTransfer_Allowed() public {
        // Add recipient to allowlist
        address[] memory recipients = new address[](1);
        recipients[0] = recipient1;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Create native transfer (value > 0, empty data)
        bytes memory executeCalldata = abi.encode(recipient1, 1 ether, "");

        // Should not revert
        vm.prank(account1);
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_NativeTransfer_Unauthorized() public {
        // Don't add recipient to allowlist

        // Create native transfer (value > 0, empty data)
        bytes memory executeCalldata = abi.encode(recipient1, 1 ether, "");

        // Should revert with UnauthorizedRecipient
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, recipient1));
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_NativeTransferToZeroAddress() public {
        // Create native transfer to address(0)
        bytes memory executeCalldata = abi.encode(address(0), 1 ether, "");

        // Should revert with UnauthorizedRecipient for address(0)
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, address(0)));
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_NativeTransferWithData() public {
        // Add recipient to allowlist
        address[] memory recipients = new address[](1);
        recipients[0] = recipient1;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Create native transfer with non-empty data (should fail)
        bytes memory executeCalldata = abi.encode(recipient1, 1 ether, "0x1234");

        // Should revert with CallDataIsNotEmpty
        vm.prank(account1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAddressBookModule.CallDataIsNotEmpty.selector, account1, recipient1, 1 ether, "0x1234"
            )
        );
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeCalldata);
    }

    // ==================== Native Transfer Batch Tests ====================

    function test_verifyAllowedTargetOrRecipient_NativeTransferBatch_Allowed() public {
        // Add recipients to allowlist
        address[] memory recipients = new address[](2);
        recipients[0] = recipient1;
        recipients[1] = recipient2;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Create batch native transfers (value > 0, empty data)
        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: recipient1, value: 1 ether, data: ""});
        calls[1] = Call({target: recipient2, value: 0.5 ether, data: ""});

        bytes memory batchCalldata = abi.encode(calls);

        // Should not revert
        vm.prank(account1);
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.executeBatch.selector, batchCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_NativeTransferBatch_Unauthorized() public {
        // Add only one recipient to allowlist
        address[] memory recipients = new address[](1);
        recipients[0] = recipient1;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Create batch native transfers with one unauthorized recipient
        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: recipient1, value: 1 ether, data: ""});
        calls[1] = Call({
            target: recipient2, // Not in allowlist
            value: 0.5 ether,
            data: ""
        });

        bytes memory batchCalldata = abi.encode(calls);

        // Should revert with UnauthorizedRecipient for recipient2
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, recipient2));
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.executeBatch.selector, batchCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_NativeTransferBatchToZeroAddress() public {
        // Add recipient1 to allowlist so the first call passes
        address[] memory recipients = new address[](1);
        recipients[0] = recipient1;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Create batch native transfers with one to zero address
        Call[] memory calls = new Call[](2);
        calls[0] = Call({
            target: recipient1, // This should pass
            value: 1 ether,
            data: ""
        });
        calls[1] = Call({
            target: address(0), // Zero address - this should fail
            value: 0.5 ether,
            data: ""
        });

        bytes memory batchCalldata = abi.encode(calls);

        // Should revert with UnauthorizedRecipient for address(0)
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, address(0)));
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.executeBatch.selector, batchCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_NativeTransferBatchWithData() public {
        // Add recipient to allowlist
        address[] memory recipients = new address[](1);
        recipients[0] = recipient1;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Create batch native transfers with non-empty data (should fail)
        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: recipient1, value: 1 ether, data: ""});
        calls[1] = Call({
            target: recipient1,
            value: 0.5 ether,
            data: "0x1234" // Non-empty data
        });

        bytes memory batchCalldata = abi.encode(calls);

        // Should revert with CallDataIsNotEmpty for the second call
        vm.prank(account1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAddressBookModule.CallDataIsNotEmpty.selector, account1, recipient1, 0.5 ether, "0x1234"
            )
        );
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.executeBatch.selector, batchCalldata);
    }

    // ==================== Validation Hook Tests ====================

    function test_preUserOpValidationHook_Success() public {
        // Add recipient to allowlist
        address[] memory recipients = new address[](1);
        recipients[0] = recipient1;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Create user operation
        PackedUserOperation memory userOp;
        userOp.sender = account1;
        // Empty signature required (empty signature is required for preUserOpValidationHook)
        userOp.signature = "";

        // Create ERC20 transfer calldata
        bytes memory transferData = abi.encodeCall(IERC20.transfer, (recipient1, 100));
        userOp.callData = abi.encodeCall(IModularAccount.execute, (address(testERC20), 0, transferData));

        // Should return SIG_VALIDATION_SUCCEEDED
        vm.prank(account1);
        uint256 result = addressBookModule.preUserOpValidationHook(0, userOp, bytes32(0));
        assertEq(result, SIG_VALIDATION_SUCCEEDED);
    }

    function test_preUserOpValidationHook_UnexpectedDataPassed() public {
        PackedUserOperation memory userOp;
        userOp.sender = account1;
        // Non-empty signature should cause revert since hook runs in validation stage
        userOp.signature = "0x1234";

        // Should revert with UnexpectedDataPassed
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(UnexpectedDataPassed.selector));
        addressBookModule.preUserOpValidationHook(0, userOp, bytes32(0));
    }

    // ==================== User Op Validation Hook Batch Tests ====================

    function test_preUserOpValidationHook_ExecuteBatch_Success() public {
        // Add recipients to allowlist
        address[] memory recipients = new address[](2);
        recipients[0] = recipient1;
        recipients[1] = recipient2;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Create user operation with executeBatch
        PackedUserOperation memory userOp;
        userOp.sender = account1;
        // Empty signature required (empty signature is required for preUserOpValidationHook)
        userOp.signature = "";

        // Create batch calls with token transfers
        Call[] memory calls = new Call[](13);
        calls[0] =
            Call({target: address(testERC20), value: 0, data: abi.encodeCall(IERC20.transfer, (recipient1, 100))});
        calls[1] = Call({
            target: address(testERC20),
            value: 0,
            data: abi.encodeCall(IERC20.transferFrom, (account1, recipient2, 200))
        });
        calls[2] = Call({target: address(testERC20), value: 0, data: abi.encodeCall(IERC20.approve, (recipient2, 300))});
        bytes memory increaseAllowanceData =
            abi.encodeWithSignature("increaseAllowance(address,uint256)", recipient1, 100);
        calls[3] = Call({target: address(testERC20), value: 0, data: increaseAllowanceData});
        bytes memory decreaseAllowanceData =
            abi.encodeWithSignature("decreaseAllowance(address,uint256)", recipient1, 100);
        calls[4] = Call({target: address(testERC20), value: 0, data: decreaseAllowanceData});
        calls[5] = Call({
            target: address(testERC721),
            value: 0,
            data: abi.encodeCall(IERC721.transferFrom, (account1, recipient2, 1))
        });
        bytes memory safeTransferFromData =
            abi.encodeWithSignature("safeTransferFrom(address,address,uint256,bytes)", account1, recipient2, 1, "");
        calls[6] = Call({target: address(testERC721), value: 0, data: safeTransferFromData});
        bytes memory safeTransferFromWithBytesData =
            abi.encodeWithSignature("safeTransferFrom(address,address,uint256,bytes)", account1, recipient2, 1, "");
        calls[7] = Call({target: address(testERC721), value: 0, data: safeTransferFromWithBytesData});
        calls[8] = Call({target: address(testERC721), value: 0, data: abi.encodeCall(IERC721.approve, (recipient2, 1))});
        calls[9] = Call({
            target: address(testERC721),
            value: 0,
            data: abi.encodeCall(IERC721.setApprovalForAll, (recipient2, true))
        });
        calls[10] = Call({
            target: address(testERC1155),
            value: 0,
            data: abi.encodeCall(IERC1155.safeTransferFrom, (account1, recipient2, 1, 100, ""))
        });
        uint256[] memory ids = new uint256[](1);
        ids[0] = 1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 100;
        calls[11] = Call({
            target: address(testERC1155),
            value: 0,
            data: abi.encodeCall(IERC1155.safeBatchTransferFrom, (account1, recipient2, ids, amounts, ""))
        });
        calls[12] = Call({
            target: address(testERC1155),
            value: 0,
            data: abi.encodeCall(IERC1155.setApprovalForAll, (recipient2, true))
        });

        userOp.callData = abi.encodeWithSelector(IModularAccount.executeBatch.selector, calls);

        // Should return SIG_VALIDATION_SUCCEEDED
        vm.prank(account1);
        uint256 result = addressBookModule.preUserOpValidationHook(0, userOp, bytes32(0));
        assertEq(result, SIG_VALIDATION_SUCCEEDED);
    }

    function test_preUserOpValidationHook_ExecuteBatch_Success_TokenCall_OtherCalls() public {
        // Add recipients to allowlist
        address[] memory recipients = new address[](2);
        recipients[0] = recipient1;
        recipients[1] = recipient2;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Create user operation with executeBatch
        PackedUserOperation memory userOp;
        userOp.sender = account1;
        userOp.signature = ""; // Empty signature required

        // Create batch calls with token transfers and other calls
        Call[] memory calls = new Call[](2);
        calls[0] =
            Call({target: address(testERC20), value: 0, data: abi.encodeCall(IERC20.transfer, (recipient1, 100))});
        bytes memory otherCallData = abi.encodeWithSignature("mint(address,uint256)", recipient2, 200);
        calls[1] = Call({target: address(testERC20_2), value: 0, data: otherCallData});

        userOp.callData = abi.encodeWithSelector(IModularAccount.executeBatch.selector, calls);

        // Should return SIG_VALIDATION_SUCCEEDED
        vm.prank(account1);
        uint256 result = addressBookModule.preUserOpValidationHook(0, userOp, bytes32(0));
        assertEq(result, SIG_VALIDATION_SUCCEEDED);
    }

    function test_preUserOpValidationHook_ExecuteBatch_UnauthorizedRecipient() public {
        // Add only one recipient to allowlist
        address[] memory recipients = new address[](1);
        recipients[0] = recipient1;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Create user operation with executeBatch
        PackedUserOperation memory userOp;
        userOp.sender = account1;
        // Empty signature required (empty signature is required for preUserOpValidationHook)
        userOp.signature = "";

        // Create batch calls with one unauthorized recipient
        Call[] memory calls = new Call[](2);
        calls[0] =
            Call({target: address(testERC20), value: 0, data: abi.encodeCall(IERC20.transfer, (recipient1, 100))});
        calls[1] =
            Call({target: address(testERC20), value: 0, data: abi.encodeCall(IERC20.transfer, (recipient2, 200))});

        userOp.callData = abi.encodeWithSelector(IModularAccount.executeBatch.selector, calls);

        // Should revert with UnauthorizedRecipient for recipient2
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, recipient2));
        addressBookModule.preUserOpValidationHook(0, userOp, bytes32(0));
    }

    function test_preUserOpValidationHook_ExecuteBatch_NativeTransfers() public {
        // Add recipients to allowlist
        address[] memory recipients = new address[](2);
        recipients[0] = recipient1;
        recipients[1] = recipient2;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Create user operation with executeBatch for native transfers
        PackedUserOperation memory userOp;
        userOp.sender = account1;
        // Empty signature required (empty signature is required for preUserOpValidationHook)
        userOp.signature = "";

        // Create batch calls with native transfers
        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: recipient1, value: 1 ether, data: ""});
        calls[1] = Call({target: recipient2, value: 0.5 ether, data: ""});

        userOp.callData = abi.encodeWithSelector(IModularAccount.executeBatch.selector, calls);

        // Should return SIG_VALIDATION_SUCCEEDED
        vm.prank(account1);
        uint256 result = addressBookModule.preUserOpValidationHook(0, userOp, bytes32(0));
        assertEq(result, SIG_VALIDATION_SUCCEEDED);
    }

    function test_preUserOpValidationHook_ExecuteBatch_NativeTransferToZeroAddress() public {
        // Add recipient1 to allowlist
        address[] memory recipients = new address[](1);
        recipients[0] = recipient1;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Create user operation with executeBatch
        PackedUserOperation memory userOp;
        userOp.sender = account1;
        userOp.signature = ""; // Empty signature required

        // Create batch calls with one transfer to zero address
        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: recipient1, value: 1 ether, data: ""});
        calls[1] = Call({target: address(0), value: 0.5 ether, data: ""});

        userOp.callData = abi.encodeWithSelector(IModularAccount.executeBatch.selector, calls);

        // Should revert with UnauthorizedRecipient for address(0)
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, address(0)));
        addressBookModule.preUserOpValidationHook(0, userOp, bytes32(0));
    }

    function test_preUserOpValidationHook_ExecuteBatch_MixedTokenAndNative() public {
        // Add recipients to allowlist
        address[] memory recipients = new address[](2);
        recipients[0] = recipient1;
        recipients[1] = recipient2;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Create user operation with executeBatch
        PackedUserOperation memory userOp;
        userOp.sender = account1;
        // Empty signature required (empty signature is required for preUserOpValidationHook)
        userOp.signature = "";

        // Create batch calls mixing token transfers and native transfers
        Call[] memory calls = new Call[](3);
        calls[0] =
            Call({target: address(testERC20), value: 0, data: abi.encodeCall(IERC20.transfer, (recipient1, 100))});
        calls[1] = Call({target: recipient2, value: 1 ether, data: ""});
        calls[2] = Call({
            target: address(testERC1155),
            value: 0,
            data: abi.encodeCall(IERC1155.safeTransferFrom, (account1, recipient1, 1, 50, ""))
        });

        userOp.callData = abi.encodeWithSelector(IModularAccount.executeBatch.selector, calls);

        // Should return SIG_VALIDATION_SUCCEEDED
        vm.prank(account1);
        uint256 result = addressBookModule.preUserOpValidationHook(0, userOp, bytes32(0));
        assertEq(result, SIG_VALIDATION_SUCCEEDED);
    }

    function test_preUserOpValidationHook_ExecuteBatch_NonTokenMethod() public {
        // Add recipient to allowlist
        address[] memory recipients = new address[](1);
        recipients[0] = recipient1;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Create user operation with executeBatch
        PackedUserOperation memory userOp;
        userOp.sender = account1;
        // Empty signature required (empty signature is required for preUserOpValidationHook)
        userOp.signature = "";

        // Create batch calls with non-token methods (should pass through)
        Call[] memory calls = new Call[](2);
        calls[0] = Call({
            target: address(testERC20),
            value: 0,
            data: abi.encodeCall(testERC20.mint, (recipient1, 100)) // Non-tracked method
        });
        calls[1] = Call({
            target: address(testERC20),
            value: 0,
            data: abi.encodeCall(IERC20.transfer, (recipient1, 50)) // Tracked method
        });

        userOp.callData = abi.encodeWithSelector(IModularAccount.executeBatch.selector, calls);

        // Should return SIG_VALIDATION_SUCCEEDED (mint is ignored, transfer is validated)
        vm.prank(account1);
        uint256 result = addressBookModule.preUserOpValidationHook(0, userOp, bytes32(0));
        assertEq(result, SIG_VALIDATION_SUCCEEDED);
    }

    function test_preUserOpValidationHook_ExecuteBatch_EmptyBatch() public {
        // Create user operation with empty executeBatch
        PackedUserOperation memory userOp;
        userOp.sender = account1;
        // Empty signature required (empty signature is required for preUserOpValidationHook)
        userOp.signature = "";

        // Create empty batch
        Call[] memory calls = new Call[](0);
        userOp.callData = abi.encodeWithSelector(IModularAccount.executeBatch.selector, calls);

        // Should return SIG_VALIDATION_SUCCEEDED (no calls to validate)
        vm.prank(account1);
        uint256 result = addressBookModule.preUserOpValidationHook(0, userOp, bytes32(0));
        assertEq(result, SIG_VALIDATION_SUCCEEDED);
    }

    function test_preUserOpValidationHook_ExecuteBatch_TokenTransferZeroRecipient() public {
        // Add recipient1 to allowlist so the first call passes
        address[] memory recipients = new address[](1);
        recipients[0] = recipient1;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Create user operation with executeBatch
        PackedUserOperation memory userOp;
        userOp.sender = account1;
        // Empty signature required (empty signature is required for preUserOpValidationHook)
        userOp.signature = "";

        // Create batch calls with token transfer to zero address
        Call[] memory calls = new Call[](2);
        calls[0] =
            Call({target: address(testERC20), value: 0, data: abi.encodeCall(IERC20.transfer, (recipient1, 100))});
        calls[1] =
            Call({target: address(testERC20), value: 0, data: abi.encodeCall(IERC20.transfer, (address(0), 200))});

        userOp.callData = abi.encodeWithSelector(IModularAccount.executeBatch.selector, calls);

        // Should revert with UnauthorizedRecipient for address(0)
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, address(0)));
        addressBookModule.preUserOpValidationHook(0, userOp, bytes32(0));
    }

    function test_preUserOpValidationHook_ExecuteBatch_MultipleTokenTypesZeroRecipient() public {
        // Add recipient1 to allowlist so valid calls pass
        address[] memory recipients = new address[](1);
        recipients[0] = recipient1;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Create user operation with executeBatch
        PackedUserOperation memory userOp;
        userOp.sender = account1;
        // Empty signature required (empty signature is required for preUserOpValidationHook)
        userOp.signature = "";

        // Create batch calls with different token types, one with zero recipient
        Call[] memory calls = new Call[](3);
        calls[0] =
            Call({target: address(testERC20), value: 0, data: abi.encodeCall(IERC20.transfer, (recipient1, 100))});
        calls[1] = Call({
            target: address(testERC721),
            value: 0,
            data: abi.encodeCall(IERC721.transferFrom, (account1, recipient1, 1))
        });
        calls[2] = Call({
            target: address(testERC1155),
            value: 0,
            data: abi.encodeCall(IERC1155.safeTransferFrom, (account1, address(0), 1, 50, ""))
        });

        userOp.callData = abi.encodeWithSelector(IModularAccount.executeBatch.selector, calls);

        // Should revert with UnauthorizedRecipient for address(0) in the ERC1155 transfer
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(IAddressBookModule.UnauthorizedRecipient.selector, account1, address(0)));
        addressBookModule.preUserOpValidationHook(0, userOp, bytes32(0));
    }

    function test_preRuntimeValidationHook_Success() public {
        // Add recipient to allowlist
        address[] memory recipients = new address[](1);
        recipients[0] = recipient1;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Create ERC20 transfer calldata
        bytes memory transferData = abi.encodeCall(IERC20.transfer, (recipient1, 100));
        bytes memory fullCalldata = abi.encodeCall(IModularAccount.execute, (address(testERC20), 0, transferData));

        // Should not revert
        vm.prank(account1);
        addressBookModule.preRuntimeValidationHook(0, account1, 0, fullCalldata, "");
    }

    function test_preSignatureValidationHook_Unsupported() public {
        // Should always revert with Unsupported
        vm.expectRevert(abi.encodeWithSelector(Unsupported.selector));
        addressBookModule.preSignatureValidationHook(0, account1, bytes32(0), "");
    }

    // ==================== Error Conditions Tests ====================

    function test_verifyAllowedTargetOrRecipient_UnsupportedSelector() public {
        bytes memory executeCalldata = abi.encode(address(testERC20), 0, "");

        // Should revert with Unsupported for unknown selector
        vm.prank(account1);
        vm.expectRevert(abi.encodeWithSelector(Unsupported.selector));
        addressBookModule.verifyAllowedTargetOrRecipient(bytes4(0x12345678), executeCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_TokenContractWithoutCode() public {
        // Create a non-contract address
        address nonContract = makeAddr("nonContract");

        // Create ERC20 transfer calldata targeting non-contract
        bytes memory transferData = abi.encodeCall(IERC20.transfer, (recipient1, 100));
        bytes memory executeCalldata = abi.encode(nonContract, 0, transferData);

        // Should revert with InvalidTargetCodeLength
        vm.prank(account1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAddressBookModule.InvalidTargetCodeLength.selector, account1, nonContract, 0, transferData
            )
        );
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_NonTokenMethod() public {
        // Add recipient to allowlist
        address[] memory recipients = new address[](1);
        recipients[0] = recipient1;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Create calldata for non-token method (e.g., mint)
        bytes memory mintData = abi.encodeCall(testERC20.mint, (recipient1, 100));
        bytes memory executeCalldata = abi.encode(address(testERC20), 0, mintData);

        // Should not revert because mint is not a tracked token method
        vm.prank(account1);
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeCalldata);
    }

    // ==================== Module Metadata Tests ====================

    function test_moduleId() public view {
        string memory moduleId = addressBookModule.moduleId();
        assertEq(moduleId, "avara.address-book-module.1.0.0");
    }

    function test_supportsInterface() public view {
        assertTrue(addressBookModule.supportsInterface(type(IAddressBookModule).interfaceId));
        assertTrue(addressBookModule.supportsInterface(type(IModule).interfaceId));
        assertTrue(addressBookModule.supportsInterface(type(IValidationHookModule).interfaceId));
        assertTrue(addressBookModule.supportsInterface(type(IExecutionModule).interfaceId));
        assertFalse(addressBookModule.supportsInterface(bytes4(0x12345678)));
    }

    function test_executionManifest() public view {
        ExecutionManifest memory manifest = addressBookModule.executionManifest();

        // Should have 2 execution functions
        assertEq(manifest.executionFunctions.length, 2);

        // Check addAllowedRecipients function
        assertEq(manifest.executionFunctions[0].executionSelector, addressBookModule.addAllowedRecipients.selector);
        assertTrue(manifest.executionFunctions[0].skipRuntimeValidation);
        assertFalse(manifest.executionFunctions[0].allowGlobalValidation);

        // Check removeAllowedRecipients function
        assertEq(manifest.executionFunctions[1].executionSelector, addressBookModule.removeAllowedRecipients.selector);
        assertFalse(manifest.executionFunctions[1].skipRuntimeValidation);
        assertTrue(manifest.executionFunctions[1].allowGlobalValidation);

        // Should have 1 interface ID
        assertEq(manifest.interfaceIds.length, 1);
        assertEq(manifest.interfaceIds[0], type(IAddressBookModule).interfaceId);
    }

    // ==================== Edge Cases and Malformed Data Tests ====================

    function test_verifyAllowedTargetOrRecipient_MalformedERC20Transfer() public {
        // Create malformed ERC20 transfer calldata (too short)
        bytes memory malformedData = abi.encodePacked(IERC20.transfer.selector, uint128(0x1234));
        bytes memory executeCalldata = abi.encode(address(testERC20), 0, malformedData);

        // Should not revert because malformed data fails the length check in containsERC20Methods()
        // So the module treats it as a non-token method and skips validation.
        // Calls containing insufficient calldata for parameter decoding will revert.
        vm.prank(account1);
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeCalldata);
    }

    function test_verifyAllowedTargetOrRecipient_MalformedERC20Transfer_DirectCall() public {
        // This test demonstrates what happens if malformed calldata actually reaches the ERC20 contract

        // Try to call the ERC20 contract directly with malformed data
        // This should revert because Solidity cannot decode the parameters properly
        assertGt(address(testERC20).code.length, 0, "no code at address");
        // Mint some tokens so the transfer can succeed
        testERC20.mint(address(this), 1000);
        bytes memory transferData = abi.encodeWithSelector(IERC20.transfer.selector, address(1), uint256(1));
        (bool transferSuccess,) = address(testERC20).call(transferData);
        assertTrue(transferSuccess);

        // Try to call the ERC20 contract with malformed data (too short)
        bytes memory malformedData = abi.encodePacked(IERC20.transfer.selector, uint128(0x1234));
        (bool success,) = address(testERC20).call(malformedData);

        // The call should fail due to insufficient calldata for parameter decoding
        assertFalse(success);
    }

    function test_verifyAllowedTargetOrRecipient_ExtraLongERC20Transfer_DirectCall() public {
        // This test shows what happens with extra-long calldata (more than needed)

        // Create ERC20 transfer calldata with extra bytes at the end
        bytes memory normalTransferData = abi.encodeCall(IERC20.transfer, (recipient1, 100));
        bytes memory extraLongData = abi.encodePacked(normalTransferData, "extra_garbage_data_here");

        // Mint some tokens first so the transfer can succeed
        testERC20.mint(address(this), 1000);

        // Try to call the ERC20 contract with extra-long calldata
        // This should SUCCEED - Solidity ignores extra bytes at the end
        (bool success,) = address(testERC20).call(extraLongData);

        // The call should succeed because Solidity only reads what it needs
        assertTrue(success);

        // Verify the transfer actually worked
        assertEq(testERC20.balanceOf(recipient1), 100);
    }

    function test_verifyAllowedTargetOrRecipient_ZeroValueTokenCall() public {
        // Add recipient to allowlist
        address[] memory recipients = new address[](1);
        recipients[0] = recipient1;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Create ERC20 transfer with zero value (should still work)
        bytes memory transferData = abi.encodeCall(IERC20.transfer, (recipient1, 0));
        bytes memory executeCalldata = abi.encode(address(testERC20), 0, transferData);

        // Should not revert
        vm.prank(account1);
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeCalldata);
    }

    function test_fuzz_addAllowedRecipients(address[] memory recipients) public {
        vm.assume(recipients.length > 0 && recipients.length < 100);

        // Filter out zero addresses and duplicates
        address[] memory filteredRecipients = new address[](recipients.length);
        uint256 count = 0;

        for (uint256 i = 0; i < recipients.length; i++) {
            if (recipients[i] != address(0)) {
                bool isDuplicate = false;
                for (uint256 j = 0; j < count; j++) {
                    if (filteredRecipients[j] == recipients[i]) {
                        isDuplicate = true;
                        break;
                    }
                }
                if (!isDuplicate) {
                    filteredRecipients[count] = recipients[i];
                    count++;
                }
            }
        }

        if (count == 0) return;

        // Resize array
        assembly {
            mstore(filteredRecipients, count)
        }

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(filteredRecipients);

        address[] memory allowedRecipients = addressBookModule.getAllowedRecipients(account1);
        assertEq(allowedRecipients.length, count);
    }

    function test_fuzz_verifyAllowedTargetOrRecipient_NativeTransfer(address target, uint256 value) public {
        vm.assume(target != address(0));
        vm.assume(value > 0);

        // Add target to allowlist
        address[] memory recipients = new address[](1);
        recipients[0] = target;

        vm.prank(account1);
        addressBookModule.addAllowedRecipients(recipients);

        // Create native transfer
        bytes memory executeCalldata = abi.encode(target, value, "");

        // Should not revert
        vm.prank(account1);
        addressBookModule.verifyAllowedTargetOrRecipient(IModularAccount.execute.selector, executeCalldata);
    }
}
