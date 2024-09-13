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

import {TestUtils} from "./util/TestUtils.sol";
import "./util/TestERC721.sol";
import "./util/TestERC1155.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {FunctionReference} from "../src/msca/6900/v0.7/common/Structs.sol";
import "./util/TestLiquidityPool.sol";
import "../src/msca/6900/v0.7/factories/semi/SingleOwnerMSCAFactory.sol";
import "../src/msca/6900/v0.7/libs/FunctionReferenceLib.sol";
import "../src/msca/6900/v0.7/interfaces/IStandardExecutor.sol";
import "../src/msca/6900/v0.7/plugins/v1_0_0/acl/SingleOwnerPlugin.sol";
import {ECDSAAccountFactory} from "../src/account/v1/factory/ECDSAAccountFactory.sol";
import {ECDSAAccount} from "../src/account/v1/ECDSAAccount.sol";

contract WalletMigrationTest is TestUtils {
    using FunctionReferenceLib for bytes21;
    using FunctionReferenceLib for FunctionReference;
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

    // MSCA
    error WalletStorageIsInitialized();

    IEntryPoint private entryPoint = new EntryPoint();
    PluginManager private pluginManager = new PluginManager();
    address payable private beneficiary; // e.g. bundler
    TestERC1155 private testERC1155;
    TestERC721 private testERC721;
    TestLiquidityPool private testERC20;
    SingleOwnerMSCAFactory private singleOwnerMSCAFactory;
    ECDSAAccountFactory private ecdsaAccountFactory;

    function setUp() public {
        beneficiary = payable(address(makeAddr("bundler")));
        testERC1155 = new TestERC1155("getrich.com");
        testERC721 = new TestERC721("getrich", "$$$");
        testERC20 = new TestLiquidityPool("getrich", "$$$");
        singleOwnerMSCAFactory = new SingleOwnerMSCAFactory(address(entryPoint), address(pluginManager));
        ecdsaAccountFactory = new ECDSAAccountFactory(entryPoint);
    }

    function testUpgradeFromSCAToSingleOwnerMSCA() public {
        (address ownerAddr, uint256 ownerPrivateKey) = makeAddrAndKey("testUpgradeFromSCAToSingleOwnerMSCA_scaToMSCA");
        ECDSAAccount sca = ecdsaAccountFactory.createAccount(ownerAddr);
        // pre-mint assets into sca
        vm.deal(address(sca), 1 ether);
        // mint one 721
        testERC721.safeMint(address(sca), 1);
        // mint two 1155
        testERC1155.mint(address(sca), 0, 2, "");
        // mint three ERC20
        testERC20.mint(address(sca), 3);
        address newImpl = address(new SingleOwnerMSCA(entryPoint, pluginManager));

        // call from owner
        vm.startPrank(ownerAddr);
        sca.upgradeToAndCall(newImpl, abi.encodeCall(SingleOwnerMSCA.initializeSingleOwnerMSCA, (ownerAddr)));
        vm.stopPrank();
        // new account
        SingleOwnerMSCA upgradedMSCA = SingleOwnerMSCA(payable(address(sca)));
        // verify owner hasn't changed
        assertEq(upgradedMSCA.getNativeOwner(), ownerAddr);
        // verify assets
        assertEq(address(sca).balance, 1 ether);
        assertEq(testERC721.balanceOf(address(sca)), 1);
        assertEq(testERC1155.balanceOf(address(sca), 0), 2);
        assertEq(testERC20.balanceOf(address(sca)), 3);
        // new wallet can still send eth
        address recipient = vm.addr(123);
        vm.startPrank(ownerAddr);
        upgradedMSCA.execute(recipient, 100000000000000000, "");
        vm.stopPrank();
        assertEq(recipient.balance, 100000000000000000);
        assertEq(address(sca).balance, 900000000000000000);
        // send via user op
        sendNativeToken(address(sca), ownerPrivateKey);
    }

    function sendNativeToken(address senderAddr, uint256 senderPrivateKey) internal {
        address recipientAddr = makeAddr("sendNativeToken");
        vm.deal(senderAddr, 1 ether);

        uint256 acctNonce = entryPoint.getNonce(senderAddr, 0);
        bytes memory executeCallData = abi.encodeWithSelector(
            bytes4(keccak256("execute(address,uint256,bytes)")), recipientAddr, 100000000000, "0x"
        );
        PackedUserOperation memory userOp = buildPartialUserOp(
            senderAddr,
            acctNonce,
            "0x",
            vm.toString(executeCallData),
            83353,
            1028650,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        bytes memory signature = signUserOpHash(entryPoint, vm, senderPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
        // verify recipient balance
        assertEq(recipientAddr.balance, 100000000000);
    }
}
