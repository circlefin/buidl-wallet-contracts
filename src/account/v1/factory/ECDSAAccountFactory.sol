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

import {ECDSAAccount, IEntryPoint} from "../ECDSAAccount.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

/**
 * @dev Account factory that creates the upgradeable account signed and verified by ECDSA.
 */
contract ECDSAAccountFactory {
    event AccountCreated(address indexed proxy, address indexed owner);

    // logic implementation
    ECDSAAccount public immutable ACCOUNT_IMPLEMENTATION;

    constructor(IEntryPoint _entryPoint) {
        ACCOUNT_IMPLEMENTATION = new ECDSAAccount(_entryPoint);
    }

    /**
     * @dev Salted deterministic deployment using create2 and a specific logic UpgradeableECDSAAccount implementation.
     * Use index 0 in salt that allows to deploy only one account from the same owner.
     * @param _owner owner (e.g. EOA) of the account
     */
    function createAccount(address _owner) public returns (ECDSAAccount account) {
        // use this as salt
        uint256 index = 0;
        bytes32 salt = keccak256(abi.encodePacked(_owner, index));
        return createAccount(_owner, salt);
    }

    /**
     * @dev Pre-compute the counterfactual address prior to calling createAccount.
     * Use index 0 in salt that allows to deploy only one account from the same owner.
     * @param _owner owner (e.g. EOA) of the account
     */
    function getAddress(address _owner) public view returns (address) {
        uint256 index = 0;
        bytes32 salt = keccak256(abi.encodePacked(_owner, index));
        return getAddress(_owner, salt);
    }

    /**
     * @dev Salted deterministic deployment using create2 and a specific logic UpgradeableECDSAAccount implementation.
     * index could be part of the salt if the owner wants to control multiple accounts from the same owner key.
     * @param _owner owner (e.g. EOA) of the account
     * @param _salt extra salt (e.g. using owner and index) that allows for deterministic deployment
     */
    function createAccount(address _owner, bytes32 _salt) public returns (ECDSAAccount account) {
        address addr = getAddress(_owner, _salt);
        if (addr.code.length > 0) {
            return ECDSAAccount(payable(addr));
        }

        // initializes the upgradeable proxy with the initial UpgradeableECDSAAccount logic implementation
        // create2 is called by specifying salt option
        // cast to UpgradeableECDSAAccount
        account = ECDSAAccount(
            payable(
                new ERC1967Proxy{salt: _salt}(
                    address(ACCOUNT_IMPLEMENTATION), abi.encodeCall(ECDSAAccount.initialize, (_owner))
                )
            )
        );
        emit AccountCreated(address(account), _owner);
    }

    /**
     * @dev Pre-compute the counterfactual address prior to calling createAccount.
     * @param _owner owner (e.g. EOA) of the account
     * @param _salt extra salt (e.g. using owner and index) that allows for deterministic deployment
     */
    function getAddress(address _owner, bytes32 _salt) public view returns (address) {
        bytes32 code = keccak256(
            abi.encodePacked(
                type(ERC1967Proxy).creationCode,
                abi.encode(address(ACCOUNT_IMPLEMENTATION), abi.encodeCall(ECDSAAccount.initialize, (_owner)))
            )
        );
        // call computeAddress(salt, bytecodeHash, address(this))
        // address(this) is the deployer address
        return Create2.computeAddress(_salt, code);
    }
}
