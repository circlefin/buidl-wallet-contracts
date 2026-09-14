/*
 * Copyright 2026 Circle Internet Group, Inc. All rights reserved.

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

import {InvalidLength, UnauthorizedCaller} from "../common/Errors.sol";
import {ICreate3Factory} from "./ICreate3Factory.sol";
import {Ownable, Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {CREATE3} from "solady/utils/CREATE3.sol";

/**
 * @dev Shared deterministic deployment factory using CREATE3.
 *      The deployed contract address depends only on this factory's address and the provided salt.
 *      Callers remain responsible for their own salt derivation and init code construction.
 */
contract Create3Factory is Ownable2Step, ICreate3Factory {
    error EmptyCreationCode();
    error ContractAlreadyDeployed(address deployed);
    error InvalidCaller(address caller);
    error InvalidOwner(address owner);
    error NativeValueMismatch(uint256 expected, uint256 actual);
    error RenounceOwnershipNotAllowed();

    // Tracks which contracts can consume deployment salts through this shared factory.
    mapping(address => bool) public isCallerAllowed;

    event FactoryDeployed(address indexed factory, address indexed owner);
    event CallerPermissionSet(address indexed caller, bool allowed);
    event ContractDeployed(address indexed deployed, address indexed caller, bytes32 indexed salt);

    constructor(address _owner) Ownable(_requireValidOwner(_owner)) {
        emit FactoryDeployed(address(this), _owner);
    }

    /**
     * @dev Deterministically deploys arbitrary unfunded creation code through CREATE3 for an allowed caller.
     * @param _salt salt that scopes the deterministic deployment address for this factory
     * @param _creationCode creation bytecode for the contract being deployed
     */
    function deploy(bytes32 _salt, bytes memory _creationCode) external override returns (address deployed) {
        deployed = _deploy(0, _salt, _creationCode);
    }

    /**
     * @dev Deterministically deploys arbitrary creation code through CREATE3 for an allowed caller.
     * @param _value native token value to forward to the deployed contract's constructor
     * @param _salt salt that scopes the deterministic deployment address for this factory
     * @param _creationCode creation bytecode for the contract being deployed
     */
    function deploy(uint256 _value, bytes32 _salt, bytes memory _creationCode)
        external
        payable
        returns (address deployed)
    {
        deployed = _deploy(_value, _salt, _creationCode);
    }

    /**
     * @dev Shared deployment path for both unfunded and value-forwarding CREATE3 deployments.
     */
    function _deploy(uint256 _value, bytes32 _salt, bytes memory _creationCode) internal returns (address deployed) {
        if (!isCallerAllowed[msg.sender]) {
            revert UnauthorizedCaller();
        }
        if (msg.value != _value) {
            revert NativeValueMismatch(_value, msg.value);
        }
        if (_creationCode.length == 0) {
            revert EmptyCreationCode();
        }

        // Predict first so we can fail cleanly if this salt has already been consumed.
        deployed = CREATE3.predictDeterministicAddress(_salt);
        if (deployed.code.length > 0) {
            revert ContractAlreadyDeployed(deployed);
        }

        deployed = CREATE3.deployDeterministic(_value, _creationCode, _salt);
        emit ContractDeployed(deployed, msg.sender, _salt);
    }

    /**
     * @dev Pre-computes the deterministic deployment address for a CREATE3 salt.
     * @param _salt salt that scopes the deterministic deployment address for this factory
     */
    function getAddress(bytes32 _salt) external view override returns (address predicted) {
        predicted = CREATE3.predictDeterministicAddress(_salt);
    }

    /**
     * @dev Updates which callers can deploy through this shared factory.
     * @param _callers caller addresses to update
     * @param _permissions allowlist flags corresponding 1:1 with `_callers`
     */
    function setCallers(address[] calldata _callers, bool[] calldata _permissions) external onlyOwner {
        if (_callers.length != _permissions.length) {
            revert InvalidLength();
        }

        for (uint256 i = 0; i < _callers.length; ++i) {
            if (_callers[i] == address(0)) {
                revert InvalidCaller(_callers[i]);
            }
            if (isCallerAllowed[_callers[i]] == _permissions[i]) {
                continue;
            }
            isCallerAllowed[_callers[i]] = _permissions[i];
            emit CallerPermissionSet(_callers[i], _permissions[i]);
        }
    }

    /**
     * @dev Ownership must remain governed so caller permissions can be updated over time.
     */
    function renounceOwnership() public pure override {
        revert RenounceOwnershipNotAllowed();
    }

    function _requireValidOwner(address _owner) private pure returns (address) {
        if (_owner == address(0)) {
            revert InvalidOwner(_owner);
        }
        return _owner;
    }
}
