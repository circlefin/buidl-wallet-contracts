/**
 * Copyright 2024 Circle Internet Group, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
pragma solidity 0.8.24;

import {ICreate3Factory} from "../../../../../factory/ICreate3Factory.sol";
import {InvalidInitializationInput} from "../../../shared/common/Errors.sol";
import {SingleOwnerMSCA} from "../../account/semi/SingleOwnerMSCA.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {Ownable, Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @dev Account factory that creates the semi-MSCA that enshrines single owner into the account storage.
 *      No plugin installation is required during account creation.
 */
contract SingleOwnerMSCAFactory is Ownable2Step {
    error InvalidFactoryOwner(address owner);
    error InvalidAccountImplementation(address implementation);
    error InvalidCreate3Factory(address factory);
    error InvalidWithdrawAddress(address withdrawAddress);
    error RenounceOwnershipNotAllowed();
    error AccountAlreadyDeployed(address account);
    error UnexpectedDeployedAddress(address expected, address actual);

    // logic implementation
    SingleOwnerMSCA public immutable ACCOUNT_IMPLEMENTATION;
    ICreate3Factory public immutable CREATE3_FACTORY;
    IEntryPoint public immutable ENTRY_POINT;
    bytes32 public constant FACTORY_FAMILY_NAMESPACE = keccak256("circle.msca.single-owner");

    event FactoryDeployed(
        address indexed factory, address accountImplementation, address create3Factory, bytes32 factoryFamilyNamespace
    );
    event AccountCreated(address indexed proxy, address sender, bytes32 salt);

    /**
     * @dev Salted deterministic deployment using the shared Create3Factory and a specific logic
     *      SingleOwnerMSCA implementation.
     *      This factory is a staked EntryPoint entity because account creation now depends on mutable shared state in
     *      Create3Factory.
     *      Tx/userOp is either gated by userOpValidationFunction or runtimeValidationFunction, and SingleOwnerMSCA
     *      is a minimum account with a pre built-in owner validation, so we do not require the user to install any
     * plugins
     *      during the deployment. No hooks can be injected during the account deployment, so for a future installation
     *      of more complicated plugins, please call installPlugin via a separate tx/userOp after account deployment.
     */
    constructor(address _owner, address _singleOwnerMSCAImplAddr, address _create3FactoryAddr)
        Ownable(_requireValidOwner(_owner))
    {
        if (_singleOwnerMSCAImplAddr == address(0)) {
            revert InvalidAccountImplementation(_singleOwnerMSCAImplAddr);
        }
        if (_create3FactoryAddr == address(0)) {
            revert InvalidCreate3Factory(_create3FactoryAddr);
        }

        ACCOUNT_IMPLEMENTATION = SingleOwnerMSCA(payable(_singleOwnerMSCAImplAddr));
        CREATE3_FACTORY = ICreate3Factory(_create3FactoryAddr);
        ENTRY_POINT = ACCOUNT_IMPLEMENTATION.ENTRY_POINT();
        emit FactoryDeployed(
            address(this), address(ACCOUNT_IMPLEMENTATION), _create3FactoryAddr, FACTORY_FAMILY_NAMESPACE
        );
    }

    /**
     * @dev Salted deterministic deployment using the shared Create3Factory and a specific logic
     *      SingleOwnerMSCA implementation.
     *      Tx/userOp is either gated by userOpValidationFunction or runtimeValidationFunction, and SingleOwnerMSCA
     *      is a minimum account with a pre built-in owner validation, so we do not require the user to install any
     * plugins
     *      during the deployment. No hooks can be injected during the account deployment, so for a future installation
     *      of more complicated plugins, please call installPlugin via a separate tx/userOp after account deployment.
     * @param _sender sender of the account deployment tx, it could be set to owner. If you don't have the owner
     * information during account creation,
     *                please use something unique, consistent and private to yourself. In the context of single owner
     * semi-MSCA, this field is mostly
     *                preserved as a legacy compatibility input because it has historically contributed to the
     *                counterfactual address derivation alongside owner and salt.
     * @param _salt salt that allows for deterministic deployment
     * @param _initializingData abi.encode(address), address should not be zero
     */
    function createAccount(address _sender, bytes32 _salt, bytes memory _initializingData)
        public
        returns (SingleOwnerMSCA account)
    {
        address owner = abi.decode(_initializingData, (address));
        (address counterfactualAddr, bytes32 mixedSalt) = _getAddress(_sender, _salt, owner);
        if (counterfactualAddr.code.length > 0) {
            revert AccountAlreadyDeployed(counterfactualAddr);
        }
        bytes memory creationCode = _getCreationCode(owner);
        // Create3Factory.deploy either returns the deployed address or reverts if deployment fails.
        account = SingleOwnerMSCA(payable(CREATE3_FACTORY.deploy(mixedSalt, creationCode)));
        if (address(account) != counterfactualAddr) {
            revert UnexpectedDeployedAddress(counterfactualAddr, address(account));
        }
        emit AccountCreated(counterfactualAddr, _sender, _salt);
    }

    /**
     * @dev Pre-compute the counterfactual address prior to calling createAccount.
     *      After decoding, owner is used in salt, byteCodeHash and func init call to minimize the front-running risk.
     * @param _sender sender of the account deployment tx, it could be set to owner. If you don't have the owner
     * information during account creation,
     *                please use something unique, consistent and private to yourself. In the context of single owner
     * semi-MSCA, this field is mostly
     *                preserved as a legacy compatibility input because it has historically contributed to the
     *                counterfactual address derivation alongside owner and salt.
     * @param _salt salt that allows for deterministic deployment
     * @param _initializingData abi.encode(address), address should not be zero
     */
    function getAddress(address _sender, bytes32 _salt, bytes memory _initializingData)
        public
        view
        returns (address addr, bytes32 mixedSalt)
    {
        address owner = abi.decode(_initializingData, (address));
        return _getAddress(_sender, _salt, owner);
    }

    /**
     * @dev Pre-compute the counterfactual address prior to calling createAccount.
     *      After decoding, owner is used in salt, byteCodeHash and func init call to minimize the front-running risk.
     * @param _sender sender of the account deployment tx, it could be set to owner. If you don't have the owner
     * information during account creation,
     *                please use something unique, consistent and private to yourself. In the context of single owner
     * semi-MSCA, this field is mostly
     *                preserved as a legacy compatibility input because it has historically contributed to the
     *                counterfactual address derivation alongside owner and salt.
     * @param _salt salt that allows for deterministic deployment
     * @param _owner owner of the semi MSCA
     */
    function _getAddress(address _sender, bytes32 _salt, address _owner)
        internal
        view
        returns (address addr, bytes32 mixedSalt)
    {
        if (_owner == address(0)) {
            revert InvalidInitializationInput();
        }
        mixedSalt = keccak256(abi.encode(FACTORY_FAMILY_NAMESPACE, _sender, _owner, _salt));
        addr = CREATE3_FACTORY.getAddress(mixedSalt);
        return (addr, mixedSalt);
    }

    /**
     * @dev Add stake for this entity.
     * @notice This method can also carry eth value to add to the current stake.
     * @param _unstakeDelaySec the unstake delay for this entity. Can only be increased.
     */
    function addStake(uint32 _unstakeDelaySec) public payable onlyOwner {
        ENTRY_POINT.addStake{value: msg.value}(_unstakeDelaySec);
    }

    /**
     * @dev Unlock the stake, in order to withdraw it.
     * @notice This entity can't serve requests once unlocked, until it calls addStake again.
     */
    function unlockStake() public onlyOwner {
        ENTRY_POINT.unlockStake();
    }

    /**
     * @dev Withdraw the entire entity's stake.
     * @notice stake must be unlocked first (and then wait for the unstakeDelay to be over).
     * @param _withdrawAddress the address to send withdrawn value.
     */
    function withdrawStake(address payable _withdrawAddress) public onlyOwner {
        if (_withdrawAddress == address(0)) {
            revert InvalidWithdrawAddress(_withdrawAddress);
        }
        ENTRY_POINT.withdrawStake(_withdrawAddress);
    }

    /**
     * @dev Ownership must remain governed so stake lifecycle management is never stranded.
     */
    function renounceOwnership() public pure override {
        revert RenounceOwnershipNotAllowed();
    }

    function _getCreationCode(address _owner) internal view returns (bytes memory creationCode) {
        creationCode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(
                address(ACCOUNT_IMPLEMENTATION), abi.encodeCall(SingleOwnerMSCA.initializeSingleOwnerMSCA, (_owner))
            )
        );
    }

    function _requireValidOwner(address _owner) private pure returns (address) {
        if (_owner == address(0)) {
            revert InvalidFactoryOwner(_owner);
        }
        return _owner;
    }
}
