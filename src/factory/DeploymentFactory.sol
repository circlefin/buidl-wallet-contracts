/*
 * Copyright 2026 Circle Internet Group, Inc. All rights reserved.
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

import {UnauthorizedCaller} from "../common/Errors.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {CREATE3} from "solady/utils/CREATE3.sol";

/**
 * @dev Deployment factory supporting both CREATE2 and CREATE3.
 */
contract DeploymentFactory is Ownable2StepUpgradeable, UUPSUpgradeable {
    error EmptyCreationCode();
    error ContractAlreadyDeployed(address deployed);
    error InvalidOwner(address owner);
    error NativeValueMismatch(uint256 expected, uint256 actual);
    error RenounceOwnershipNotAllowed();

    bytes32 internal constant SALT_PREFIX_CREATE2 = keccak256("deployCreate2");
    bytes32 internal constant SALT_PREFIX_CREATE2_PERMISSIONLESS = keccak256("deployCreate2Permissionless");
    // CREATE3 uses CREATE2 internally (to deploy a proxy), so while the final address derivation
    // differs from raw CREATE2, we namespace the salt as defense-in-depth against any overlap
    // between the intermediate CREATE2 in solady's CREATE3 and our direct CREATE2 paths.
    bytes32 internal constant SALT_PREFIX_CREATE3 = keccak256("deployCreate3");

    /// @custom:storage-location erc7201:circle.storage.DeploymentFactory
    struct DeploymentFactoryStorage {
        address create2Deployer;
        address create3Deployer;
    }

    // keccak256(abi.encode(uint256(keccak256("circle.storage.DeploymentFactory")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant STORAGE_SLOT = 0x7f3f3b4fcf3abd1467694b77390fd6bdca5a29cb09861af6d201cad3913dff00;

    event Create2DeployerUpdated(address indexed oldDeployer, address indexed newDeployer);
    event Create3DeployerUpdated(address indexed oldDeployer, address indexed newDeployer);
    event Create2Deployed(address indexed deployed, address indexed caller, bytes32 indexed salt);
    event Create2PermissionlessDeployed(address indexed deployed, address indexed caller, bytes32 indexed salt);
    event Create3Deployed(address indexed deployed, address indexed caller, bytes32 indexed salt);

    modifier onlyCreate2Deployer() {
        if (msg.sender != _getStorage().create2Deployer) {
            revert UnauthorizedCaller();
        }
        _;
    }

    modifier onlyCreate3Deployer() {
        if (msg.sender != _getStorage().create3Deployer) {
            revert UnauthorizedCaller();
        }
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _owner) external initializer {
        if (_owner == address(0)) {
            revert InvalidOwner(_owner);
        }
        __Ownable_init(_owner);
        __UUPSUpgradeable_init();
    }

    // ========== Permissioned CREATE2 ==========

    /**
     * @dev Permissioned CREATE2 deployment. Only the designated CREATE2 deployer can call.
     * @param _salt salt that scopes the deterministic deployment address for this factory
     * @param _creationCode creation bytecode for the contract being deployed
     */
    function deployCreate2(bytes32 _salt, bytes memory _creationCode)
        external
        onlyCreate2Deployer
        returns (address deployed)
    {
        deployed = _deployCreate2(SALT_PREFIX_CREATE2, 0, _salt, _creationCode);
        emit Create2Deployed(deployed, msg.sender, _salt);
    }

    /**
     * @dev Permissioned CREATE2 deployment with native value forwarding.
     * @param _value native token value to forward to the deployed contract's constructor
     * @param _salt salt that scopes the deterministic deployment address for this factory
     * @param _creationCode creation bytecode for the contract being deployed
     */
    function deployCreate2(uint256 _value, bytes32 _salt, bytes memory _creationCode)
        external
        payable
        onlyCreate2Deployer
        returns (address deployed)
    {
        deployed = _deployCreate2(SALT_PREFIX_CREATE2, _value, _salt, _creationCode);
        emit Create2Deployed(deployed, msg.sender, _salt);
    }

    /**
     * @dev Pre-computes the deterministic deployment address for a permissioned CREATE2.
     * @param _salt salt that scopes the deterministic deployment address for this factory
     * @param _creationCode creation bytecode for the contract being deployed
     */
    function getCreate2Address(bytes32 _salt, bytes memory _creationCode) external view returns (address predicted) {
        bytes32 effectiveSalt = _namespacedSalt(SALT_PREFIX_CREATE2, _salt);
        predicted = Create2.computeAddress(effectiveSalt, keccak256(_creationCode));
    }

    // ========== Permissionless CREATE2 ==========

    /**
     * @dev Permissionless CREATE2 deployment.
     * @param _salt salt that scopes the deterministic deployment address for this factory
     * @param _creationCode creation bytecode for the contract being deployed
     */
    function deployCreate2Permissionless(bytes32 _salt, bytes memory _creationCode)
        external
        returns (address deployed)
    {
        deployed = _deployCreate2(SALT_PREFIX_CREATE2_PERMISSIONLESS, 0, _salt, _creationCode);
        emit Create2PermissionlessDeployed(deployed, msg.sender, _salt);
    }

    /**
     * @dev Permissionless CREATE2 deployment with native value forwarding.
     * @param _value native token value to forward to the deployed contract's constructor
     * @param _salt salt that scopes the deterministic deployment address for this factory
     * @param _creationCode creation bytecode for the contract being deployed
     */
    function deployCreate2Permissionless(uint256 _value, bytes32 _salt, bytes memory _creationCode)
        external
        payable
        returns (address deployed)
    {
        deployed = _deployCreate2(SALT_PREFIX_CREATE2_PERMISSIONLESS, _value, _salt, _creationCode);
        emit Create2PermissionlessDeployed(deployed, msg.sender, _salt);
    }

    /**
     * @dev Pre-computes the deterministic deployment address for a permissionless CREATE2.
     * @param _salt salt that scopes the deterministic deployment address for this factory
     * @param _creationCode creation bytecode for the contract being deployed
     */
    function getCreate2PermissionlessAddress(bytes32 _salt, bytes memory _creationCode)
        external
        view
        returns (address predicted)
    {
        bytes32 effectiveSalt = _namespacedSalt(SALT_PREFIX_CREATE2_PERMISSIONLESS, _salt);
        predicted = Create2.computeAddress(effectiveSalt, keccak256(_creationCode));
    }

    // ========== Permissioned CREATE3 ==========

    /**
     * @dev Deterministically deploys arbitrary unfunded creation code through CREATE3.
     * @param _salt salt that scopes the deterministic deployment address for this factory
     * @param _creationCode creation bytecode for the contract being deployed
     */
    function deployCreate3(bytes32 _salt, bytes memory _creationCode)
        external
        onlyCreate3Deployer
        returns (address deployed)
    {
        deployed = _deployCreate3(0, _salt, _creationCode);
        emit Create3Deployed(deployed, msg.sender, _salt);
    }

    /**
     * @dev Deterministically deploys arbitrary creation code through CREATE3.
     * @param _value native token value to forward to the deployed contract's constructor
     * @param _salt salt that scopes the deterministic deployment address for this factory
     * @param _creationCode creation bytecode for the contract being deployed
     */
    function deployCreate3(uint256 _value, bytes32 _salt, bytes memory _creationCode)
        external
        payable
        onlyCreate3Deployer
        returns (address deployed)
    {
        deployed = _deployCreate3(_value, _salt, _creationCode);
        emit Create3Deployed(deployed, msg.sender, _salt);
    }

    /**
     * @dev Pre-computes the deterministic deployment address for a CREATE3 salt.
     * @param _salt salt that scopes the deterministic deployment address for this factory
     */
    function getCreate3Address(bytes32 _salt) external view returns (address predicted) {
        bytes32 effectiveSalt = _namespacedSalt(SALT_PREFIX_CREATE3, _salt);
        predicted = CREATE3.predictDeterministicAddress(effectiveSalt);
    }

    // ========== Admin ==========

    /**
     * @dev Sets the designated deployer for the permissioned CREATE2 path.
     *      Pass address(0) to disable permissioned CREATE2 deployments.
     * @param _deployer the address authorized to call deployCreate2
     */
    function setCreate2Deployer(address _deployer) external onlyOwner {
        DeploymentFactoryStorage storage $ = _getStorage();
        address oldDeployer = $.create2Deployer;
        $.create2Deployer = _deployer;
        emit Create2DeployerUpdated(oldDeployer, _deployer);
    }

    /**
     * @dev Sets the designated deployer for the permissioned CREATE3 path.
     *      Pass address(0) to disable permissioned CREATE3 deployments.
     * @param _deployer the address authorized to call deployCreate3
     */
    function setCreate3Deployer(address _deployer) external onlyOwner {
        DeploymentFactoryStorage storage $ = _getStorage();
        address oldDeployer = $.create3Deployer;
        $.create3Deployer = _deployer;
        emit Create3DeployerUpdated(oldDeployer, _deployer);
    }

    function create2Deployer() external view returns (address) {
        return _getStorage().create2Deployer;
    }

    function create3Deployer() external view returns (address) {
        return _getStorage().create3Deployer;
    }

    /**
     * @dev Ownership must remain governed for upgrades and deployer management.
     */
    function renounceOwnership() public pure override {
        revert RenounceOwnershipNotAllowed();
    }

    // ========== Internal ==========

    function _getStorage() private pure returns (DeploymentFactoryStorage storage $) {
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            $.slot := STORAGE_SLOT
        }
    }

    function _namespacedSalt(bytes32 _prefix, bytes32 _salt) internal pure returns (bytes32) {
        return keccak256(abi.encode(_prefix, _salt));
    }

    function _deployCreate2(bytes32 _prefix, uint256 _value, bytes32 _salt, bytes memory _creationCode)
        internal
        returns (address deployed)
    {
        if (msg.value != _value) {
            revert NativeValueMismatch(_value, msg.value);
        }
        if (_creationCode.length == 0) {
            revert EmptyCreationCode();
        }

        bytes32 effectiveSalt = _namespacedSalt(_prefix, _salt);
        deployed = Create2.computeAddress(effectiveSalt, keccak256(_creationCode));
        if (deployed.code.length > 0) {
            revert ContractAlreadyDeployed(deployed);
        }

        deployed = Create2.deploy(_value, effectiveSalt, _creationCode);
    }

    function _deployCreate3(uint256 _value, bytes32 _salt, bytes memory _creationCode)
        internal
        returns (address deployed)
    {
        if (msg.value != _value) {
            revert NativeValueMismatch(_value, msg.value);
        }
        if (_creationCode.length == 0) {
            revert EmptyCreationCode();
        }

        bytes32 effectiveSalt = _namespacedSalt(SALT_PREFIX_CREATE3, _salt);
        deployed = CREATE3.predictDeterministicAddress(effectiveSalt);
        if (deployed.code.length > 0) {
            revert ContractAlreadyDeployed(deployed);
        }

        deployed = CREATE3.deployDeterministic(_value, _creationCode, effectiveSalt);
    }

    // solhint-disable-next-line no-empty-blocks
    function _authorizeUpgrade(address) internal override onlyOwner {}
}
