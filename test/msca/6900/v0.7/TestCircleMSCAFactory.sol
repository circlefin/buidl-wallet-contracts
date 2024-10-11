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

import {Create2FailedDeployment, InvalidLength} from "../../../../src/msca/6900/shared/common/Errors.sol";
import "./TestCircleMSCA.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/utils/Create2.sol";

/**
 * @dev Only for testing purpose. Account factory that creates the TestCircleMSCA with a set of plugins to be installed.
 *      For plugins that requires dependencies and optional injectedHooks, please use installPlugin function after
 *      the account is deployed.
 */
contract TestCircleMSCAFactory is Ownable {
    // logic implementation
    TestCircleMSCA public immutable accountImplementation;
    IEntryPoint public immutable entryPoint;
    mapping(address => bool) public isPluginAllowed;

    event AccountCreated(address indexed proxy, address sender, bytes32 salt);

    error RequireAtLeastOnePluginDuringDeployment();
    error PluginIsNotAllowed(address plugin);

    constructor(address _owner, IEntryPoint _entryPoint, PluginManager _pluginManager) {
        transferOwnership(_owner);
        accountImplementation = new TestCircleMSCA(_entryPoint, _pluginManager);
        entryPoint = _entryPoint;
    }

    function setPlugins(address[] calldata _plugins, bool[] calldata _permissions) external onlyOwner {
        if (_plugins.length != _permissions.length) {
            revert InvalidLength();
        }
        for (uint256 i = 0; i < _plugins.length; ++i) {
            isPluginAllowed[_plugins[i]] = _permissions[i];
        }
    }

    /**
     * @dev Salted deterministic deployment using create2 and a specific logic UpgradableMSCA implementation.
     *      Since UpgradableMSCA is only a bare minimum account and tx/userOp (including installPlugin) is gated by
     *      either userOpValidationFunction (most of our use cases) or runtimeValidationFunction,
     *      we require the user to install at least one plugin (e.g. ACL) that can provide validationFunction during
     * account deployment.
     *      No dependencies or hooks can be injected during this plugin installation, so for a full installation of more
     * complicated plugins,
     *      please call installPlugin via a separate tx/userOp after account deployment.
     * @param _sender sender of the account deployment tx, it could be set to owner. If you don't have the owner
     * information during account creation,
     *                please use something unique, consistent and private to yourself.
     * @param _salt salt that allows for deterministic deployment
     * @param _initializingData abi.encode(address[] plugins, bytes32[] manifestHashes, bytes[] pluginInstallData)
     */
    function createAccount(address _sender, bytes32 _salt, bytes memory _initializingData)
        public
        returns (TestCircleMSCA account)
    {
        (address[] memory _plugins, bytes32[] memory _manifestHashes, bytes[] memory _pluginInstallData) =
            abi.decode(_initializingData, (address[], bytes32[], bytes[]));
        if (
            _plugins.length == 0 || _plugins.length != _manifestHashes.length
                || _plugins.length != _pluginInstallData.length
        ) {
            revert RequireAtLeastOnePluginDuringDeployment();
        }
        (address counterfactualAddr, bytes32 mixedSalt) =
            _getAddress(_sender, _salt, _plugins, _manifestHashes, _pluginInstallData);
        if (counterfactualAddr.code.length > 0) {
            return TestCircleMSCA(payable(counterfactualAddr));
        }
        // only perform implementation upgrade by setting empty _data in ERC1967Proxy
        // meanwhile we also initialize proxy storage, which calls PluginManager._installPlugin directly to bypass
        // validateNativeFunction checks
        account = TestCircleMSCA(
            payable(
                new ERC1967Proxy{salt: mixedSalt}(
                    address(accountImplementation),
                    abi.encodeCall(
                        UpgradableMSCA.initializeUpgradableMSCA, (_plugins, _manifestHashes, _pluginInstallData)
                    )
                )
            )
        );
        if (address(account) != counterfactualAddr) {
            revert Create2FailedDeployment();
        }
        emit AccountCreated(counterfactualAddr, _sender, _salt);
    }

    /**
     * @dev Pre-compute the counterfactual address prior to calling createAccount.
     * @param _sender sender of the account deployment tx, it could be set to owner. If you don't have the owner
     * information during account creation,
     *                please use something unique, consistent and private to yourself.
     * @param _salt salt that allows for deterministic deployment
     * @param _initializingData abi.encode(address[] plugins, bytes32[] manifestHashes, bytes[] pluginInstallData)
     */
    function getAddress(address _sender, bytes32 _salt, bytes memory _initializingData)
        public
        view
        returns (address addr, bytes32 mixedSalt)
    {
        (address[] memory _plugins, bytes32[] memory _manifestHashes, bytes[] memory _pluginInstallData) =
            abi.decode(_initializingData, (address[], bytes32[], bytes[]));
        return _getAddress(_sender, _salt, _plugins, _manifestHashes, _pluginInstallData);
    }

    /**
     * Add stake for this entity.
     * @notice This method can also carry eth value to add to the current stake.
     * @param _unstakeDelaySec - the unstake delay for this entity. Can only be increased.
     */
    function addStake(uint32 _unstakeDelaySec) public payable onlyOwner {
        entryPoint.addStake{value: msg.value}(_unstakeDelaySec);
    }

    /**
     * Unlock the stake, in order to withdraw it.
     * @notice This entity can't serve requests once unlocked, until it calls addStake again.
     */
    function unlockStake() public onlyOwner {
        entryPoint.unlockStake();
    }

    /**
     * Withdraw the entire entity's stake.
     * @notice stake must be unlocked first (and then wait for the unstakeDelay to be over).
     * @param _withdrawAddress the address to send withdrawn value.
     */
    function withdrawStake(address payable _withdrawAddress) public onlyOwner {
        entryPoint.withdrawStake(_withdrawAddress);
    }

    /**
     * @dev Pre-compute the counterfactual address prior to calling createAccount.
     * @param _sender sender of the account deployment tx, it could be set to owner. If you don't have the owner
     * information during account creation,
     *                please use something unique, consistent and private to yourself.
     * @param _salt salt that allows for deterministic deployment
     * @param _plugins plugin addresses
     * @param _manifestHashes plugin manifest hashes
     * @param _pluginInstallData optional bytes array to be decoded and used by the plugin to setup initial plugin data
     * for MSCA.
     */
    function _getAddress(
        address _sender,
        bytes32 _salt,
        address[] memory _plugins,
        bytes32[] memory _manifestHashes,
        bytes[] memory _pluginInstallData
    ) internal view returns (address addr, bytes32 mixedSalt) {
        for (uint256 i = 0; i < _plugins.length; ++i) {
            if (!isPluginAllowed[_plugins[i]]) {
                revert PluginIsNotAllowed(_plugins[i]);
            }
        }
        mixedSalt = keccak256(abi.encodePacked(_sender, _salt));
        bytes32 code = keccak256(
            abi.encodePacked(
                type(ERC1967Proxy).creationCode,
                abi.encode(
                    address(accountImplementation),
                    abi.encodeCall(
                        UpgradableMSCA.initializeUpgradableMSCA, (_plugins, _manifestHashes, _pluginInstallData)
                    )
                )
            )
        );
        addr = Create2.computeAddress(mixedSalt, code, address(this));
        return (addr, mixedSalt);
    }
}
