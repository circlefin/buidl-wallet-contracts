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

import {Create2FailedDeployment, InvalidLength} from "../../shared/common/Errors.sol";
import {UpgradableMSCA} from "../account/UpgradableMSCA.sol";

import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {ValidationConfig} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

import {HookConfig} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

/**
 * @dev Account factory that creates the upgradeable MSCA with a set of modules to be installed.
 *      For modules that requires dependencies and optional injectedHooks, please use installModule function after
 *      the account is deployed. This factory is a staked entity at entry point. What is stake? Please refer to
 *      https://eips.ethereum.org/EIPS/eip-4337#reputation-scoring-and-throttlingbanning-for-global-entities
 * @notice We only support fully audited modules during account creation for security reasons.
 */
contract UpgradableMSCAFactory is Ownable2Step {
    using ValidationConfigLib for ValidationConfig;
    using HookConfigLib for HookConfig;
    // logic implementation

    UpgradableMSCA public immutable ACCOUNT_IMPLEMENTATION;
    IEntryPoint public immutable ENTRY_POINT;
    mapping(address => bool) public isModuleAllowed;

    event FactoryDeployed(address indexed factory, address accountImplementation, address entryPoint);
    event AccountCreated(address indexed proxy, bytes32 sender, bytes32 salt);

    error ModuleIsNotAllowed(address module);

    constructor(address _owner, address _entryPointAddr) Ownable(_owner) {
        ENTRY_POINT = IEntryPoint(_entryPointAddr);
        ACCOUNT_IMPLEMENTATION = new UpgradableMSCA(ENTRY_POINT);
        emit FactoryDeployed(address(this), address(ACCOUNT_IMPLEMENTATION), _entryPointAddr);
    }

    function setModules(address[] calldata _modules, bool[] calldata _permissions) external onlyOwner {
        if (_modules.length != _permissions.length) {
            revert InvalidLength();
        }
        for (uint256 i = 0; i < _modules.length; ++i) {
            isModuleAllowed[_modules[i]] = _permissions[i];
        }
    }

    function createAccountWithValidation(bytes32 _sender, bytes32 _salt, bytes memory _initializingData)
        public
        returns (UpgradableMSCA account)
    {
        (
            ValidationConfig _validationConfig,
            bytes4[] memory _selectors,
            bytes memory _installData,
            bytes[] memory _hooks
        ) = abi.decode(_initializingData, (ValidationConfig, bytes4[], bytes, bytes[]));
        (address counterfactualAddr, bytes32 mixedSalt) =
            _getAddressWithValidation(_sender, _salt, _validationConfig, _selectors, _installData, _hooks);
        if (counterfactualAddr.code.length > 0) {
            return UpgradableMSCA(payable(counterfactualAddr));
        }
        account = UpgradableMSCA(
            payable(
                new ERC1967Proxy{salt: mixedSalt}(
                    address(ACCOUNT_IMPLEMENTATION),
                    abi.encodeCall(
                        UpgradableMSCA.initializeWithValidation, (_validationConfig, _selectors, _installData, _hooks)
                    )
                )
            )
        );
        if (address(account) != counterfactualAddr) {
            revert Create2FailedDeployment();
        }
        emit AccountCreated(counterfactualAddr, _sender, _salt);
    }

    function getAddressWithValidation(bytes32 _sender, bytes32 _salt, bytes memory _initializingData)
        public
        view
        returns (address addr, bytes32 mixedSalt)
    {
        (
            ValidationConfig _validationConfig,
            bytes4[] memory _selectors,
            bytes memory _installData,
            bytes[] memory _hooks
        ) = abi.decode(_initializingData, (ValidationConfig, bytes4[], bytes, bytes[]));
        return _getAddressWithValidation(_sender, _salt, _validationConfig, _selectors, _installData, _hooks);
    }

    /**
     * Add stake for this entity.
     * @notice This method can also carry eth value to add to the current stake.
     * @param _unstakeDelaySec - the unstake delay for this entity. Can only be increased.
     */
    function addStake(uint32 _unstakeDelaySec) public payable onlyOwner {
        ENTRY_POINT.addStake{value: msg.value}(_unstakeDelaySec);
    }

    /**
     * Unlock the stake, in order to withdraw it.
     * @notice This entity can't serve requests once unlocked, until it calls addStake again.
     */
    function unlockStake() public onlyOwner {
        ENTRY_POINT.unlockStake();
    }

    /**
     * Withdraw the entire entity's stake.
     * @notice stake must be unlocked first (and then wait for the unstakeDelay to be over).
     * @param _withdrawAddress the address to send withdrawn value.
     */
    function withdrawStake(address payable _withdrawAddress) public onlyOwner {
        ENTRY_POINT.withdrawStake(_withdrawAddress);
    }

    function _getAddressWithValidation(
        bytes32 _sender,
        bytes32 _salt,
        ValidationConfig _validationConfig,
        bytes4[] memory _selectors,
        bytes memory _installData,
        bytes[] memory _hooks
    ) internal view returns (address addr, bytes32 mixedSalt) {
        address module = _validationConfig.module();
        if (!isModuleAllowed[module]) {
            revert ModuleIsNotAllowed(module);
        }
        for (uint256 i = 0; i < _hooks.length; ++i) {
            address hookModule;
            bytes memory hook = _hooks[i];
            if (hook.length < 20) {
                revert ModuleIsNotAllowed(hookModule);
            }
            // Skips the first 32 bytes that represent the length, then loads the next word
            // Shifts the loaded 32 bytes to the right by 12 bytes to retrieve the address
            // solhint-disable-next-line no-inline-assembly
            assembly ("memory-safe") {
                hookModule := shr(96, mload(add(hook, 0x20)))
            }
            if (!isModuleAllowed[hookModule]) {
                revert ModuleIsNotAllowed(hookModule);
            }
        }
        mixedSalt = keccak256(abi.encodePacked(_sender, _salt));
        bytes32 code = keccak256(
            abi.encodePacked(
                type(ERC1967Proxy).creationCode,
                abi.encode(
                    address(ACCOUNT_IMPLEMENTATION),
                    abi.encodeCall(
                        UpgradableMSCA.initializeWithValidation, (_validationConfig, _selectors, _installData, _hooks)
                    )
                )
            )
        );
        addr = Create2.computeAddress(mixedSalt, code, address(this));
        return (addr, mixedSalt);
    }
}
