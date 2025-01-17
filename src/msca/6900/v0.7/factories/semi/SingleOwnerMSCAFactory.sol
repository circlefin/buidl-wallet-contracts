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

import {Create2FailedDeployment, InvalidInitializationInput} from "../../../shared/common/Errors.sol";
import {SingleOwnerMSCA} from "../../account/semi/SingleOwnerMSCA.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

/**
 * @dev Account factory that creates the semi-MSCA that enshrines single owner into the account storage.
 *      No plugin installation is required during account creation.
 */
contract SingleOwnerMSCAFactory {
    // logic implementation
    SingleOwnerMSCA public immutable ACCOUNT_IMPLEMENTATION;

    event FactoryDeployed(address indexed factory, address accountImplementation);
    event AccountCreated(address indexed proxy, address sender, bytes32 salt);

    /**
     * @dev Salted deterministic deployment using create2 and a specific logic SingleOwnerMSCA implementation.
     *      Tx/userOp is either gated by userOpValidationFunction or runtimeValidationFunction, and SingleOwnerMSCA
     *      is a minimum account with a pre built-in owner validation, so we do not require the user to install any
     * plugins
     *      during the deployment. No hooks can be injected during the account deployment, so for a future installation
     *      of more complicated plugins, please call installPlugin via a separate tx/userOp after account deployment.
     */
    constructor(address _singleOwnerMSCAImplAddr) {
        ACCOUNT_IMPLEMENTATION = SingleOwnerMSCA(payable(_singleOwnerMSCAImplAddr));
        emit FactoryDeployed(address(this), address(ACCOUNT_IMPLEMENTATION));
    }

    /**
     * @dev Salted deterministic deployment using create2 and a specific logic SingleOwnerMSCA implementation.
     *      Tx/userOp is either gated by userOpValidationFunction or runtimeValidationFunction, and SingleOwnerMSCA
     *      is a minimum account with a pre built-in owner validation, so we do not require the user to install any
     * plugins
     *      during the deployment. No hooks can be injected during the account deployment, so for a future installation
     *      of more complicated plugins, please call installPlugin via a separate tx/userOp after account deployment.
     * @param _sender sender of the account deployment tx, it could be set to owner. If you don't have the owner
     * information during account creation,
     *                please use something unique, consistent and private to yourself. In the context of single owner
     * semi-MSCA, this field is mostly
     *                for consistency because we also use owner to mix the salt.
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
            return SingleOwnerMSCA(payable(counterfactualAddr));
        }
        // only perform implementation upgrade by setting empty _data in ERC1967Proxy
        // meanwhile we also initialize proxy storage, which calls PluginManager._installPlugin directly to bypass
        // validateNativeFunction checks
        account = SingleOwnerMSCA(
            payable(
                new ERC1967Proxy{salt: mixedSalt}(
                    address(ACCOUNT_IMPLEMENTATION), abi.encodeCall(SingleOwnerMSCA.initializeSingleOwnerMSCA, (owner))
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
     *      After decoding, owner is used in salt, byteCodeHash and func init call to minimize the front-running risk.
     * @param _sender sender of the account deployment tx, it could be set to owner. If you don't have the owner
     * information during account creation,
     *                please use something unique, consistent and private to yourself. In the context of single owner
     * semi-MSCA, this field is mostly
     *                for consistency because we also use owner to mix the salt.
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
     *                for consistency because we also use owner to mix the salt.
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
        mixedSalt = keccak256(abi.encodePacked(_sender, _owner, _salt));
        bytes32 code = keccak256(
            abi.encodePacked(
                type(ERC1967Proxy).creationCode,
                abi.encode(
                    address(ACCOUNT_IMPLEMENTATION), abi.encodeCall(SingleOwnerMSCA.initializeSingleOwnerMSCA, (_owner))
                )
            )
        );
        addr = Create2.computeAddress(mixedSalt, code, address(this));
        return (addr, mixedSalt);
    }
}
