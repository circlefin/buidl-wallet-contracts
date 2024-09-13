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

import {ValidationData} from "../../../../src/msca/6900/shared/common/Structs.sol";
import "../../../../src/msca/6900/v0.7/plugins/BasePlugin.sol";
import "../../../../src/msca/6900/v0.7/plugins/v1_0_0/acl/ISingleOwnerPlugin.sol";

/// This hook cannot be installed due to expecting being installed with hook dependencies
contract TestUserOpValidatorWithDependencyHook is BasePlugin {
    event Foo();

    function testValidatorHookFoo() external {
        emit Foo();
    }

    /**
     * @dev Pack into the serialized format as validAfter | validUntil | authorizer.
     */
    function _packValidationData(ValidationData memory data) internal pure returns (uint256) {
        return uint160(data.authorizer) | (uint256(data.validUntil) << 160) | (uint256(data.validAfter) << (160 + 48));
    }

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;
        manifest.executionFunctions = new bytes4[](1);
        // Execution functions defined in this plugin to be installed on the MSCA.
        manifest.executionFunctions[0] = this.testValidatorHookFoo.selector;
        manifest.preUserOpValidationHooks = new ManifestAssociatedFunction[](1);
        // hook is provided from an external plugin (dependency)
        manifest.preUserOpValidationHooks[0] = ManifestAssociatedFunction({
            executionSelector: this.testValidatorHookFoo.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.DEPENDENCY,
                functionId: uint8(0),
                dependencyIndex: 0
            })
        });
        manifest.dependencyInterfaceIds = new bytes4[](1);
        manifest.dependencyInterfaceIds[0] = type(ISingleOwnerPlugin).interfaceId;
        return manifest;
    }
}
