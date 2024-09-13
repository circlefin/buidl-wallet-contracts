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

import "../common/Structs.sol";

library FunctionReferenceLib {
    function unpack(bytes21 frBytes) internal pure returns (FunctionReference memory) {
        return FunctionReference(address(bytes20(frBytes)), uint8(bytes1(frBytes << 160)));
    }

    function pack(FunctionReference memory functionReference) internal pure returns (bytes21) {
        return (bytes21(bytes20(functionReference.plugin)) | bytes21(uint168(functionReference.functionId)));
    }
}
