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

address constant ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

// Use address(0) if unknown or deploying a new version of a contract.
address constant PLUGIN_MANAGER_ADDRESS = 0xBc17c439278c4E64C333beE4A890DE6d1f862dDb;
address constant UPGRADABLE_MSCA_FACTORY_ADDRESS = 0x3e6b66A72B76850c372FBDf29f53268ad636B320;
address constant SINGLE_OWNER_PLUGIN_ADDRESS = 0x7af5E9DBe3e50F023a5b99f44002697cF8e1de2e;
address constant COLD_STORAGE_ADDRESS_BOOK_PLUGIN_ADDRESS = 0x3c95978Af08B6B2Fd82659B393be86AfB4bd3D6F;
address constant WEIGHTED_MULTISIG_PLUGIN_ADDRESS = 0x5a2262d58eB72B84701D6efBf6bB6586C793A65b;
address constant DEFAULT_TOKEN_CALLBACK_PLUGIN_ADDRESS = 0x03431Fb00fB2e26b5bC502DFeF8dA30E1C8643b8;

address constant PAYMASTER_ADDRESS = 0x36058Cc257967db1912FC276F9CBEC072CD572cb;
address constant PAYMASTER_PROXY_ADDRESS = 0x03dF76C8c30A88f424CF3CBBC36A1Ca02763103b;
