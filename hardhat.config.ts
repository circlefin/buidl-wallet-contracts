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
import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@openzeppelin/hardhat-upgrades";
import "@nomicfoundation/hardhat-foundry";
import "@nomiclabs/hardhat-ethers";
import "@nomiclabs/hardhat-etherscan";
import 'hardhat-deploy';

// deployment
const privateKey = process.env.DEPLOYER_PRIVATE_KEY ?? ``

function getNetwork (url: string): { url: string, accounts: [ privateKey: string ] } {
  return {
    url,
    accounts: [privateKey],
  }
}

function getNetworkFromInfura (name: string): { url: string, accounts: [ privateKey: string ] } {
  return getNetwork(`https://${name}.infura.io/v3/${process.env.INFURA_API_KEY}`)
}

function getNetworkFromAlchemy (name: string): { url: string, accounts: [ privateKey: string ] } {
  return getNetwork(`https://${name}.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}`)
}

// https://docs.soliditylang.org/en/latest/ir-breaking-changes.html#solidity-ir-based-codegen-changes
const optimizedCompilerSettings = {
  version: '0.8.24',
  settings: {
    optimizer: { enabled: true, runs: 1000000 },
    viaIR: true
  }
}

const config: HardhatUserConfig = {
  solidity: {
    compilers: [{
      version: '0.8.24',
      settings: {
        optimizer: { enabled: true, runs: 1000000 }
      },
    }],
    overrides: {
      'src/paymaster/permissioned/SponsorPaymaster.sol': optimizedCompilerSettings
    }
  },
  namedAccounts: {
    // default deployer
    deployer: {
      default: process.env.DEPLOYER_ADDRESS ?? ``
    },
  },
  networks: {
    dev: { url: 'http://localhost:8545' },
    sepolia: getNetworkFromAlchemy('eth-sepolia'),
    mainnet: getNetworkFromAlchemy('eth-mainnet'),
    amoy: getNetworkFromAlchemy('polygon-amoy'),
    polygon: getNetworkFromAlchemy('polygon-mainnet'),
    arbitrum: getNetworkFromAlchemy('arb-mainnet'),
    arbsepolia: getNetworkFromAlchemy('arb-sepolia')
  },
  etherscan: {
    // change to polygonscan for polygon
    apiKey: process.env.ETHERSCAN_API_KEY
  }
};

export default config;
