#!/bin/sh
# Copyright 2024 Circle Internet Group, Inc. All rights reserved.

# SPDX-License-Identifier: GPL-3.0-or-later

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

function main {
    # If the argument is empty then run both functions else only run provided function as argument $1.
    [ -z "$1" ] && { go_abigen; ts_abigen; } || $1
}

function go_abigen {
  # variables
  PROJECT_PATH="/root/buidl-wallet-contracts"
  ABIGEN="docker run -v .:$PROJECT_PATH --rm abigen abigen"

  # generate bytecode & abi json
  forge build --extra-output-files abi evm

  # build abigen docker image
  docker build -f Dockerfile.abigen -t abigen .

  # abigen
  $ABIGEN --abi $PROJECT_PATH/out/ECDSAAccountFactory.sol/ECDSAAccountFactory.abi.json --bin $PROJECT_PATH/out/ECDSAAccountFactory.sol/ECDSAAccountFactory.bin --pkg ECDSAAccountFactory --type ECDSAAccountFactory --out $PROJECT_PATH/abigen/ECDSAAccountFactory.sol/ECDSAAccountFactory.go
  $ABIGEN --abi $PROJECT_PATH/out/ECDSAAccount.sol/ECDSAAccount.abi.json --bin $PROJECT_PATH/out/ECDSAAccount.sol/ECDSAAccount.bin --pkg ECDSAAccount --type ECDSAAccount --out $PROJECT_PATH/abigen/ECDSAAccount.sol/ECDSAAccount.go
  $ABIGEN --abi $PROJECT_PATH/out/SponsorPaymaster.sol/SponsorPaymaster.abi.json --bin $PROJECT_PATH/out/SponsorPaymaster.sol/SponsorPaymaster.bin --pkg SponsorPaymaster --type SponsorPaymaster --out $PROJECT_PATH/abigen/SponsorPaymaster.sol/SponsorPaymaster.go
  $ABIGEN --abi $PROJECT_PATH/out/UpgradableMSCA.sol/UpgradableMSCA.abi.json --bin $PROJECT_PATH/out/UpgradableMSCA.sol/UpgradableMSCA.bin --pkg UpgradableMSCA --type UpgradableMSCA --out $PROJECT_PATH/abigen/UpgradableMSCA.sol/UpgradableMSCA.go
  $ABIGEN --abi $PROJECT_PATH/out/PluginManager.sol/PluginManager.abi.json --bin $PROJECT_PATH/out/PluginManager.sol/PluginManager.bin --pkg PluginManager --type PluginManager --out $PROJECT_PATH/abigen/PluginManager.sol/PluginManager.go
  $ABIGEN --abi $PROJECT_PATH/out/UpgradableMSCAFactory.sol/UpgradableMSCAFactory.abi.json --bin $PROJECT_PATH/out/UpgradableMSCAFactory.sol/UpgradableMSCAFactory.bin --pkg UpgradableMSCAFactory --type UpgradableMSCAFactory --out $PROJECT_PATH/abigen/UpgradableMSCAFactory.sol/UpgradableMSCAFactory.go
  $ABIGEN --abi $PROJECT_PATH/out/SingleOwnerMSCAFactory.sol/SingleOwnerMSCAFactory.abi.json --bin $PROJECT_PATH/out/SingleOwnerMSCAFactory.sol/SingleOwnerMSCAFactory.bin --pkg SingleOwnerMSCAFactory --type SingleOwnerMSCAFactory --out $PROJECT_PATH/abigen/SingleOwnerMSCAFactory.sol/SingleOwnerMSCAFactory.go
  $ABIGEN --abi $PROJECT_PATH/out/SingleOwnerMSCA.sol/SingleOwnerMSCA.abi.json --bin $PROJECT_PATH/out/SingleOwnerMSCA.sol/SingleOwnerMSCA.bin --pkg SingleOwnerMSCA --type SingleOwnerMSCA --out $PROJECT_PATH/abigen/SingleOwnerMSCA.sol/SingleOwnerMSCA.go
  $ABIGEN --abi $PROJECT_PATH/out/AddressBookPlugin.sol/AddressBookPlugin.abi.json --bin $PROJECT_PATH/out/AddressBookPlugin.sol/AddressBookPlugin.bin --pkg AddressBookPlugin --type AddressBookPlugin --out $PROJECT_PATH/abigen/AddressBookPlugin.sol/AddressBookPlugin.go
}

function ts_abigen {
  cd ./dist
  ../node_modules/.bin/typechain --target ethers-v5 --out-dir ./interfaces '../out/ECDSAAccount.sol/ECDSAAccount.json'
  ../node_modules/.bin/rollup ./interfaces/factories/ECDSAAccount__factory.ts --format cjs --file ./ECDSAAccount.js -c rollup.config.js --bundleConfigAsCjs
  ../node_modules/.bin/typechain --target ethers-v5 --out-dir ./interfaces '../out/ECDSAAccountFactory.sol/ECDSAAccountFactory.json'
  ../node_modules/.bin/rollup ./interfaces/factories/ECDSAAccountFactory__factory.ts --format cjs --file ./ECDSAAccountFactory.js -c rollup.config.js --bundleConfigAsCjs
  ../node_modules/.bin/typechain --target ethers-v5 --out-dir ./interfaces '../out/SponsorPaymaster.sol/SponsorPaymaster.json'
  ../node_modules/.bin/rollup ./interfaces/factories/SponsorPaymaster__factory.ts --format cjs --file ./SponsorPaymaster.js -c rollup.config.js --bundleConfigAsCjs
  ../node_modules/.bin/typechain --target ethers-v5 --out-dir ./interfaces '../out/UpgradableMSCAFactory.sol/UpgradableMSCAFactory.json'
  ../node_modules/.bin/rollup ./interfaces/factories/UpgradableMSCAFactory__factory.ts --format cjs --file ./UpgradableMSCAFactory.js -c rollup.config.js --bundleConfigAsCjs
  ../node_modules/.bin/typechain --target ethers-v5 --out-dir ./interfaces '../out/PluginManager.sol/PluginManager.json'
  ../node_modules/.bin/rollup ./interfaces/factories/PluginManager__factory.ts --format cjs --file ./PluginManager.js -c rollup.config.js --bundleConfigAsCjs
  ../node_modules/.bin/typechain --target ethers-v5 --out-dir ./interfaces '../out/UpgradableMSCA.sol/UpgradableMSCA.json'
  ../node_modules/.bin/rollup ./interfaces/factories/UpgradableMSCA__factory.ts --format cjs --file ./UpgradableMSCA.js -c rollup.config.js --bundleConfigAsCjs
  ../node_modules/.bin/typechain --target ethers-v5 --out-dir ./interfaces '../out/SingleOwnerMSCAFactory.sol/SingleOwnerMSCAFactory.json'
  ../node_modules/.bin/rollup ./interfaces/factories/SingleOwnerMSCAFactory__factory.ts --format cjs --file ./SingleOwnerMSCAFactory.js -c rollup.config.js --bundleConfigAsCjs
  ../node_modules/.bin/typechain --target ethers-v5 --out-dir ./interfaces '../out/SingleOwnerMSCA.sol/SingleOwnerMSCA.json'
  ../node_modules/.bin/rollup ./interfaces/factories/SingleOwnerMSCA__factory.ts --format cjs --file ./SingleOwnerMSCA.js -c rollup.config.js --bundleConfigAsCjs
  ../node_modules/.bin/typechain --target ethers-v5 --out-dir ./interfaces '../out/AddressBookPlugin.sol/AddressBookPlugin.json'
    ../node_modules/.bin/rollup ./interfaces/factories/AddressBookPlugin__factory.ts --format cjs --file ./AddressBookPlugin.js -c rollup.config.js --bundleConfigAsCjs
}

main "$@"
