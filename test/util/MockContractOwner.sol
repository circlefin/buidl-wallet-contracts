/// @notice Forked from Alchemy Multisig Plugin with permission.
/// Source:
/// https://github.com/alchemyplatform/multisig-plugin/blob/49a31d5149924a1fe9636fd0becaeb920f047cd6/test/mocks/MockContractOwner.sol
/// Modification: pragma solidity ^0.8.22 -> ^0.8.24

pragma solidity 0.8.24;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract MockContractOwner is IERC1271 {
    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function isValidSignature(bytes32 digest, bytes memory signature) public view override returns (bytes4) {
        // EOA owner of this contractOwner path
        (address signer,,) = ECDSA.tryRecover(digest, signature);
        if (signer == owner) {
            return _1271_MAGIC_VALUE;
        }
        return 0xffffffff;
    }
}
