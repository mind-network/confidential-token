// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.27;

import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import {ERC7984} from "@openzeppelin/confidential-contracts/token/ERC7984/ERC7984.sol";
import {
    ERC7984ERC20Wrapper
} from "@openzeppelin/confidential-contracts/token/ERC7984/extensions/ERC7984ERC20Wrapper.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract FHEToken is ZamaEthereumConfig, ERC7984ERC20Wrapper {
    constructor(
        string memory name_,
        string memory symbol_,
        string memory tokenURI_,
        IERC20 underlying_
    ) ERC7984(name_, symbol_, tokenURI_) ERC7984ERC20Wrapper(underlying_) {}
}
