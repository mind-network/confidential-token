// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @dev Simple ERC20 used for local testing of the FHEToken wrapper.
contract TestERC20 is ERC20 {
    uint8 private constant _DECIMALS = 6;

    constructor(string memory name_, string memory symbol_, uint256 initialSupply) ERC20(name_, symbol_) {
        _mint(msg.sender, initialSupply);
    }

    function decimals() public pure override returns (uint8) {
        return _DECIMALS;
    }

    /// @dev Convenience mint hook for tests; intentionally unrestricted.
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
