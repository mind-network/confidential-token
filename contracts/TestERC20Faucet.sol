// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @dev Simple faucet that dispenses a fixed amount of TestERC20 per claim.
contract TestERC20Faucet is Ownable {
    using SafeERC20 for IERC20;

    IERC20 public immutable token;
    uint256 public amount;

    event Claimed(address indexed account, uint256 amount);
    event AmountUpdated(uint256 amount);
    event Withdrawn(address indexed to, uint256 amount);

    constructor(address token_, uint256 amount_, address owner_) Ownable(owner_) {
        require(token_ != address(0), "Faucet: token is zero");
        token = IERC20(token_);
        amount = amount_;
    }

    function claim() external {
        uint256 transferAmount = amount;
        require(transferAmount > 0, "Faucet: amount is zero");
        token.safeTransfer(msg.sender, transferAmount);
        emit Claimed(msg.sender, transferAmount);
    }

    function setAmount(uint256 newAmount) external onlyOwner {
        amount = newAmount;
        emit AmountUpdated(newAmount);
    }

    function withdraw(address to, uint256 amount_) external onlyOwner {
        token.safeTransfer(to, amount_);
        emit Withdrawn(to, amount_);
    }
}
