import { ethers } from "hardhat";
import type { FHEToken } from "../../types";
import type { FHEToken__factory } from "../../types";
import type { TestERC20 } from "../../types";
import type { TestERC20__factory } from "../../types";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

export async function deployFHETokenFixture(owner: HardhatEthersSigner) {
  const INITIAL_SUPPLY = ethers.parseUnits("1000000", 6);

  const TestERC20Factory = (await ethers.getContractFactory("TestERC20")) as TestERC20__factory;
  const underlying = (await TestERC20Factory.deploy("Test Token", "TST", INITIAL_SUPPLY)) as TestERC20;

  // Deploy FHEToken with initial supply
  const FHETokenFactory = (await ethers.getContractFactory("FHEToken")) as FHEToken__factory;
  const FHEToken = (await FHETokenFactory.deploy(
    "Confidential Token",
    "CTKN",
    "https://example.com/token",
    underlying,
  )) as FHEToken;

  const FHETokenAddress = await FHEToken.getAddress();

  return {
    FHEToken,
    FHETokenAddress,
    underlying,
  };
}
