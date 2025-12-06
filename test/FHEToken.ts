import { FhevmType } from "@fhevm/hardhat-plugin";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { expect } from "chai";
import { ethers, fhevm } from "hardhat";
import { FHEToken, TestERC20 } from "../types";

describe("FHEToken", function () {
  const TOKEN_URI = "ipfs://cwtt";
  const INITIAL_SUPPLY = ethers.parseUnits("1000000", 6);
  const WRAP_AMOUNT = ethers.parseUnits("1000", 6);
  const TRANSFER_AMOUNT = ethers.parseUnits("250", 6);
  const UNWRAP_AMOUNT = ethers.parseUnits("400", 6);

  let owner: HardhatEthersSigner;
  let alice: HardhatEthersSigner;
  let bob: HardhatEthersSigner;
  let underlying: TestERC20;
  let token: FHEToken;
  let tokenAddress: string;

  before(async function () {
    [owner, alice, bob] = await ethers.getSigners();
  });

  beforeEach(async function () {
    if (!fhevm.isMock) {
      console.warn(`This hardhat test suite cannot run on Sepolia Testnet`);
      this.skip();
    }

    underlying = (await ethers.deployContract("TestERC20", [
      "Test Token",
      "TST",
      INITIAL_SUPPLY,
    ])) as TestERC20;

    token = (await ethers.deployContract("FHEToken", [
      "Confidential Token",
      "CTKN",
      TOKEN_URI,
      await underlying.getAddress(),
    ])) as FHEToken;

    tokenAddress = await token.getAddress();
  });

  it("initializes metadata and underlying settings", async function () {
    expect(await token.name()).to.equal("Confidential Token");
    expect(await token.symbol()).to.equal("CTKN");
    expect(await token.contractURI()).to.equal(TOKEN_URI);
    expect(await token.decimals()).to.equal(6);
    expect(await token.rate()).to.equal(1);
    expect(await token.underlying()).to.equal(await underlying.getAddress());
    expect(await underlying.balanceOf(owner.address)).to.equal(INITIAL_SUPPLY);
  });

  it("wraps underlying tokens and updates confidential balance", async function () {
    await underlying.connect(owner).approve(tokenAddress, WRAP_AMOUNT);
    await token.wrap(owner.address, WRAP_AMOUNT);

    const ownerBalanceHandle = await token.confidentialBalanceOf(owner.address);
    const decryptedBalance = await fhevm.userDecryptEuint(
      FhevmType.euint64,
      ownerBalanceHandle,
      tokenAddress,
      owner,
    );

    expect(decryptedBalance).to.equal(WRAP_AMOUNT);
    expect(await underlying.balanceOf(owner.address)).to.equal(INITIAL_SUPPLY - WRAP_AMOUNT);
    expect(await underlying.balanceOf(tokenAddress)).to.equal(WRAP_AMOUNT);
  });

  it("supports confidential transfers between users", async function () {
    await underlying.connect(owner).approve(tokenAddress, WRAP_AMOUNT);
    await token.wrap(owner.address, WRAP_AMOUNT);

    const encryptedTransfer = await fhevm
      .createEncryptedInput(tokenAddress, owner.address)
      .add64(Number(TRANSFER_AMOUNT))
      .encrypt();

    await token
      .connect(owner)
      [
        "confidentialTransfer(address,bytes32,bytes)"
      ](alice.address, encryptedTransfer.handles[0], encryptedTransfer.inputProof);

    const ownerBalanceHandle = await token.confidentialBalanceOf(owner.address);
    const aliceBalanceHandle = await token.confidentialBalanceOf(alice.address);

    const ownerBalance = await fhevm.userDecryptEuint(FhevmType.euint64, ownerBalanceHandle, tokenAddress, owner);
    const aliceBalance = await fhevm.userDecryptEuint(FhevmType.euint64, aliceBalanceHandle, tokenAddress, alice);

    expect(ownerBalance).to.equal(WRAP_AMOUNT - TRANSFER_AMOUNT);
    expect(aliceBalance).to.equal(TRANSFER_AMOUNT);
  });

  it("unwraps wrapped tokens back into the underlying asset", async function () {
    await underlying.connect(owner).approve(tokenAddress, WRAP_AMOUNT);
    await token.wrap(owner.address, WRAP_AMOUNT);

    const encryptedUnwrap = await fhevm
      .createEncryptedInput(tokenAddress, owner.address)
      .add64(Number(UNWRAP_AMOUNT))
      .encrypt();

    const unwrapTx = await token
      .connect(owner)
      [
        "unwrap(address,address,bytes32,bytes)"
      ](owner.address, owner.address, encryptedUnwrap.handles[0], encryptedUnwrap.inputProof);
    const unwrapReceipt = await unwrapTx.wait();

    if (!unwrapReceipt) {
      throw new Error("unwrap transaction did not produce a receipt");
    }

    const events = await token.queryFilter(
      token.filters.UnwrapRequested(owner.address),
      unwrapReceipt.blockNumber,
      unwrapReceipt.blockNumber,
    );
    const unwrapHandle = events[0]?.args?.amount as string | undefined;

    if (!unwrapHandle) {
      throw new Error("UnwrapRequested event not found");
    }
    const { clearValues, decryptionProof } = await fhevm.publicDecrypt([unwrapHandle]);
    const clearUnwrapAmount = clearValues[unwrapHandle] as bigint;

    await token.finalizeUnwrap(unwrapHandle, clearUnwrapAmount, decryptionProof);

    const ownerBalanceHandle = await token.confidentialBalanceOf(owner.address);
    const decryptedBalance = await fhevm.userDecryptEuint(
      FhevmType.euint64,
      ownerBalanceHandle,
      tokenAddress,
      owner,
    );

    expect(decryptedBalance).to.equal(WRAP_AMOUNT - clearUnwrapAmount);
    expect(await underlying.balanceOf(owner.address)).to.equal(INITIAL_SUPPLY - (WRAP_AMOUNT - clearUnwrapAmount));
    expect(await underlying.balanceOf(tokenAddress)).to.equal(WRAP_AMOUNT - clearUnwrapAmount);
  });
});
