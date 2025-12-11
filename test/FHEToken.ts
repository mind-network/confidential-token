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
  const EIP712_RESOURCE = "demo-payment";

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

  async function confidentialBalanceOrZero(address: string, signer: HardhatEthersSigner) {
    const handle = await token.confidentialBalanceOf(address);
    if (handle === ethers.ZeroHash) return 0n;
    return fhevm.userDecryptEuint(FhevmType.euint64, handle, tokenAddress, signer);
  }

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

  it("executes a confidential transfer via EIP-712 authorization relayed by another account", async function () {
    await underlying.connect(owner).approve(tokenAddress, WRAP_AMOUNT);
    await token.wrap(alice.address, WRAP_AMOUNT);

    const aliceBalanceBefore = await confidentialBalanceOrZero(alice.address, alice);
    const bobBalanceBefore = await confidentialBalanceOrZero(bob.address, bob);

    const encryptedTransfer = await fhevm
      .createEncryptedInput(tokenAddress, owner.address)
      .add64(Number(TRANSFER_AMOUNT))
      .encrypt();

    const now = (await ethers.provider.getBlock("latest"))!.timestamp;
    const resourceHash = ethers.keccak256(ethers.toUtf8Bytes(EIP712_RESOURCE));
    const encryptedAmountHash = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(["bytes32"], [encryptedTransfer.handles[0]]),
    );

    const payment = {
      holder: alice.address,
      payee: bob.address,
      maxClearAmount: TRANSFER_AMOUNT,
      resourceHash,
      validAfter: BigInt(now),
      validBefore: BigInt(now + 3600),
      nonce: ethers.hexlify(ethers.randomBytes(32)),
      encryptedAmountHash,
    };

    const domain = {
      name: `${await token.name()} Confidential`,
      version: "1",
      chainId: (await ethers.provider.getNetwork()).chainId,
      verifyingContract: tokenAddress,
    };

    const types = {
      ConfidentialPayment: [
        { name: "holder", type: "address" },
        { name: "payee", type: "address" },
        { name: "maxClearAmount", type: "uint256" },
        { name: "resourceHash", type: "bytes32" },
        { name: "validAfter", type: "uint48" },
        { name: "validBefore", type: "uint48" },
        { name: "nonce", type: "bytes32" },
        { name: "encryptedAmountHash", type: "bytes32" },
      ],
    };

    const signature = await alice.signTypedData(domain, types, payment);

    await token
      .connect(owner)
      .confidentialTransferWithAuthorization(
        payment,
        encryptedTransfer.handles[0],
        encryptedTransfer.inputProof,
        signature,
      );

    const aliceBalanceAfter = await confidentialBalanceOrZero(alice.address, alice);
    const bobBalanceAfter = await confidentialBalanceOrZero(bob.address, bob);

    expect(aliceBalanceAfter).to.equal(aliceBalanceBefore - TRANSFER_AMOUNT);
    expect(bobBalanceAfter).to.equal(bobBalanceBefore + TRANSFER_AMOUNT);
  });
});
