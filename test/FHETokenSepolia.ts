import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { deployments, ethers } from "hardhat";
import { expect } from "chai";
import { FHEToken, TestERC20 } from "../types";
import { createInstance, SepoliaConfig } from "@zama-fhe/relayer-sdk/node";

describe("FHEToken (Sepolia, real relayer)", function () {
  let owner: HardhatEthersSigner;
  let alice: HardhatEthersSigner;
  let bob: HardhatEthersSigner;
  let token: FHEToken;
  let underlying: TestERC20;
  let tokenAddress: string;
  let relayerInstance: Awaited<ReturnType<typeof createInstance>>;

  const WRAP_AMOUNT = ethers.parseUnits("1000", 6);
  const TRANSFER_AMOUNT = ethers.parseUnits("300", 6);
  const UNWRAP_AMOUNT = ethers.parseUnits("150", 6);
  const MAX_RETRIES = 3;
  const BASE_DELAY_MS = 1500;

  function progress(step: string) {
    console.log(">>> ", step);
  }

  async function sleep(ms: number) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  async function userDecryptEuint64(handle: string, contractAddress: string, signer: HardhatEthersSigner) {
    const keypair = relayerInstance.generateKeypair();
    const startTimestamp = Math.floor(Date.now() / 1000).toString();
    const durationDays = "10";
    const contractAddresses = [contractAddress];
    const eip712 = relayerInstance.createEIP712(keypair.publicKey, contractAddresses, startTimestamp, durationDays);

    const signature = await signer.signTypedData(
      eip712.domain,
      { UserDecryptRequestVerification: eip712.types.UserDecryptRequestVerification },
      eip712.message,
    );

    const result = await relayerInstance.userDecrypt(
      [{ handle, contractAddress }],
      keypair.privateKey,
      keypair.publicKey,
      signature.replace("0x", ""),
      contractAddresses,
      signer.address,
      startTimestamp,
      durationDays,
    );

    return result[handle] as bigint;
  }

  async function userDecryptEuint64WithRetry(handle: string, contractAddress: string, signer: HardhatEthersSigner) {
    let delay = BASE_DELAY_MS;
    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
      try {
        return await userDecryptEuint64(handle, contractAddress, signer);
      } catch (e) {
        if (attempt === MAX_RETRIES) {
          throw e;
        }
        progress(`Relayer unavailable (attempt ${attempt}), retrying in ${delay}ms...`);
        await sleep(delay);
        delay *= 2;
      }
    }
    throw new Error("unreachable");
  }

  async function confidentialBalanceOrZero(address: string, signer: HardhatEthersSigner) {
    const handle = await token.confidentialBalanceOf(address);
    if (handle === ethers.ZeroHash) return 0n;
    return userDecryptEuint64WithRetry(handle, tokenAddress, signer);
  }

  async function publicDecryptWithRetry(handles: string[]) {
    let delay = BASE_DELAY_MS;
    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
      try {
        return await relayerInstance.publicDecrypt(handles);
      } catch (e) {
        if (attempt === MAX_RETRIES) {
          throw e;
        }
        progress(`Relayer publicDecrypt unavailable (attempt ${attempt}), retrying in ${delay}ms...`);
        await sleep(delay);
        delay *= 2;
      }
    }
    throw new Error("unreachable");
  }

  before(async function () {
    relayerInstance = await createInstance(SepoliaConfig);

    [owner, alice, bob] = await ethers.getSigners();
    console.log(`Owner: ${owner.address}`);
    console.log(`Alice: ${alice.address}`);
    console.log(`Bob: ${bob.address}`);

    try {
      const fh = await deployments.get("FHEToken");
      tokenAddress = fh.address;
      token = (await ethers.getContractAt("FHEToken", fh.address)) as FHEToken;

      const t20 = await deployments.get("TestERC20");
      underlying = (await ethers.getContractAt("TestERC20", t20.address)) as TestERC20;
    } catch (e) {
      (e as Error).message += ". Deploy with `npx hardhat deploy --network sepolia --tags TestERC20,FHEToken`.";
      throw e;
    }
  });

  it("wraps and transfers on Sepolia", async function () {
    this.timeout(6 * 60 * 1000); // give Sepolia time

    progress("Approving wrapper for underlying...");
    await (await underlying.connect(owner).approve(tokenAddress, WRAP_AMOUNT)).wait();

    progress("Fetching starting confidential balances...");
    const ownerBalanceBefore = await confidentialBalanceOrZero(owner.address, owner);
    const aliceBalanceBefore = await confidentialBalanceOrZero(alice.address, alice);
    console.log(`Owner balance before: ${ownerBalanceBefore}`);
    console.log(`Alice balance before: ${aliceBalanceBefore}`);

    progress(`Wrapping ${WRAP_AMOUNT} underlying into FHEToken...`);
    await (await token.connect(owner).wrap(owner.address, WRAP_AMOUNT)).wait();

    progress("Decrypting owner balance after wrap via relayer...");
    const ownerBalanceAfterWrap = await confidentialBalanceOrZero(owner.address, owner);
    console.log(`Owner balance after wrap: ${ownerBalanceAfterWrap}`);
    expect(ownerBalanceAfterWrap - ownerBalanceBefore).to.equal(WRAP_AMOUNT);

    progress("Creating encrypted transfer input...");
    const encryptedTransfer = await relayerInstance
      .createEncryptedInput(tokenAddress, owner.address)
      .add64(Number(TRANSFER_AMOUNT))
      .encrypt();

    progress(`Confidential transfer ${TRANSFER_AMOUNT} to alice...`);
    await (
      await token
        .connect(owner)
        [
          "confidentialTransfer(address,bytes32,bytes)"
        ](alice.address, encryptedTransfer.handles[0], encryptedTransfer.inputProof)
    ).wait();

    progress("Decrypting balances after transfer via relayer...");
    const ownerBalanceAfter = await confidentialBalanceOrZero(owner.address, owner);
    const aliceBalanceAfter = await confidentialBalanceOrZero(alice.address, alice);

    console.log(`Owner balance after: ${ownerBalanceAfter}`);
    console.log(`Alice balance after: ${aliceBalanceAfter}`);

    expect(ownerBalanceAfter).to.equal(ownerBalanceBefore + WRAP_AMOUNT - TRANSFER_AMOUNT);
    expect(aliceBalanceAfter).to.equal(aliceBalanceBefore + TRANSFER_AMOUNT);
  });

  it("executes confidential transfer via EIP-712 authorization relayed by owner", async function () {
    this.timeout(6 * 60 * 1000);

    progress("Approving wrapper for underlying (EIP-712 test)...");
    await (await underlying.connect(owner).approve(tokenAddress, WRAP_AMOUNT)).wait();

    progress("Wrapping to Alice...");
    await (await token.connect(owner).wrap(alice.address, WRAP_AMOUNT)).wait();

    progress("Reading balances before...");
    const aliceBefore = await confidentialBalanceOrZero(alice.address, alice);
    const bobBefore = await confidentialBalanceOrZero(bob.address, bob);

    progress("Creating encrypted input (owner as sender)...");
    const encryptedTransfer = await relayerInstance
      .createEncryptedInput(tokenAddress, owner.address)
      .add64(Number(TRANSFER_AMOUNT))
      .encrypt();

    const now = (await ethers.provider.getBlock("latest"))!.timestamp;
    const resourceHash = ethers.keccak256(ethers.toUtf8Bytes("sepolia-eip712"));
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

    progress("Alice signing typed data...");
    const signature = await alice.signTypedData(domain, types, payment);

    progress("Owner relays confidentialTransferWithAuthorization...");
    await (
      await token
        .connect(owner)
        .confidentialTransferWithAuthorization(
          payment,
          encryptedTransfer.handles[0],
          encryptedTransfer.inputProof,
          signature,
        )
    ).wait();

    progress("Reading balances after...");
    const aliceAfter = await confidentialBalanceOrZero(alice.address, alice);
    const bobAfter = await confidentialBalanceOrZero(bob.address, bob);

    expect(aliceAfter).to.equal(aliceBefore - TRANSFER_AMOUNT);
    expect(bobAfter).to.equal(bobBefore + TRANSFER_AMOUNT);
  });

  it("unwraps alice balance back to underlying on Sepolia", async function () {
    this.timeout(8 * 60 * 1000);

    progress("Approving wrapper for underlying (unwrap test)...");
    await (await underlying.connect(owner).approve(tokenAddress, WRAP_AMOUNT)).wait();

    progress("Reading starting balances...");
    const ownerConfBefore = await confidentialBalanceOrZero(owner.address, owner);
    const aliceConfBefore = await confidentialBalanceOrZero(alice.address, alice);
    const underlyingOwnerBefore = await underlying.balanceOf(owner.address);
    const underlyingAliceBefore = await underlying.balanceOf(alice.address);
    const underlyingTokenBefore = await underlying.balanceOf(tokenAddress);

    progress("Wrapping for unwrap test...");
    await (await token.connect(owner).wrap(owner.address, WRAP_AMOUNT)).wait();

    progress("Transferring to alice for unwrap...");
    const encryptedTransfer = await relayerInstance
      .createEncryptedInput(tokenAddress, owner.address)
      .add64(Number(TRANSFER_AMOUNT))
      .encrypt();
    await (
      await token
        .connect(owner)
        [
          "confidentialTransfer(address,bytes32,bytes)"
        ](alice.address, encryptedTransfer.handles[0], encryptedTransfer.inputProof)
    ).wait();

    const aliceConfMid = await confidentialBalanceOrZero(alice.address, alice);
    expect(aliceConfMid).to.be.greaterThanOrEqual(UNWRAP_AMOUNT);

    progress("Creating unwrap encrypted amount for alice...");
    const encryptedUnwrap = await relayerInstance
      .createEncryptedInput(tokenAddress, alice.address)
      .add64(Number(UNWRAP_AMOUNT))
      .encrypt();

    progress("Calling unwrap...");
    const unwrapTx = await token
      .connect(alice)
      [
        "unwrap(address,address,bytes32,bytes)"
      ](alice.address, alice.address, encryptedUnwrap.handles[0], encryptedUnwrap.inputProof);
    const unwrapReceipt = await unwrapTx.wait();
    if (!unwrapReceipt) {
      throw new Error("unwrap transaction did not produce a receipt");
    }
    console.log("unwrap tx hash:", unwrapReceipt.hash);

    const events = await token.queryFilter(
      token.filters.UnwrapRequested(alice.address),
      unwrapReceipt.blockNumber,
      unwrapReceipt.blockNumber,
    );
    const unwrapHandle = events[0]?.args?.amount as string | undefined;
    if (!unwrapHandle) {
      throw new Error("UnwrapRequested event not found");
    }

    progress("Public decrypting unwrap amount...");
    const { clearValues, decryptionProof } = await publicDecryptWithRetry([unwrapHandle]);
    const clearAmount = clearValues[unwrapHandle] as bigint;
    progress(`Unwrap clear amount: ${clearAmount}`);

    progress("Finalizing unwrap...");
    const unwrapFinalizeTx = await token.finalizeUnwrap(unwrapHandle, Number(clearAmount), decryptionProof);
    console.log("unwrap finalize tx hash:", unwrapFinalizeTx.hash);
    console.log("Waiting for 1 min for unwrap finalize tx to be synced between nodes...");
    await sleep(60 * 1000);

    const aliceConfAfter = await confidentialBalanceOrZero(alice.address, alice);
    const underlyingAliceAfter = await underlying.balanceOf(alice.address);
    const underlyingTokenAfter = await underlying.balanceOf(tokenAddress);

    expect(aliceConfAfter).to.equal(aliceConfMid - clearAmount);
    expect(underlyingAliceAfter - underlyingAliceBefore).to.equal(clearAmount);
    const underlyingDelta = underlyingTokenAfter - underlyingTokenBefore;
    expect(underlyingDelta).to.equal(WRAP_AMOUNT - clearAmount);
    const ownerConfAfter = await confidentialBalanceOrZero(owner.address, owner);
    expect(ownerConfAfter).to.equal(ownerConfBefore + WRAP_AMOUNT - TRANSFER_AMOUNT);
  });
});
