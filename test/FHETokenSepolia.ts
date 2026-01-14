import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { deployments, ethers } from "hardhat";
import { expect } from "chai";
import { FHEToken, FHETokenBatcher, TestERC20 } from "../types";
import { createInstance, SepoliaConfig } from "@zama-fhe/relayer-sdk/node";

describe("FHEToken (Sepolia, real relayer)", function () {
  let owner: HardhatEthersSigner;
  let alice: HardhatEthersSigner;
  let bob: HardhatEthersSigner;
  let token: FHEToken;
  let batcher: FHETokenBatcher;
  let underlying: TestERC20;
  let tokenAddress: string;
  let batcherAddress: string;
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

  async function buildDomain() {
    return {
      name: await token.name(),
      version: "1",
      chainId: (await ethers.provider.getNetwork()).chainId,
      verifyingContract: tokenAddress,
    };
  }

  async function approveAndWrapTo(recipient: string, amount: bigint, label: string) {
    progress(`Approving wrapper for underlying (${label})...`);
    await (await underlying.connect(owner).approve(tokenAddress, amount)).wait();

    progress(`Wrapping to ${recipient}...`);
    await (await token.connect(owner).wrap(recipient, amount)).wait();
  }

  async function encryptAmountForCaller(amount: bigint, caller: string) {
    return relayerInstance.createEncryptedInput(tokenAddress, caller).add64(Number(amount)).encrypt();
  }

  function buildConfidentialPayment(holder: string, payee: string, amount: bigint, resourceHash: string, now: number) {
    return {
      holder,
      payee,
      maxClearAmount: amount,
      resourceHash,
      validAfter: BigInt(now),
      validBefore: BigInt(now + 3600),
      nonce: ethers.hexlify(ethers.randomBytes(32)),
    };
  }

  function buildUnwrapAuthorization(holder: string, to: string, now: number, encryptedAmountHash: string) {
    return {
      holder,
      to,
      validAfter: BigInt(now),
      validBefore: BigInt(now + 3600),
      nonce: ethers.hexlify(ethers.randomBytes(32)),
      encryptedAmountHash,
    };
  }

  const CONFIDENTIAL_PAYMENT_TYPES = {
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

  const UNWRAP_AUTHORIZATION_TYPES = {
    UnwrapAuthorization: [
      { name: "holder", type: "address" },
      { name: "to", type: "address" },
      { name: "validAfter", type: "uint48" },
      { name: "validBefore", type: "uint48" },
      { name: "nonce", type: "bytes32" },
      { name: "encryptedAmountHash", type: "bytes32" },
    ],
  };

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
    console.log(`Decrypting confidential balance for ${address} with handle ${handle}...`);
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

      const batch = await deployments.get("FHETokenBatcher");
      batcherAddress = batch.address;
      batcher = (await ethers.getContractAt("FHETokenBatcher", batch.address)) as FHETokenBatcher;

      const t20 = await deployments.get("TestERC20");
      underlying = (await ethers.getContractAt("TestERC20", t20.address)) as TestERC20;
    } catch (e) {
      (e as Error).message +=
        ". Deploy with `npx hardhat deploy --network sepolia --tags TestERC20,FHEToken,FHETokenBatcher`.";
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
    const encryptedTransfer = await encryptAmountForCaller(TRANSFER_AMOUNT, owner.address);

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

  it("executes confidential transfer via EIP-712 authorization relayed by bob", async function () {
    this.timeout(6 * 60 * 1000);

    progress("Approving wrapper for underlying (EIP-712 test)...");
    await approveAndWrapTo(alice.address, WRAP_AMOUNT, "EIP-712 test");

    progress("Reading balances before...");
    const aliceBefore = await confidentialBalanceOrZero(alice.address, alice);
    const bobBefore = await confidentialBalanceOrZero(bob.address, bob);

    progress("Creating encrypted input (bob as sender)...");
    const encryptedTransfer = await encryptAmountForCaller(TRANSFER_AMOUNT, bob.address);

    const now = (await ethers.provider.getBlock("latest"))!.timestamp;
    const resourceHash = ethers.keccak256(ethers.toUtf8Bytes("sepolia-eip712"));
    const encryptedAmountHash = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(["bytes32"], [encryptedTransfer.handles[0]]),
    );

    const payment = {
      ...buildConfidentialPayment(alice.address, bob.address, TRANSFER_AMOUNT, resourceHash, now),
      encryptedAmountHash,
    };

    const domain = await buildDomain();

    progress("Alice signing typed data...");
    const signature = await alice.signTypedData(domain, CONFIDENTIAL_PAYMENT_TYPES, payment);

    progress("Bob relays confidentialTransferWithAuthorization...");
    const relayTx = await (
      await token
        .connect(bob)
        .confidentialTransferWithAuthorization(
          payment,
          encryptedTransfer.handles[0],
          encryptedTransfer.inputProof,
          signature,
        )
    ).wait();

    if (!relayTx) {
      throw new Error("relay transaction did not produce a receipt");
    }

    progress("Fetching ConfidentialPaymentExecuted event...");
    const events = await token.queryFilter(
      token.filters.ConfidentialPaymentExecuted(alice.address, bob.address),
      relayTx.blockNumber,
      relayTx.blockNumber,
    );
    const returnedHandle = events[0]?.args?.transferredAmount as string | undefined;

    if (!returnedHandle) {
      throw new Error("ConfidentialPaymentExecuted event not found");
    }

    progress("User decrypting returned handle (receiver)...");
    const decryptedTransfer = await userDecryptEuint64WithRetry(returnedHandle, tokenAddress, bob);
    console.log("Decrypted transfer amount:", decryptedTransfer.toString());

    progress("Reading balances after...");
    const aliceAfter = await confidentialBalanceOrZero(alice.address, alice);
    const bobAfter = await confidentialBalanceOrZero(bob.address, bob);

    expect(aliceAfter).to.equal(aliceBefore - TRANSFER_AMOUNT);
    expect(bobAfter).to.equal(bobBefore + TRANSFER_AMOUNT);
    expect(decryptedTransfer).to.equal(TRANSFER_AMOUNT);
  });

  it("unwraps with EIP-712 authorization relayed by bob", async function () {
    this.timeout(8 * 60 * 1000);

    await approveAndWrapTo(owner.address, WRAP_AMOUNT, "unwrap auth test");

    const ownerConfBefore = await confidentialBalanceOrZero(owner.address, owner);
    const underlyingBobBefore = await underlying.balanceOf(bob.address);

    const now = (await ethers.provider.getBlock("latest"))!.timestamp;

    progress("Creating encrypted unwrap input (bob as sender)...");
    const encryptedUnwrap = await encryptAmountForCaller(UNWRAP_AMOUNT, bob.address);

    const unwrapAuth = buildUnwrapAuthorization(
      owner.address,
      bob.address,
      now,
      ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["bytes32"], [encryptedUnwrap.handles[0]])),
    );

    const domain = await buildDomain();

    progress("Owner signing unwrap typed data...");
    const signature = await owner.signTypedData(domain, UNWRAP_AUTHORIZATION_TYPES, unwrapAuth);

    progress("Bob relays unwrapWithAuthorization...");
    const unwrapTx = await token
      .connect(bob)
      .unwrapWithAuthorization(unwrapAuth, encryptedUnwrap.handles[0], encryptedUnwrap.inputProof, signature);
    const unwrapReceipt = await unwrapTx.wait();
    if (!unwrapReceipt) {
      throw new Error("unwrap authorization transaction did not produce a receipt");
    }

    const events = await token.queryFilter(
      token.filters.UnwrapRequested(bob.address),
      unwrapReceipt.blockNumber,
      unwrapReceipt.blockNumber,
    );
    const unwrapHandle = events[0]?.args?.amount as string | undefined;
    if (!unwrapHandle) {
      throw new Error("UnwrapRequested event not found");
    }

    progress("Waiting before public decrypt...");
    await sleep(30 * 1000);
    progress("Public decrypting unwrap amount...");
    const { clearValues, decryptionProof } = await publicDecryptWithRetry([unwrapHandle]);
    const clearAmount = clearValues[unwrapHandle] as bigint;

    progress("Finalizing unwrap...");
    await (await token.finalizeUnwrap(unwrapHandle, Number(clearAmount), decryptionProof)).wait();

    const ownerConfAfter = await confidentialBalanceOrZero(owner.address, owner);
    const underlyingBobAfter = await underlying.balanceOf(bob.address);

    expect(ownerConfAfter).to.equal(ownerConfBefore - clearAmount);
    expect(underlyingBobAfter).to.equal(underlyingBobBefore + clearAmount);
  });

  it("batches confidential transfers with partial success on Sepolia", async function () {
    this.timeout(6 * 60 * 1000);

    await approveAndWrapTo(alice.address, WRAP_AMOUNT, "batch test");
    const aliceBefore = await confidentialBalanceOrZero(alice.address, alice);
    const bobBefore = await confidentialBalanceOrZero(bob.address, bob);

    const now = (await ethers.provider.getBlock("latest"))!.timestamp;
    const resourceHash = ethers.keccak256(ethers.toUtf8Bytes("sepolia-batch"));

    progress("Creating encrypted inputs for batch...");
    const encryptedOk = await encryptAmountForCaller(TRANSFER_AMOUNT, batcherAddress);
    const encryptedBad = await encryptAmountForCaller(TRANSFER_AMOUNT, batcherAddress);

    const paymentOk = {
      ...buildConfidentialPayment(alice.address, bob.address, TRANSFER_AMOUNT, resourceHash, now),
      encryptedAmountHash: ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(["bytes32"], [encryptedOk.handles[0]]),
      ),
    };

    const paymentExpired = {
      ...buildConfidentialPayment(alice.address, bob.address, TRANSFER_AMOUNT, resourceHash, now),
      validAfter: BigInt(now - 10),
      validBefore: BigInt(now - 1),
      encryptedAmountHash: ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(["bytes32"], [encryptedBad.handles[0]]),
      ),
    };

    const domain = await buildDomain();

    const sigOk = await alice.signTypedData(domain, CONFIDENTIAL_PAYMENT_TYPES, paymentOk);
    const sigExpired = await alice.signTypedData(domain, CONFIDENTIAL_PAYMENT_TYPES, paymentExpired);

    const requests = [
      {
        p: paymentOk,
        encryptedAmountInput: encryptedOk.handles[0],
        inputProof: encryptedOk.inputProof,
        sig: sigOk,
      },
      {
        p: paymentExpired,
        encryptedAmountInput: encryptedBad.handles[0],
        inputProof: encryptedBad.inputProof,
        sig: sigExpired,
      },
    ];

    progress("Static call for batch status...");
    const [successes, handles] = await batcher
      .getFunction("batchConfidentialTransferWithAuthorization")
      .staticCall(tokenAddress, requests);

    expect(successes[0]).to.equal(true);
    expect(successes[1]).to.equal(false);
    expect(handles[0]).to.not.equal(ethers.ZeroHash);
    expect(handles[1]).to.equal(ethers.ZeroHash);

    progress("Relaying batch transaction...");
    await (await batcher.connect(bob).batchConfidentialTransferWithAuthorization(tokenAddress, requests)).wait();

    const aliceAfter = await confidentialBalanceOrZero(alice.address, alice);
    const bobAfter = await confidentialBalanceOrZero(bob.address, bob);

    expect(aliceAfter - aliceBefore).to.equal(0n - TRANSFER_AMOUNT);
    expect(bobAfter - bobBefore).to.equal(TRANSFER_AMOUNT);
  });

  it("unwraps owner balance back to underlying on Sepolia", async function () {
    this.timeout(8 * 60 * 1000);

    progress("Approving wrapper for underlying (unwrap test)...");
    await (await underlying.connect(owner).approve(tokenAddress, WRAP_AMOUNT)).wait();

    progress("Reading starting balances...");
    const ownerConfBefore = await confidentialBalanceOrZero(owner.address, owner);
    const underlyingOwnerBefore = await underlying.balanceOf(owner.address);
    const underlyingTokenBefore = await underlying.balanceOf(tokenAddress);

    progress("Wrapping for unwrap test...");
    await (await token.connect(owner).wrap(owner.address, WRAP_AMOUNT)).wait();

    const ownerConfMid = await confidentialBalanceOrZero(owner.address, owner);
    expect(ownerConfMid).to.be.greaterThanOrEqual(UNWRAP_AMOUNT);

    progress("Creating unwrap encrypted amount for owner...");
    const encryptedUnwrap = await relayerInstance
      .createEncryptedInput(tokenAddress, owner.address)
      .add64(Number(UNWRAP_AMOUNT))
      .encrypt();

    progress("Calling unwrap...");
    const unwrapTx = await token
      .connect(owner)
      [
        "unwrap(address,address,bytes32,bytes)"
      ](owner.address, owner.address, encryptedUnwrap.handles[0], encryptedUnwrap.inputProof);
    const unwrapReceipt = await unwrapTx.wait();
    if (!unwrapReceipt) {
      throw new Error("unwrap transaction did not produce a receipt");
    }
    console.log("unwrap tx hash:", unwrapReceipt.hash);

    const events = await token.queryFilter(
      token.filters.UnwrapRequested(owner.address),
      unwrapReceipt.blockNumber,
      unwrapReceipt.blockNumber,
    );
    const unwrapHandle = events[0]?.args?.amount as string | undefined;
    if (!unwrapHandle) {
      throw new Error("UnwrapRequested event not found");
    }

    progress("Waiting before public decrypt...");
    await sleep(30 * 1000);
    progress("Public decrypting unwrap amount...");
    const { clearValues, decryptionProof } = await publicDecryptWithRetry([unwrapHandle]);
    const clearAmount = clearValues[unwrapHandle] as bigint;
    progress(`Unwrap clear amount: ${clearAmount}`);

    progress("Finalizing unwrap...");
    const unwrapFinalizeTx = await token.finalizeUnwrap(unwrapHandle, Number(clearAmount), decryptionProof);
    console.log("unwrap finalize tx hash:", unwrapFinalizeTx.hash);
    console.log("Waiting for 1 min for unwrap finalize tx to be synced between nodes...");
    await sleep(60 * 1000);

    const ownerConfAfter = await confidentialBalanceOrZero(owner.address, owner);
    const underlyingOwnerAfter = await underlying.balanceOf(owner.address);
    const underlyingTokenAfter = await underlying.balanceOf(tokenAddress);

    expect(ownerConfAfter).to.equal(ownerConfMid - clearAmount);
    expect(underlyingOwnerAfter - underlyingOwnerBefore).to.equal(0n - WRAP_AMOUNT + clearAmount);
    const underlyingDelta = underlyingTokenAfter - underlyingTokenBefore;
    expect(underlyingDelta).to.equal(WRAP_AMOUNT - clearAmount);
    const ownerConfAfterFinal = await confidentialBalanceOrZero(owner.address, owner);
    expect(ownerConfAfterFinal).to.equal(ownerConfBefore + WRAP_AMOUNT - clearAmount);
  });
});
