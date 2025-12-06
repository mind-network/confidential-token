import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { ethers, deployments } from "hardhat";
import { FHECounter } from "../types";
import { expect } from "chai";
import { createInstance, SepoliaConfig } from "@zama-fhe/relayer-sdk/node";

type Signers = {
  alice: HardhatEthersSigner;
};

describe("FHECounterSepolia", function () {
  let signers: Signers;
  let fheCounterContract: FHECounter;
  let fheCounterContractAddress: string;
  let relayerInstance: Awaited<ReturnType<typeof createInstance>>;
  let step: number;
  let steps: number;
  const MAX_RETRIES = 3;
  const BASE_DELAY_MS = 1500;

  function progress(message: string) {
    console.log(`${++step}/${steps} ${message}`);
  }

  before(async function () {
    relayerInstance = await createInstance(SepoliaConfig);

    try {
      const FHECounterDeployement = await deployments.get("FHECounter");
      fheCounterContractAddress = FHECounterDeployement.address;
      fheCounterContract = await ethers.getContractAt("FHECounter", FHECounterDeployement.address);
    } catch (e) {
      (e as Error).message += ". Call 'npx hardhat deploy --network sepolia'";
      throw e;
    }

    const ethSigners: HardhatEthersSigner[] = await ethers.getSigners();
    signers = { alice: ethSigners[0] };
  });

  beforeEach(async () => {
    step = 0;
    steps = 0;
  });

  async function sleep(ms: number) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  async function userDecryptEuint32(handle: string, signer: HardhatEthersSigner) {
    const keypair = relayerInstance.generateKeypair();
    const startTimestamp = Math.floor(Date.now() / 1000).toString();
    const durationDays = "10";
    const contractAddresses = [fheCounterContractAddress];
    const eip712 = relayerInstance.createEIP712(keypair.publicKey, contractAddresses, startTimestamp, durationDays);

    const signature = await signer.signTypedData(
      eip712.domain,
      { UserDecryptRequestVerification: eip712.types.UserDecryptRequestVerification },
      eip712.message,
    );

    const result = await relayerInstance.userDecrypt(
      [{ handle, contractAddress: fheCounterContractAddress }],
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

  async function userDecryptEuint32WithRetry(handle: string, signer: HardhatEthersSigner) {
    let delay = BASE_DELAY_MS;
    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
      try {
        return await userDecryptEuint32(handle, signer);
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

  it("increment the counter by 1", async function () {
    steps = 10;

    this.timeout(4 * 40000);

    progress("Encrypting '0'...");
    const encryptedZero = await relayerInstance
      .createEncryptedInput(fheCounterContractAddress, signers.alice.address)
      .add32(0)
      .encrypt();

    progress(
      `Call increment(0) FHECounter=${fheCounterContractAddress} handle=${ethers.hexlify(encryptedZero.handles[0])} signer=${signers.alice.address}...`,
    );
    let tx = await fheCounterContract
      .connect(signers.alice)
      .increment(encryptedZero.handles[0], encryptedZero.inputProof);
    await tx.wait();

    progress(`Call FHECounter.getCount()...`);
    const encryptedCountBeforeInc = await fheCounterContract.getCount();
    expect(encryptedCountBeforeInc).to.not.eq(ethers.ZeroHash);

    progress(`Decrypting FHECounter.getCount()=${encryptedCountBeforeInc}...`);
    const clearCountBeforeInc = await userDecryptEuint32WithRetry(encryptedCountBeforeInc, signers.alice);
    progress(`Clear FHECounter.getCount()=${clearCountBeforeInc}`);

    progress(`Encrypting '1'...`);
    const encryptedOne = await relayerInstance
      .createEncryptedInput(fheCounterContractAddress, signers.alice.address)
      .add32(1)
      .encrypt();

    progress(
      `Call increment(1) FHECounter=${fheCounterContractAddress} handle=${ethers.hexlify(encryptedOne.handles[0])} signer=${signers.alice.address}...`,
    );
    tx = await fheCounterContract.connect(signers.alice).increment(encryptedOne.handles[0], encryptedOne.inputProof);
    await tx.wait();

    progress(`Call FHECounter.getCount()...`);
    const encryptedCountAfterInc = await fheCounterContract.getCount();

    progress(`Decrypting FHECounter.getCount()=${encryptedCountAfterInc}...`);
    const clearCountAfterInc = await userDecryptEuint32WithRetry(encryptedCountAfterInc, signers.alice);
    progress(`Clear FHECounter.getCount()=${clearCountAfterInc}`);

    expect(clearCountAfterInc - clearCountBeforeInc).to.eq(1n);
  });
});
