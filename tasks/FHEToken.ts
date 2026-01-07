import { task } from "hardhat/config";
import type { TaskArguments } from "hardhat/types";

const ERC20_ABI = ["function approve(address spender, uint256 amount) external returns (bool)"];

/**
 * Example:
 *   - npx hardhat --network localhost task:fhe-wrap --amount 100
 *   - npx hardhat --network sepolia task:fhe-wrap --amount 250 --to 0x... --signer 1
 */
task("task:fhe-wrap", "Wrap underlying tokens into FHEToken")
  .addParam("amount", "Amount of underlying tokens to wrap (human units)")
  .addOptionalParam("address", "FHEToken address (defaults to deployments)")
  .addOptionalParam("to", "Recipient of wrapped FHEToken (defaults to signer[0])")
  .addOptionalParam("decimals", "Underlying token decimals (defaults to 6)")
  .addOptionalParam("underlying", "Underlying token address (defaults to FHEToken.underlying())")
  .addOptionalParam("signer", "Signer index to use (defaults to 0)")
  .setAction(async function (taskArguments: TaskArguments, hre) {
    const { deployments, ethers } = hre;

    const amountRaw = taskArguments.amount;
    const decimals = parseInt(taskArguments.decimals ?? "6", 10);
    if (!Number.isInteger(decimals)) {
      throw new Error("Argument --decimals must be an integer");
    }

    const amount = ethers.parseUnits(amountRaw, decimals);

    const signers = await ethers.getSigners();
    const signerIndex = parseInt(taskArguments.signer ?? "0", 10);
    if (!Number.isInteger(signerIndex) || signerIndex < 0 || signerIndex >= signers.length) {
      throw new Error(`Argument --signer must be between 0 and ${signers.length - 1}`);
    }
    const sender = signers[signerIndex];

    const fheTokenDeployment = taskArguments.address
      ? { address: taskArguments.address }
      : await deployments.get("FHEToken");
    const fheToken = await ethers.getContractAt("FHEToken", fheTokenDeployment.address);

    const to = taskArguments.to ?? sender.address;
    const underlyingAddress = taskArguments.underlying ?? (await fheToken.underlying());
    const underlying = new ethers.Contract(underlyingAddress, ERC20_ABI, sender);

    const approveTx = await underlying.approve(fheTokenDeployment.address, amount);
    console.log(`Approve tx: ${approveTx.hash}`);
    await approveTx.wait();

    const wrapTx = await fheToken.connect(sender).wrap(to, amount);
    console.log(`Wrap tx: ${wrapTx.hash}`);
    const receipt = await wrapTx.wait();
    console.log(`Wrap status: ${receipt?.status}`);
  });
