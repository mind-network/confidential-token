import { parseUnits } from "ethers";
import { DeployFunction } from "hardhat-deploy/types";
import { HardhatRuntimeEnvironment } from "hardhat/types";

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const { deployer } = await hre.getNamedAccounts();
  const { deploy, get, log } = hre.deployments;

  const underlying = await get("TestERC20");
  const amount = parseUnits(process.env.TEST_ERC20_FAUCET_AMOUNT ?? "1000", 6);
  const owner = process.env.TEST_ERC20_FAUCET_OWNER ?? deployer;

  const deployed = await deploy("TestERC20Faucet", {
    from: deployer,
    args: [underlying.address, amount, owner],
    log: true,
  });

  log(`TestERC20Faucet deployed at ${deployed.address}`);
};

export default func;
func.id = "deploy_test_erc20_faucet";
func.tags = ["TestERC20Faucet"];
func.dependencies = ["TestERC20"];
