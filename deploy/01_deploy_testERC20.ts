import { parseUnits } from "ethers";
import { DeployFunction } from "hardhat-deploy/types";
import { HardhatRuntimeEnvironment } from "hardhat/types";

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const { deployer } = await hre.getNamedAccounts();
  const { deploy, log } = hre.deployments;

  const name = process.env.TEST_ERC20_NAME ?? "Test Token";
  const symbol = process.env.TEST_ERC20_SYMBOL ?? "TST";
  const initialSupply = parseUnits(process.env.TEST_ERC20_SUPPLY ?? "1000000", 6); // 6 decimals in TestERC20

  const deployed = await deploy("TestERC20", {
    from: deployer,
    args: [name, symbol, initialSupply],
    log: true,
  });

  log(`TestERC20 deployed at ${deployed.address}`);
};

export default func;
func.id = "deploy_test_erc20";
func.tags = ["TestERC20"];
