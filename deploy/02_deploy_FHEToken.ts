import { DeployFunction } from "hardhat-deploy/types";
import { HardhatRuntimeEnvironment } from "hardhat/types";

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const { deployer } = await hre.getNamedAccounts();
  const { deploy, get, log } = hre.deployments;

  const name = process.env.FHETOKEN_NAME ?? "Confidential Token";
  const symbol = process.env.FHETOKEN_SYMBOL ?? "CTKN";
  const tokenURI = process.env.FHETOKEN_URI ?? "ipfs://cwtt";

  const underlying = await get("TestERC20");

  const deployed = await deploy("FHEToken", {
    from: deployer,
    args: [name, symbol, tokenURI, underlying.address],
    log: true,
  });

  log(`FHEToken deployed at ${deployed.address} (underlying ${underlying.address})`);
};

export default func;
func.id = "deploy_fhe_token";
func.tags = ["FHEToken"];
func.dependencies = ["TestERC20"];
