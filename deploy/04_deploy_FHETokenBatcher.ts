import { DeployFunction } from "hardhat-deploy/types";
import { HardhatRuntimeEnvironment } from "hardhat/types";

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const { deployer } = await hre.getNamedAccounts();
  const { deploy, log } = hre.deployments;

  const deployed = await deploy("FHETokenBatcher", {
    from: deployer,
    log: true,
  });

  log(`FHETokenBatcher deployed at ${deployed.address}`);
};

export default func;
func.id = "deploy_fhe_token_batcher";
func.tags = ["FHETokenBatcher"];
