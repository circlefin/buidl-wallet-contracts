import {HardhatRuntimeEnvironment} from 'hardhat/types';
import {DeployFunction} from 'hardhat-deploy/types';
import Factory from './metadata/ECDSAAccountFactory.json';

const deployECDSAAccountFactory: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
    const {deployments, getNamedAccounts} = hre;
    const {deploy} = deployments;

    const entryPoint = process.env.ENTRY_POINT ?? ``;
    const accountFactoryDeployerPrivateKey = process.env.DEPLOYER_PRIVATE_KEY;
    if (!accountFactoryDeployerPrivateKey) {
        throw new Error("DEPLOYER_PRIVATE_KEY is not set");
    }
    const {deployer} = await getNamedAccounts()
    console.log("Deployer address:", deployer);

    const ecdsaAccountFactory = await deploy(
        'ECDSAAccountFactory', {
            from: deployer,
            contract: {
                abi: Factory.abi,
                bytecode: Factory.bytecode
            },
            args: [entryPoint],
            log: true,
            deterministicDeployment: true
        })
    console.log("ECDSAAccountFactory deployed to:", ecdsaAccountFactory.address);
};
export default deployECDSAAccountFactory;
deployECDSAAccountFactory.tags = ['ECDSAAccountFactory'];
