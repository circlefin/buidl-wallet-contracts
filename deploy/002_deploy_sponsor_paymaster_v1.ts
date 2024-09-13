import {HardhatRuntimeEnvironment} from 'hardhat/types';
import {DeployFunction} from 'hardhat-deploy/types';
import SponsorPaymasterImplementation from './metadata/SponsorPaymaster_Implementation.json'
import SponsorPaymasterProxy from './metadata/SponsorPaymaster_Proxy.json'

const deploySponsorPaymaster: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
    const {deployments, getNamedAccounts} = hre;
    const {deploy} = deployments;

    const entryPoint = process.env.ENTRY_POINT;
    const verifyingSigner = process.env.VERIFYING_SIGNER;
    const owner = process.env.PAYMASTER_OWNER;
    const {deployer} = await getNamedAccounts();

    // These arguments that are used to deploy the first SponsorPaymaster contract, we need to keep the same arguments for
    // any future deployment to have a canonical address across EVM chains.
    const proxyArgDataInternal = `0x485cc955000000000000000000000000${process.env.PAYMASTER_OWNER!.replace("0x", "")}000000000000000000000000${process.env.VERIFYING_SIGNER!.replace("0x","")}`
    const proxyArgData = `0x485cc955000000000000000000000000${process.env.PAYMASTER_OWNER!.replace("0x", "")}000000000000000000000000${process.env.PAYMASTER_OWNER!.replace("0x","")}`

    const sponsorPaymasterImplementation = await deploy("SponsorPaymaster_Implementation", {
        from: deployer,
        args: [entryPoint],
        contract: {
            abi: SponsorPaymasterImplementation.abi,
            bytecode: SponsorPaymasterImplementation.bytecode
        },
        gasLimit: 2e7,
        log: true,
        deterministicDeployment: true
    });

    console.log("SponsorPaymaster_Implementation deployed to:", sponsorPaymasterImplementation.address);

    // Deploying the SponsorPaymaster used for internal environment, the address should be "0x67aC303faB3A9507Ac48fD5B5EE176c4E39aE98C".
    const sponsorPaymasterProxyInternal = await deploy('SponsorPaymaster_Proxy', {
        from: deployer,
        args: [sponsorPaymasterImplementation.address, proxyArgDataInternal],
        contract: {
            abi: SponsorPaymasterProxy.abi,
            bytecode: SponsorPaymasterProxy.bytecode
        },
        gasLimit: 2e7,
        log: true,
        deterministicDeployment: true
    });

    console.log("SponsorPaymaster_Proxy for Internal environment deployed to:", sponsorPaymasterProxyInternal.address);

    // Deploying the SponsorPaymaster used for public environment, the address should be "0x7ceA357B5AC0639F89F9e378a1f03Aa5005C0a25".
    const sponsorPaymasterProxy = await deploy('SponsorPaymaster_Proxy', {
        from: deployer,
        args: [sponsorPaymasterImplementation.address, proxyArgData],
        contract: {
            abi: SponsorPaymasterProxy.abi,
            bytecode: SponsorPaymasterProxy.bytecode
        },
        gasLimit: 2e7,
        log: true,
        deterministicDeployment: true
    });

    console.log("SponsorPaymaster_Proxy deployed to:", sponsorPaymasterProxy.address);
}

export default deploySponsorPaymaster;
deploySponsorPaymaster.tags = ['SponsorPaymaster'];
