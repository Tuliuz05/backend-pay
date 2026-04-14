import "dotenv/config";
import hardhatToolboxMochaEthers from "@nomicfoundation/hardhat-toolbox-mocha-ethers";

export default {
  plugins: [hardhatToolboxMochaEthers],
  solidity: {
    version: "0.8.20",
    settings: {
      optimizer: {
        enabled: true,
        runs:    200,
      },
    },
  },
  networks: {
    hashkeyTestnet: {
      type: "http",
      chainType: "l1",
      url:      "https://testnet.hsk.xyz",
      chainId:  133,
      accounts: process.env.DEPLOYER_PRIVATE_KEY
        ? [process.env.DEPLOYER_PRIVATE_KEY]
        : [],
    },
    hashkeyMainnet: {
      type: "http",
      chainType: "l1",
      url:      "https://mainnet.hsk.xyz",
      chainId:  177,
      accounts: process.env.DEPLOYER_PRIVATE_KEY
        ? [process.env.DEPLOYER_PRIVATE_KEY]
        : [],
    },
  },
  etherscan: {
    apiKey: {
      hashkeyTestnet: "no-api-key-needed",
    },
    customChains: [
      {
        network:  "hashkeyTestnet",
        chainId:  133,
        urls: {
          apiURL:      "https://testnet-explorer.hsk.xyz/api",
          browserURL:  "https://testnet-explorer.hsk.xyz",
        },
      },
    ],
  },
};