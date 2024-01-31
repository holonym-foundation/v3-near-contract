const { keyStores, KeyPair, connect, utils } = require('near-api-js');
const fs = require('fs');
const { randomBytes } = require('crypto')
const bs58 = require('bs58');

const keyStore = new keyStores.InMemoryKeyStore();
const prv = bs58.encode(randomBytes(64));
const keyPair = KeyPair.fromString(`ed25519:${prv}`);
const accountID = Buffer.from(keyPair.publicKey.data).toString('hex');
keyStore.setKey('mainnet', accountID, keyPair);

const connectionConfig = {
  networkId: "mainnet",
  keyStore,
  nodeUrl: "https://rpc.mainnet.near.org",
  walletUrl: "https://wallet.mainnet.near.org",
  helperUrl: "https://helper.mainnet.near.org",
  explorerUrl: "https://nearblocks.io",
};

const main = async () => {
  const nearConnection = await connect(connectionConfig);
  const account = await nearConnection.account(accountID);
  const transactionOutcome = await account.deployContract(
    fs.readFileSync("../target/wasm32-unknown-unknown/release/holonear.wasm")
  );
};

main().catch(console.error);