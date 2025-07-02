import { ethers } from "ethers";
import { writeFileSync } from "fs";
import "dotenv/config";

const OWNER_PK = process.env.OWNER_PK!;

const signer = new ethers.Wallet(OWNER_PK);

const TOKEN_ADDRESS = "...";
const CONTRACT_ADDR = "...";
const CHAIN_ID = 421614;
const NUM_RECIPS = 10;

const recips: any[] = [];
while (recips.length < NUM_RECIPS) {
  recips.push({
    recipient: "0x",
    amount: "10",
  });
}

const UID = ethers.utils.hexlify(ethers.utils.randomBytes(32));

const EXPIRY = Math.floor(Date.now() / 1e3) + 86_400;

const domain = {
  name: "Airdrop",
  version: "1",
  chainId: CHAIN_ID,
  verifyingContract: CONTRACT_ADDR,
};

const types = {
  AirdropContentERC721: [
    { name: "recipient", type: "address" },
    { name: "tokenId", type: "uint256" },
  ],
  AirdropRequestERC721: [
    { name: "uid", type: "bytes32" },
    { name: "tokenAddress", type: "address" },
    { name: "expirationTimestamp", type: "uint256" },
    { name: "contents", type: "AirdropContentERC721[]" },
  ],
};

const message = {
  uid: UID,
  tokenAddress: TOKEN_ADDRESS,
  expirationTimestamp: EXPIRY,
  contents: recips,
};

async function main() {
  writeFileSync("airdropReq.json", JSON.stringify(message));

  const signature = await signer._signTypedData(domain, types, message);

  const digestOff = ethers.utils._TypedDataEncoder.hash(domain, types, message);
  console.log("off-chain digest:", digestOff);

  console.log("owner address:", await signer.getAddress());
  console.log("signature:", signature);

  const abiTypes = "(bytes32,address,uint256,(address,uint256)[])";

  const abiValues = [
    message.uid,
    message.tokenAddress,
    message.expirationTimestamp,
    message.contents.map((c) => [c.recipient, c.amount]),
  ];

  const reqRaw = ethers.utils.defaultAbiCoder.encode([abiTypes], [abiValues]);
  console.log("reqRaw:", reqRaw);

  const reqRawBytes: number[] = Array.from(ethers.utils.arrayify(reqRaw));
  const sigBytes: number[] = Array.from(ethers.utils.arrayify(signature));

  const sigFixed = sigBytes as number[] & { length: 65 };

  writeFileSync(
    "airdropCall.json",
    JSON.stringify({ reqRaw: reqRawBytes, sig: sigBytes, sigFixed }, null, 2)
  );
}

main();
