import { ethers } from "ethers";
import { MerkleTree } from "@thirdweb-dev/merkletree";
import keccak256 from "keccak256";
import { writeFileSync } from "fs";

const TARGET_RECIPIENT = "0x..";

const NUM_RECIPS = 10_000;
const AMOUNT_WEI = BigInt(10);

const recips: string[] = [];

while (recips.length < NUM_RECIPS - 1) {
  const addr = ethers.Wallet.createRandom().address.toLowerCase();
  if (addr !== TARGET_RECIPIENT.toLowerCase()) recips.push(addr);
}

const i = Math.floor(Math.random() * NUM_RECIPS);
recips.splice(i, 0, TARGET_RECIPIENT.toLowerCase()); // insert target address at random index

const amts = Array(NUM_RECIPS).fill(AMOUNT_WEI.toString());

const leaves = recips.map((addr, idx) =>
  ethers.utils.solidityKeccak256(["address", "uint256"], [addr, amts[idx]])
);
const tree = new MerkleTree(leaves, keccak256, { sortPairs: true });
const root = tree.getHexRoot();

// save tree info
writeFileSync(
  "airdropRoot.json",
  JSON.stringify({ root, recips, amts }, null, 2)
);

console.log(`generated merkle root: ${root}`);
